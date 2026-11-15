import type {
  BundleRow, CacheStats, CleanReport, FileGrant, FileHit, FileSource, FileToolReport, JobRecord, JobRequest
} from '../main/ets/center/CenterTypes'
import { CenterError } from '../main/ets/center/CenterError'
import { largeTiers } from '../main/ets/center/CenterLimits'
import type { InstallerIo, InstallerStat, OpenedInstaller } from '../main/ets/engine/InstallerScan'
import { CancelFlag } from '../main/ets/task/CancelFlag'
import type { CleanContext, FileToolContext } from '../main/ets/task/Contexts'
import { RunnerRegistry, RunnerSet } from '../main/ets/task/RunnerRegistry'
import type { ResultHand, RunEnd } from '../main/ets/task/RunnerRegistry'
import { CleanRunner } from '../main/ets/feature/clean/CleanRunner'
import type { CleanSources } from '../main/ets/feature/clean/CleanRunner'
import { CorpseFinder, CorpseResult } from '../main/ets/feature/clean/CorpseFinder'
import { DuplicateFinder, DuplicateTools } from '../main/ets/feature/clean/DuplicateFinder'
import type { FileDigest, FileHash } from '../main/ets/feature/clean/DuplicateFinder'
import { LargeFileFinder, LargeFileTools, largeReason } from '../main/ets/feature/clean/LargeFileFinder'

const SELF: string = 'com.jinyinhu.securitycenter'
const DOWNLOAD: string = 'file:///storage/Download'

function require(value: boolean, message: string): void {
  if (!value) {
    throw new Error(message)
  }
}

class Node {
  dir: boolean = false
  link: boolean = false
  size: number = 0
  names: string[] = []
  sha: string = ''
}

function pathOf(uri: string): string {
  return uri.startsWith('file://') ? uri.substring('file://'.length) : uri
}

class Disk implements InstallerIo, FileHash {
  nodes: Map<string, Node> = new Map<string, Node>()
  fds: Map<number, string> = new Map<number, string>()
  next: number = 3
  opened: string[] = []
  hashed: string[] = []

  file(path: string, size: number, sha: string = ''): void {
    let node = new Node()
    node.size = size
    node.sha = sha
    this.nodes.set(path, node)
    this.parent(path)
  }

  dir(path: string): void {
    if (!this.nodes.has(path)) {
      let node = new Node()
      node.dir = true
      this.nodes.set(path, node)
    }
  }

  private parent(path: string): void {
    let at = path.lastIndexOf('/')
    let parent = path.substring(0, at)
    if (parent.length === 0) {
      return
    }
    this.dir(parent)
    let node = this.nodes.get(parent) as Node
    let name = path.substring(at + 1)
    if (node.names.indexOf(name) < 0) {
      node.names.push(name)
    }
    this.parent(parent)
  }

  accept(uri: string, root: string): CenterError | string {
    let path = pathOf(uri)
    let rootPath = pathOf(root)
    if (path.startsWith('/system') ||
      !(path === rootPath || path.startsWith(rootPath.replace(/\/$/, '') + '/'))) {
      return new CenterError('rejected-system-path', path)
    }
    return path
  }

  open(uri: string, root: string, _fromPicker: boolean, _grants: FileGrant[]): CenterError | OpenedInstaller {
    let accepted = this.accept(uri, root)
    if (accepted instanceof CenterError) {
      return accepted
    }
    if (!this.nodes.has(accepted)) {
      return new CenterError('io', accepted)
    }
    let fd = this.next++
    this.fds.set(fd, accepted)
    this.opened.push(accepted)
    return { fd: fd, path: accepted }
  }

  release(opened: OpenedInstaller): void {
    this.fds.delete(opened.fd)
  }

  list(path: string): string[] {
    return (this.nodes.get(path) as Node).names.slice()
  }

  stat(path: string): InstallerStat {
    let node = this.nodes.get(path)
    if (node === undefined) {
      throw new Error('missing ' + path)
    }
    return { directory: node.dir, symbolicLink: node.link }
  }

  size(fd: number): number {
    return (this.nodes.get(this.fds.get(fd) as string) as Node).size
  }

  now(): number {
    return Date.now()
  }

  async hash(fd: number, _cancel: SharedArrayBuffer): Promise<FileDigest> {
    let path = this.fds.get(fd) as string
    this.hashed.push(path)
    return { sha256: (this.nodes.get(path) as Node).sha, cancelled: false }
  }
}

class Files implements FileSource {
  grants: FileGrant[] = []

  constructor(uris: string[]) {
    for (let uri of uris) {
      this.grants.push({ uri: uri, displayName: uri, persisted: true, at: '' })
    }
  }

  persisted(): FileGrant[] {
    return this.grants.slice()
  }

  forget(uri: string): void {
    this.grants = this.grants.filter((grant: FileGrant): boolean => grant.uri !== uri)
  }
}

class Census {
  rows: BundleRow[] = []

  async list(): Promise<BundleRow[]> {
    return this.rows.slice()
  }
}

class Cache implements CacheStats {
  bytes: Map<string, number> = new Map<string, number>()
  unsupported: boolean = false

  async stats(bundleName: string): Promise<number> {
    if (this.unsupported) {
      throw new CenterError('unsupported', 'cacheStats')
    }
    let value = this.bytes.get(bundleName)
    return value === undefined ? 0 : value
  }
}

class Hand implements ResultHand {
  saves: Object[] = []

  save(result: Object): void {
    this.saves.push(JSON.parse(JSON.stringify(result)))
  }

  lastClean(): CleanReport {
    return this.saves[this.saves.length - 1] as CleanReport
  }

  lastTool(): FileToolReport {
    return this.saves[this.saves.length - 1] as FileToolReport
  }
}

class StubCorpse extends CorpseFinder {
  result: CorpseResult = new CorpseResult()
  calls: number = 0

  find(_files: FileSource, _open: Object, _installed: string[]): CorpseResult {
    this.calls++
    let out = new CorpseResult()
    out.stoppedByLimit = this.result.stoppedByLimit
    out.hits = this.result.hits.map((hit: FileHit): FileHit => ({
      uri: hit.uri, name: hit.name, size: hit.size, sha256: hit.sha256, clazz: hit.clazz,
      reason: hit.reason, selected: false, groupId: ''
    }))
    return out
  }
}

function bundle(name: string): BundleRow {
  return {
    bundleName: name, version: '1.0', versionCode: 1, certSha256: 'aa', certAlgo: 'platform-fingerprint',
    declaredPermissions: [], source: 'unknown',
    verdict: { level: 'unknown', source: 'system', reason: '', evidence: '', cloud: 'unchecked' }
  }
}

function fileHit(uri: string, name: string, size: number, clazz: 'residue' | 'installer',
  reason: string): FileHit {
  return {
    uri: uri, name: name, size: size, sha256: 'dead', clazz: clazz, reason: reason, selected: false,
    groupId: ''
  }
}

class Job {
  census: Census = new Census()
  cache: Cache = new Cache()
  files: Files = new Files([])
  disk: Disk = new Disk()
  cancel: CancelFlag = new CancelFlag()
  messages: string[] = []
  ownBytes: number = 0
  corpse: StubCorpse = new StubCorpse()

  ctx(): CleanContext {
    let record: JobRecord = {
      jobId: 'clean-1', seq: 1, kind: 'clean', lane: 'heavy', startedAt: '', finishedAt: '',
      state: 'running', itemCount: 0, riskCount: 0, summary: '', resultFile: ''
    }
    let request: JobRequest = { kind: 'clean', scope: 'full', focus: '', uris: [] }
    return {
      base: {
        job: record, request: request, cancel: this.cancel,
        clock: { nowIso: (): string => 't' },
        report: (_done: number, _total: number, message: string): void => {
          this.messages.push(message)
        }
      },
      census: this.census as Object as CleanContext['census'],
      cache: this.cache,
      files: this.files,
      open: this.disk as Object as CleanContext['open']
    }
  }

  toolCtx(kind: 'duplicate' | 'large-file'): FileToolContext {
    let record: JobRecord = {
      jobId: kind + '-1', seq: 1, kind: kind, lane: 'heavy', startedAt: '', finishedAt: '',
      state: 'running', itemCount: 0, riskCount: 0, summary: '', resultFile: ''
    }
    let request: JobRequest = { kind: kind, scope: 'full', focus: '', uris: [] }
    return {
      base: {
        job: record, request: request, cancel: this.cancel,
        clock: { nowIso: (): string => 't' },
        report: (_done: number, _total: number, message: string): void => {
          this.messages.push(message)
        }
      },
      files: this.files,
      open: this.disk as Object as FileToolContext['open']
    }
  }

  sources(): CleanSources {
    return {
      ownCache: async (): Promise<number> => this.ownBytes,
      selfBundle: (): string => SELF
    }
  }
}

async function runClean(job: Job): Promise<{ end: RunEnd, report: CleanReport, hand: Hand }> {
  let hand = new Hand()
  let end = await new CleanRunner(job.sources(), job.corpse).run(job.ctx(), hand)
  return { end: end, report: hand.lastClean(), hand: hand }
}

async function cacheAvailable(): Promise<void> {
  let job = new Job()
  job.census.rows = [bundle(SELF), bundle('com.other.app'), bundle('com.zero.app')]
  job.cache.bytes.set(SELF, 100)
  job.cache.bytes.set('com.other.app', 50)
  job.cache.bytes.set('com.zero.app', 0)
  job.files = new Files([DOWNLOAD])
  job.corpse.result.hits = [fileHit(DOWNLOAD + '/a.hap', 'a.hap', 10, 'installer', '已安装应用的安装包')]
  let out = await runClean(job)
  require(out.report.caches.length === 2, '字节为 0 的不列出')
  require(out.report.caches.some((row) => row.bundleName === SELF), '本应用也在列表里')
  require(out.report.caches.every((row) => row.selected === false), '写回 selected 为 false')
  require(out.report.hits.length === 1 && out.report.hits[0].selected === false, '安装包 selected=false')
  require(out.report.groups.length === 0, '清理主作业不产生 DuplicateGroup')
  require(out.report.complete === true && out.report.note === '', '未触上限且有授权时 note 空')
  require(job.corpse.calls === 1, 'CorpseFinder 被调用一次')
}

async function cacheUnavailable(): Promise<void> {
  let job = new Job()
  job.census.rows = [bundle(SELF), bundle('com.other.app')]
  job.cache.unsupported = true
  job.ownBytes = 42
  let out = await runClean(job)
  require(out.report.caches.length === 1, '不可用时只列本应用一条')
  require(out.report.caches[0].bundleName === SELF && out.report.caches[0].cacheBytes === 42,
    '本应用 cacheDir 一条')
  require(out.report.note.indexOf('无法读取其他应用缓存') >= 0, 'note 含无法读取其他应用缓存')
}

async function noGrantNote(): Promise<void> {
  let job = new Job()
  job.census.rows = [bundle(SELF)]
  job.cache.bytes.set(SELF, 1)
  let out = await runClean(job)
  require(out.report.note.indexOf('请先选择目录') >= 0, '没有授权时 note 含请先选择目录')
  require(out.report.note.indexOf('没有安装包') < 0, '不写没有安装包')
  require(job.corpse.calls === 0, '没有授权时不调用 CorpseFinder')
  require(out.report.hits.length === 0, '没有授权时 hits 为空')
}

async function corpseLimit(): Promise<void> {
  let job = new Job()
  job.census.rows = [bundle(SELF)]
  job.cache.bytes.set(SELF, 1)
  job.files = new Files([DOWNLOAD])
  job.corpse.result.hits = [fileHit(DOWNLOAD + '/a.hap', 'a.hap', 10, 'residue', '该应用未安装')]
  job.corpse.result.stoppedByLimit = true
  let out = await runClean(job)
  require(out.report.complete === false, 'stoppedByLimit 时 complete=false')
  require(out.report.note.indexOf('已达本次扫描上限') >= 0, 'note 含已达本次扫描上限')
  require(out.end.summary === '已达本次扫描上限', '作业 summary 写同一句')
}

async function noteOrder(): Promise<void> {
  let job = new Job()
  job.census.rows = [bundle(SELF)]
  job.cache.unsupported = true
  job.ownBytes = 1
  job.files = new Files([DOWNLOAD])
  job.corpse.result.stoppedByLimit = true
  let out = await runClean(job)
  require(out.report.note === '已达本次扫描上限、无法读取其他应用缓存',
    '多句 note 按第 3 节顺序：' + out.report.note)
}

async function duplicates(): Promise<void> {
  let job = new Job()
  job.files = new Files([DOWNLOAD])
  job.disk.file('/storage/Download/a.bin', 100, 'same')
  job.disk.file('/storage/Download/b.bin', 100, 'same')
  job.disk.file('/storage/Download/c.bin', 100, 'other')
  job.disk.file('/storage/Download/d.bin', 200, 'same')
  job.disk.file('/storage/Download/alone.bin', 50, 'solo')
  let tools = new DuplicateTools()
  tools.io = job.disk
  tools.hash = job.disk
  let hand = new Hand()
  let end = await new DuplicateFinder(tools).run(job.toolCtx('duplicate'), hand)
  let report = hand.lastTool()
  require(report.groups.length === 1, '只有内容相同且大小相同的一组')
  require(report.groups[0].fileUris.length === 2, '两个相同文件在同一 DuplicateGroup')
  require(report.groups[0].sha256 === 'same' && report.groups[0].size === 100, '组字段正确')
  require(report.hits.every((hit) => hit.selected === false && hit.clazz === 'duplicate'),
    '组内不编码保留第一条，全部 selected=false')
  require(job.disk.hashed.indexOf('/storage/Download/alone.bin') < 0, '组内只有 1 个的不算哈希')
  require(job.disk.hashed.indexOf('/storage/Download/d.bin') < 0, '大小不同的不算哈希')
  require(report.complete === true, '未触上限 complete=true')
  require(!('caches' in (report as Object)), '不产生 CleanReport')
  require(end.itemCount === 2, 'itemCount 为命中文件数')
}

async function systemRejected(): Promise<void> {
  let job = new Job()
  job.files = new Files(['file:///system/lib'])
  job.disk.dir('/system/lib')
  job.disk.file('/system/lib/big.bin', largeTiers[0], 'x')
  let tools = new LargeFileTools()
  tools.io = job.disk
  let hand = new Hand()
  await new LargeFileFinder(tools).run(job.toolCtx('large-file'), hand)
  let report = hand.lastTool()
  require(report.hits.length === 0, '系统目录在打开前被 FileOpen 拒绝')
  require(job.disk.opened.length === 0, '被拒绝的路径不打开')
}

async function largeFiles(): Promise<void> {
  require(largeReason(largeTiers[2]) === '1GB+', '1GB+')
  require(largeReason(largeTiers[1]) === '500MB+', '500MB+')
  require(largeReason(largeTiers[0]) === '100MB+', '100MB+')
  require(largeReason(largeTiers[2] - 1) === '500MB+', '略小于 1GB 仍是 500MB+')
  let job = new Job()
  job.files = new Files([DOWNLOAD])
  job.disk.file('/storage/Download/g.bin', largeTiers[2], '')
  job.disk.file('/storage/Download/m.bin', largeTiers[1], '')
  job.disk.file('/storage/Download/s.bin', largeTiers[0], '')
  job.disk.file('/storage/Download/tiny.bin', largeTiers[0] - 1, '')
  let tools = new LargeFileTools()
  tools.io = job.disk
  let hand = new Hand()
  await new LargeFileFinder(tools).run(job.toolCtx('large-file'), hand)
  let report = hand.lastTool()
  require(report.hits.length === 3, '小于 100MB 不列出')
  let reasons = new Map<string, string>()
  for (let hit of report.hits) {
    reasons.set(hit.uri, hit.reason)
  }
  require(reasons.get(DOWNLOAD + '/g.bin') === '1GB+', '1GB 档')
  require(reasons.get(DOWNLOAD + '/m.bin') === '500MB+', '500MB 档')
  require(reasons.get(DOWNLOAD + '/s.bin') === '100MB+', '100MB 档')
  require(report.hits.every((hit) => hit.selected === false && hit.clazz === 'large'), '大文件 selected=false')
  require(report.groups.length === 0, '大文件不产生 DuplicateGroup')
  require(!('caches' in (report as Object)), '大文件不产生 CleanReport')
}

async function registry(): Promise<void> {
  RunnerRegistry.registerAll()
  require(!RunnerRegistry.table().has('clean'), '不传 Runner 时表是空的')
  let set = new RunnerSet()
  let clean = new CleanRunner({ ownCache: async (): Promise<number> => 0, selfBundle: (): string => SELF })
  let dup = new DuplicateFinder()
  let large = new LargeFileFinder()
  set.clean = (ctx, hand): Promise<RunEnd> => clean.run(ctx, hand)
  set.duplicate = (ctx, hand): Promise<RunEnd> => dup.run(ctx, hand)
  set.largeFile = (ctx, hand): Promise<RunEnd> => large.run(ctx, hand)
  RunnerRegistry.registerAll(set)
  let table = RunnerRegistry.table()
  require(table.has('clean') && table.clean === set.clean, 'registerAll 登记 clean')
  require(table.has('duplicate') && table.duplicate === set.duplicate, 'registerAll 登记 duplicate')
  require(table.has('large-file') && table.largeFile === set.largeFile, 'registerAll 登记 large-file')
  for (let kind of ['permission', 'apps', 'protect']) {
    require(!table.has(kind as 'permission'), '不登记其它种类：' + kind)
  }
}

export async function runCleanFindersChecks(): Promise<void> {
  await cacheAvailable()
  await cacheUnavailable()
  await noGrantNote()
  await corpseLimit()
  await noteOrder()
  await duplicates()
  await systemRejected()
  await largeFiles()
  await registry()
}
