import { hilog } from '@kit.PerformanceAnalysisKit'
import { CenterError } from '../../center/CenterError'
import { heavyBudgetMs, heavyMaxBytes, heavyMaxFiles, listMax } from '../../center/CenterLimits'
import type {
  CleanClass, DuplicateGroup, FileGrant, FileHit, FileToolReport
} from '../../center/CenterTypes'
import { HashWorker, isWorkerDown } from '../../engine/HashWorker'
import type { InstallerIo } from '../../engine/InstallerScan'
import { FsInstallerIo } from '../../engine/InstallerScan'
import type { FileToolContext } from '../../task/Contexts'
import { RunEnd } from '../../task/RunnerRegistry'
import type { ResultHand } from '../../task/RunnerRegistry'

const DOMAIN: number = 0x4A59
const TAG: string = 'Center'

const AT_LIMIT: string = '已达本次扫描上限'
const TRUNCATED: string = '结果较多，仅显示部分'

export interface FileHash {
  hash(fd: number, cancel: SharedArrayBuffer): Promise<FileDigest>
}

export interface FileDigest {
  sha256: string
  cancelled: boolean
}

/** 授权目录遍历与哈希。测试替换成假实现。 */
export class DuplicateTools {
  io: InstallerIo = new FsInstallerIo()
  hash: FileHash = new WorkerHash()
}

class WorkerHash implements FileHash {
  private worker: HashWorker = new HashWorker()

  async hash(fd: number, cancel: SharedArrayBuffer): Promise<FileDigest> {
    let result = await this.worker.hash(fd, cancel)
    let digest: FileDigest = { sha256: result.sha256, cancelled: result.cancelled }
    return digest
  }
}

class Report implements FileToolReport {
  hits: FileHit[] = []
  groups: DuplicateGroup[] = []
  complete: boolean = false
  note: string = ''
}

class Hit implements FileHit {
  uri: string = ''
  name: string = ''
  size: number = 0
  sha256: string = ''
  clazz: CleanClass = 'duplicate'
  reason: string = ''
  selected: boolean = false
  groupId: string = ''
}

class Group implements DuplicateGroup {
  groupId: string = ''
  sha256: string = ''
  size: number = 0
  fileUris: string[] = []
}

class Entry {
  uri: string = ''
  name: string = ''
  size: number = 0
  sha256: string = ''
}

class Budget {
  objects: number = 0
  bytes: number = 0
  started: number = 0
  hit: boolean = false

  constructor(started: number) {
    this.started = started
  }

  exhausted(now: number): boolean {
    if (this.objects >= heavyMaxFiles || this.bytes >= heavyMaxBytes || now - this.started >= heavyBudgetMs) {
      this.hit = true
    }
    return this.hit
  }
}

class Target {
  uri: string = ''
  root: string = ''
}

/**
 * 参数类型是 FileToolContext。按 size 分组，组内只有 1 个的丢掉，不算哈希。
 * 大小不同的不算哈希。哈希相同的组成 DuplicateGroup。不调用 Quarantine。
 */
export class DuplicateFinder {
  private tools: DuplicateTools

  constructor(tools: DuplicateTools = new DuplicateTools()) {
    this.tools = tools
  }

  async run(ctx: FileToolContext, hand: ResultHand): Promise<RunEnd> {
    let report = new Report()
    let budget = new Budget(Date.now())
    ctx.base.report(0, 0, '正在查找重复文件')

    let entries = await this.collect(ctx, budget)
    if (!ctx.base.cancel.cancelled()) {
      await this.group(ctx, budget, entries, report)
    }

    let dropped = false
    if (report.hits.length > listMax) {
      let keep = new Set<string>()
      let keptHits: FileHit[] = []
      let keptGroups: DuplicateGroup[] = []
      for (let group of report.groups) {
        if (keptHits.length + group.fileUris.length > listMax) {
          dropped = true
          break
        }
        keptGroups.push(group)
        for (let hit of report.hits) {
          if (hit.groupId === group.groupId) {
            keptHits.push(hit)
            keep.add(hit.uri)
          }
        }
      }
      report.hits = keptHits
      report.groups = keptGroups
      if (report.hits.length < keep.size) {
        dropped = true
      }
    }
    if (report.groups.length > listMax) {
      report.groups = report.groups.slice(0, listMax)
      dropped = true
    }

    let atLimit = budget.hit && !ctx.base.cancel.cancelled()
    report.note = notesOf(atLimit, dropped)
    report.complete = !atLimit && !dropped && !ctx.base.cancel.cancelled()
    for (let hit of report.hits) {
      hit.selected = false
    }
    hand.save(report)

    let end = new RunEnd()
    end.itemCount = report.hits.length
    end.summary = atLimit ? AT_LIMIT : ''
    return end
  }

  private async collect(ctx: FileToolContext, budget: Budget): Promise<Entry[]> {
    let out: Entry[] = []
    let grants = persistedOf(ctx.files.persisted())
    let seen = new Set<string>()
    for (let grant of grants) {
      let item = new Target()
      item.uri = grant.uri
      item.root = rootOf(grant.uri)
      if (!(await this.visit(ctx, item, item.uri, grants, seen, out, budget))) {
        break
      }
    }
    return out
  }

  private async visit(ctx: FileToolContext, item: Target, uri: string, grants: FileGrant[],
    seen: Set<string>, out: Entry[], budget: Budget): Promise<boolean> {
    if (ctx.base.cancel.cancelled() || budget.exhausted(Date.now())) {
      return false
    }
    let open = ctx.open
    let accepted = open.accept(uri, item.root)
    if (accepted instanceof CenterError) {
      return true
    }
    if (seen.has(accepted)) {
      return true
    }
    seen.add(accepted)
    let directory = false
    try {
      let stat = this.tools.io.stat(accepted)
      if (stat.symbolicLink) {
        return true
      }
      directory = stat.directory
    } catch (err) {
      hilog.warn(DOMAIN, TAG, 'duplicate stat failed')
      return true
    }
    if (!directory) {
      return await this.measure(ctx, uri, item, grants, out, budget)
    }
    let names: string[] = []
    try {
      names = this.tools.io.list(accepted).slice().sort(compareUtf8)
    } catch (err) {
      hilog.warn(DOMAIN, TAG, 'duplicate list failed')
      return true
    }
    for (let name of names) {
      if (name === '.' || name === '..' || name.indexOf('/') >= 0) {
        continue
      }
      let child = uri.replace(/\/$/, '') + '/' + name
      if (!(await this.visit(ctx, item, child, grants, seen, out, budget))) {
        return false
      }
    }
    return true
  }

  private async measure(ctx: FileToolContext, uri: string, item: Target, grants: FileGrant[],
    out: Entry[], budget: Budget): Promise<boolean> {
    if (ctx.base.cancel.cancelled() || budget.exhausted(Date.now())) {
      return false
    }
    let opened = ctx.open.open(uri, item.root, false, grants)
    if (opened instanceof CenterError) {
      return true
    }
    try {
      let size = 0
      try {
        size = this.tools.io.size(opened.fd)
      } catch (err) {
        hilog.warn(DOMAIN, TAG, 'duplicate size unreadable')
        return true
      }
      if (!Number.isSafeInteger(size) || size < 0) {
        return true
      }
      if (size > heavyMaxBytes - budget.bytes) {
        budget.hit = true
        return false
      }
      budget.objects++
      budget.bytes += size
      let entry = new Entry()
      entry.uri = uri
      entry.name = nameOf(uri)
      entry.size = size
      out.push(entry)
      ctx.base.report(out.length, 0, '正在查找重复文件')
    } finally {
      ctx.open.release(opened)
    }
    return !ctx.base.cancel.cancelled() && !budget.exhausted(Date.now())
  }

  /** 按 size 分组；组内只有 1 个丢掉；同 size 再算哈希；相同哈希组成 DuplicateGroup。 */
  private async group(ctx: FileToolContext, budget: Budget, entries: Entry[],
    report: Report): Promise<void> {
    let bySize = new Map<number, Entry[]>()
    for (let entry of entries) {
      let list = bySize.get(entry.size)
      if (list === undefined) {
        list = []
        bySize.set(entry.size, list)
      }
      list.push(entry)
    }
    let groupSeq = 0
    let sizes = Array.from(bySize.keys()).sort((a: number, b: number): number => a - b)
    for (let size of sizes) {
      let peers = bySize.get(size) as Entry[]
      if (peers.length < 2) {
        continue
      }
      if (ctx.base.cancel.cancelled() || budget.exhausted(Date.now())) {
        budget.hit = !ctx.base.cancel.cancelled()
        break
      }
      let grants = persistedOf(ctx.files.persisted())
      for (let entry of peers) {
        if (ctx.base.cancel.cancelled() || budget.exhausted(Date.now())) {
          budget.hit = !ctx.base.cancel.cancelled()
          break
        }
        let digest = await this.hashOne(ctx, entry, grants)
        if (digest === null) {
          if (ctx.base.cancel.cancelled()) {
            return
          }
          continue
        }
        entry.sha256 = digest
      }
      let byHash = new Map<string, Entry[]>()
      for (let entry of peers) {
        if (entry.sha256.length === 0) {
          continue
        }
        let list = byHash.get(entry.sha256)
        if (list === undefined) {
          list = []
          byHash.set(entry.sha256, list)
        }
        list.push(entry)
      }
      let hashes = Array.from(byHash.keys()).sort(compareUtf8)
      for (let sha of hashes) {
        let same = byHash.get(sha) as Entry[]
        if (same.length < 2) {
          continue
        }
        groupSeq++
        let groupId = 'dup-' + groupSeq.toString()
        let group = new Group()
        group.groupId = groupId
        group.sha256 = sha
        group.size = size
        group.fileUris = same.map((entry: Entry): string => entry.uri)
        report.groups.push(group)
        for (let entry of same) {
          report.hits.push(fileHit(entry, groupId))
        }
      }
    }
  }

  private async hashOne(ctx: FileToolContext, entry: Entry, grants: FileGrant[]): Promise<string | null> {
    let root = rootOf(entry.uri)
    let match = grants.find((grant: FileGrant): boolean => entry.uri.indexOf(grant.uri) === 0)
    if (match !== undefined) {
      root = rootOf(match.uri)
    }
    let opened = ctx.open.open(entry.uri, root, false, grants)
    if (opened instanceof CenterError) {
      return null
    }
    try {
      let digest = await this.tools.hash.hash(opened.fd, ctx.base.cancel.buffer)
      if (digest.cancelled || ctx.base.cancel.cancelled()) {
        return null
      }
      return digest.sha256
    } catch (err) {
      let failure = err as Object
      rethrowCancel(failure)
      if (failure instanceof CenterError && isWorkerDown(failure)) {
        throw failure
      }
      hilog.warn(DOMAIN, TAG, 'duplicate hash failed: %{public}s', reasonOf(failure))
      return null
    } finally {
      ctx.open.release(opened)
    }
  }
}

function fileHit(entry: Entry, groupId: string): FileHit {
  let hit = new Hit()
  hit.uri = entry.uri
  hit.name = entry.name
  hit.size = entry.size
  hit.sha256 = entry.sha256
  hit.clazz = 'duplicate'
  hit.reason = ''
  hit.selected = false
  hit.groupId = groupId
  return hit
}

function notesOf(atLimit: boolean, dropped: boolean): string {
  let notes: string[] = []
  if (atLimit) {
    notes.push(AT_LIMIT)
  }
  if (dropped) {
    notes.push(TRUNCATED)
  }
  return notes.join('、')
}

function persistedOf(grants: FileGrant[]): FileGrant[] {
  return grants.filter((grant: FileGrant): boolean => grant.persisted === true)
}

function rootOf(uri: string): string {
  return uri.startsWith('file:///') ? uri.substring('file://'.length) : uri
}

function nameOf(uri: string): string {
  let trimmed = uri.replace(/\/$/, '')
  return trimmed.substring(trimmed.lastIndexOf('/') + 1)
}

function compareUtf8(a: string, b: string): number {
  let left = Array.from(a)
  let right = Array.from(b)
  for (let i = 0; i < Math.min(left.length, right.length); i++) {
    let difference = (left[i].codePointAt(0) || 0) - (right[i].codePointAt(0) || 0)
    if (difference !== 0) {
      return difference
    }
  }
  return left.length - right.length
}

function rethrowCancel(err: Object): void {
  if (err instanceof CenterError && err.code === 'cancelled') {
    throw err
  }
}

function reasonOf(err: Object): string {
  if (err instanceof CenterError) {
    return err.code + ':' + err.raw
  }
  if (err instanceof Error) {
    return err.message
  }
  return 'error'
}
