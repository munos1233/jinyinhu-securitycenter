import type {
  BundleRow, CacheRow, CheckItem, CleanReport, CountedByte, ExamReport, FileHit, FileToolReport, Fingerprint,
  JobKind, JobRecord, JobState, QuarantineEntry, RiskLevel, ScanHit, ScanReport, Verdict
} from '../main/ets/center/CenterTypes'
import { CenterError } from '../main/ets/center/CenterError'
import { HeuristicRule, RuleLoad } from '../main/ets/engine/RulePack'
import { AuditLog } from '../main/ets/record/AuditLog'
import type { OwnCache, QuarantineDoor } from '../main/ets/record/Disposition'
import { Disposition } from '../main/ets/record/Disposition'
import type { CenterFiles } from '../main/ets/record/Writer'
import { Writer } from '../main/ets/record/Writer'

const SELF: string = 'com.jinyinhu.securitycenter'
const CAMERA: string = 'ohos.permission.CAMERA'
const BACKGROUND: string = 'ohos.permission.LOCATION_IN_BACKGROUND'
const NOT_SETTLED: string = '扫描尚未完成'
const TRUST: string = 'center/trust.json'
const FILE_F: string = 'file://docs/Download/f.hap'
const FILE_G: string = 'file://docs/Download/g.hap'
const FILE_OK: string = 'file://docs/Download/ok.txt'
const FILE_U: string = 'file://docs/Download/u.bin'
const FILE_NOHASH: string = 'file://docs/Download/nohash.bin'

class MemoryFiles implements CenterFiles {
  values: Map<string, string> = new Map()

  read(path: string): string | null {
    let text = this.values.get(path)
    return text === undefined ? null : text
  }

  write(path: string, text: string): void {
    this.values.set(path, text)
  }

  rename(from: string, to: string): void {
    let text = this.read(from)
    if (text === null) {
      return
    }
    this.values.delete(from)
    this.values.set(to, text)
  }

  remove(path: string): void {
    this.values.delete(path)
  }
}

class FakeInstaller {
  calls: string[] = []
  fail: string = ''

  async uninstall(bundleName: string): Promise<void> {
    this.calls.push(bundleName)
    if (this.fail.length > 0) {
      throw new CenterError('io', 'uninstall:' + this.fail)
    }
  }
}

class FakeCache {
  calls: string[] = []
  fail: string = ''

  async clear(bundleName: string): Promise<void> {
    this.calls.push(bundleName)
    if (this.fail.length > 0) {
      throw new CenterError('io', 'cleanBundleCacheFiles:' + this.fail)
    }
  }
}

class FakeOwn implements OwnCache {
  calls: number = 0
  bytes: number = 7

  async clear(): Promise<number> {
    this.calls++
    return this.bytes
  }
}

class FakeDoor implements QuarantineDoor {
  calls: string[] = []
  sizes: number[] = []
  fail: CenterError | null = null

  put(from: string, size: number, sha256: string, reason: string): CenterError | QuarantineEntry {
    this.calls.push(from)
    this.sizes.push(size)
    if (this.fail !== null) {
      return this.fail
    }
    return { id: 'q1', from: from, stored: 'q1', sha256: sha256, size: size, iv: '', tag: '', reason: reason,
      at: '', committed: true }
  }
}

class Setup {
  files: MemoryFiles = new MemoryFiles()
  installer: FakeInstaller = new FakeInstaller()
  cache: FakeCache = new FakeCache()
  own: FakeOwn = new FakeOwn()
  door: FakeDoor = new FakeDoor()
  disposition: Disposition

  constructor() {
    Writer.bind(this.files)
    this.disposition = new Disposition({
      installer: this.installer, cache: this.cache, ownCache: this.own, quarantine: this.door,
      rules: (): RuleLoad => rules()
    })
  }

  portCalls(): number {
    return this.installer.calls.length + this.cache.calls.length + this.own.calls + this.door.calls.length
  }
}

function require(value: boolean, message: string): void {
  if (!value) {
    throw new Error(message)
  }
}

function rules(): RuleLoad {
  let result = new RuleLoad()
  let row = new HeuristicRule()
  row.id = 'background-camera'
  row.permissions = [BACKGROUND, CAMERA]
  row.reason = '后台定位和相机'
  result.heuristics = [row]
  return result
}

function bundle(name: string, level: RiskLevel, evidence: string = '', granted: string[] = [],
  cert: string = 'aabb'): ScanHit {
  let fp: Fingerprint = { kind: 'bundle', id: name, bundleName: name, version: '1', versionCode: 3,
    certSha256: cert, certAlgo: 'platform-fingerprint', sha256: '', size: 0, label: name }
  let verdict: Verdict = { level: level, source: level === 'risk' ? 'local-black' : 'local-rule', reason: '原因',
    evidence: evidence, cloud: 'reached' }
  return { fingerprint: fp, displayName: name, verdict: verdict, quarantined: false, action: 'none',
    granted: granted }
}

function file(uri: string, level: RiskLevel, sha256: string = 'ab12', size: number = 40): ScanHit {
  let fp: Fingerprint = { kind: 'file', id: uri, bundleName: '', version: '', versionCode: 0, certSha256: '',
    certAlgo: 'none', sha256: sha256, size: size, label: uri }
  let verdict: Verdict = { level: level, source: level === 'risk' ? 'cloud' : 'local-rule', reason: '原因',
    evidence: '', cloud: 'reached' }
  return { fingerprint: fp, displayName: uri, verdict: verdict, quarantined: false, action: 'none', granted: [] }
}

function part(id: string, kind: 'cache' | 'installer', bytes: number): CountedByte {
  return { id: id, kind: kind, bytes: bytes }
}

function item(id: string, advice: boolean, status: CheckItem['status']): CheckItem {
  return { id: id, title: '', group: 'threat', status: status, kind: advice ? 'advice' : 'state',
    source: 'local-rule', detail: '', action: { route: '', params: '' }, countsTowardState: !advice }
}

function count(hits: ScanHit[], level: RiskLevel): number {
  return hits.filter((hit: ScanHit): boolean => hit.verdict.level === level).length
}

function exam(apps: ScanHit[], parts: CountedByte[], complete: boolean = true): ExamReport {
  let total = 0
  for (let row of parts) {
    total += row.bytes
  }
  let risk = count(apps, 'risk')
  return {
    jobId: '', state: risk > 0 ? 'risk' : 'clear', apps: apps, appsComplete: complete,
    items: [item('exam.malware.apps', false, risk > 0 ? 'risk' : 'ok'),
      item('exam.malware.suspicious', true, count(apps, 'suspicious') > 0 ? 'attention' : 'ok'),
      item('exam.permission.anomaly', true, 'attention')],
    summary: { riskApps: risk, suspiciousApps: count(apps, 'suspicious'), unknownApps: count(apps, 'unknown'),
      okApps: count(apps, 'ok'), parts: parts, cleanableBytes: total, cleanableKnown: true,
      cleanableNote: '部分安装包未统计', sensitiveApps: 1, sensitiveKnown: true, anomalyApps: 1 },
    skipped: 0, advice: 1, generatedAt: ''
  }
}

function scan(hits: ScanHit[]): ScanReport {
  return { hits: hits, complete: false, note: '已达本次扫描上限', judged: hits.length + 2,
    risk: count(hits, 'risk'), suspicious: count(hits, 'suspicious'), unknown: count(hits, 'unknown'),
    ok: count(hits, 'ok') }
}

function record(jobId: string, seq: number, kind: JobKind, state: JobState): JobRecord {
  return { jobId: jobId, seq: seq, kind: kind, lane: 'heavy', startedAt: '', finishedAt: '', state: state,
    itemCount: 0, riskCount: 0, summary: 'summary-' + jobId, resultFile: Writer.resultFileOf(jobId) }
}

function put(setup: Setup, jobId: string, body: Object): void {
  setup.files.write(Writer.resultFileOf(jobId), JSON.stringify(body))
}

function text(setup: Setup, jobId: string): string {
  let value = setup.files.read(Writer.resultFileOf(jobId))
  return value === null ? '' : value
}

function readExam(setup: Setup, jobId: string): ExamReport {
  return JSON.parse(text(setup, jobId)) as ExamReport
}

function readScan(setup: Setup, jobId: string): ScanReport {
  return JSON.parse(text(setup, jobId)) as ScanReport
}

function hitOf(hits: ScanHit[], id: string): ScanHit {
  let found = hits.find((hit: ScanHit): boolean => hit.fingerprint.id === id)
  if (found === undefined) {
    throw new Error('fixture row missing ' + id)
  }
  return found
}

function itemOf(report: ExamReport, id: string): CheckItem {
  let found = report.items.find((row: CheckItem): boolean => row.id === id)
  if (found === undefined) {
    throw new Error('fixture item missing ' + id)
  }
  return found
}

function hasPart(report: ExamReport, id: string, kind: 'cache' | 'installer'): boolean {
  return report.summary.parts.some((row: CountedByte): boolean => row.id === id && row.kind === kind)
}

function snapshot(files: MemoryFiles, skip: string = ''): string {
  let keys = Array.from(files.values.keys()).filter((key: string): boolean => key !== skip).sort()
  return keys.map((key: string): string => key + '=' + files.read(key)).join('\n')
}

function states(): string {
  return Writer.loadIndex().map((row: JobRecord): string => row.jobId + ':' + row.state + ':' + row.summary)
    .join(',')
}

function main(): Setup {
  let setup = new Setup()
  let doneExam = exam([file(FILE_F, 'risk'), bundle('com.a', 'risk', '', [BACKGROUND, CAMERA]),
    bundle('com.ok', 'ok')], [part(FILE_F, 'installer', 40), part('com.a', 'cache', 100),
    part('com.a', 'installer', 30), part(FILE_G, 'installer', 9)])
  doneExam.summary.riskApps = 5
  put(setup, 'e-done', doneExam)
  let stopped = exam([bundle('com.a', 'risk', '', [BACKGROUND, CAMERA])],
    [part(FILE_F, 'installer', 40), part('com.b', 'cache', 80), part(SELF, 'cache', 12)], false)
  put(setup, 'e-stop', stopped)
  put(setup, 'e-other', exam([file(FILE_F, 'risk'), bundle('com.a', 'risk')], [part(FILE_F, 'installer', 40)]))
  put(setup, 'e-run', exam([file(FILE_F, 'risk')], [part(FILE_F, 'installer', 40)], false))
  put(setup, 'm-1', scan([file(FILE_F, 'risk'), bundle('com.a', 'risk'), file(FILE_OK, 'ok'),
    bundle('com.s', 'suspicious', 'heuristic'), bundle('com.mis', 'unknown', 'bundle-cert-mismatch'),
    bundle('com.unc', 'unknown', 'cert-uncompared'), bundle('com.imp', 'suspicious', 'impersonation'),
    bundle('com.nocert', 'unknown', '', [], ''), file(FILE_U, 'unknown', 'cd34'),
    file(FILE_NOHASH, 'unknown', '')]))
  let black = bundle('com.black', 'unknown')
  black.verdict.source = 'local-black'
  let withBlack = readScan(setup, 'm-1')
  withBlack.hits.push(black)
  withBlack.unknown++
  put(setup, 'm-1', withBlack)
  put(setup, 'm-run', scan([file(FILE_F, 'risk')]))
  let dup: FileToolReport = { hits: [{ uri: FILE_F, name: 'f', size: 40, sha256: 'ab12', clazz: 'duplicate',
    reason: '', selected: false, groupId: 'g' }], groups: [], complete: true, note: '' }
  put(setup, 'd-1', dup)
  let caches: CacheRow[] = [{ bundleName: 'com.a', displayName: 'A', cacheBytes: 100, selected: false },
    { bundleName: 'com.b', displayName: 'B', cacheBytes: 50, selected: false },
    { bundleName: 'com.c', displayName: 'C', cacheBytes: 5, selected: false }]
  let hits: FileHit[] = [{ uri: FILE_G, name: 'g.hap', size: 9, sha256: 'ef56', clazz: 'installer',
    reason: '已安装应用的安装包', selected: false, groupId: '' }]
  let clean: CleanReport = { caches: caches, hits: hits, groups: [], complete: true, note: '' }
  put(setup, 'c-1', clean)
  let own: CleanReport = { caches: [{ bundleName: SELF, displayName: '安全中心', cacheBytes: 12, selected: false }],
    hits: [], groups: [], complete: true, note: '无法读取其他应用缓存' }
  put(setup, 'c-own', own)
  let rows: BundleRow[] = ['com.a', 'com.z'].map((name: string): BundleRow => ({ bundleName: name, version: '1',
    versionCode: 3, certSha256: 'aabb', certAlgo: 'platform-fingerprint', declaredPermissions: [],
    source: 'sideload', verdict: bundle(name, 'unknown').verdict }))
  put(setup, 'a-1', rows)
  Writer.saveIndex([record('e-other', 2, 'exam', 'done'), record('e-done', 3, 'exam', 'done'),
    record('e-stop', 4, 'exam', 'interrupted'), record('m-1', 5, 'malware', 'done'),
    record('e-run', 6, 'exam', 'running'), record('m-run', 7, 'malware', 'running'),
    record('d-1', 8, 'duplicate', 'done'), record('c-1', 9, 'clean', 'done'),
    record('a-1', 10, 'apps', 'done'), record('c-own', 11, 'clean', 'done'),
    record('m-q', 12, 'malware', 'queued')])
  return setup
}

async function checkRefusals(): Promise<void> {
  let setup = main()
  let before = snapshot(setup.files)
  let d = setup.disposition
  let results = [
    await d.quarantine('m-run', FILE_F), await d.uninstall('m-q', 'com.a'), await d.quarantine('e-run', FILE_F),
    await d.quarantine('m-1', 'file://missing'), await d.quarantine('m-1', FILE_OK),
    await d.uninstall('m-1', FILE_F), await d.quarantine('m-1', 'com.a'), await d.quarantine('nope', FILE_F),
    await d.uninstall('a-1', 'com.missing'), await d.clearCache('m-1', 'com.a'),
    await d.clearCache('c-1', 'com.none'), await d.quarantine('c-1', FILE_F), await d.uninstall('c-1', 'com.a'),
    d.trust('m-run', FILE_F), d.trust('e-run', FILE_F)
  ]
  for (let result of results) {
    require(!result.done && result.message === NOT_SETTLED, '不在已收口结果里或作业未收口的目标没有以「扫描尚未完成」拒绝')
  }
  let dupQuarantine = await d.quarantine('d-1', FILE_F)
  let dupUninstall = await d.uninstall('d-1', 'com.a')
  require(!dupQuarantine.done && !dupUninstall.done && dupQuarantine.message !== '',
    'duplicate 的结果被拿去隔离或删除')
  require(setup.portCalls() === 0, '拒绝之后仍调用了卸载、隔离或清缓存')
  require(snapshot(setup.files) === before, '拒绝之后改了结果、索引、信任区或审计')
}

async function checkQuarantineFromScan(): Promise<void> {
  let setup = main()
  let otherBefore = text(setup, 'e-other')
  let indexBefore = states()
  let result = await setup.disposition.quarantine('m-1', FILE_F)
  require(result.done, '风险文件隔离失败')
  require(setup.door.calls.length === 1 && setup.door.calls[0] === FILE_F && setup.door.sizes[0] === 40,
    '隔离没有用结果里的 uri 和大小')
  let scanned = readScan(setup, 'm-1')
  let row = hitOf(scanned.hits, FILE_F)
  require(row.quarantined && row.action === 'quarantine', '隔离后 quarantined 或 action 没改')
  require(scanned.risk === 1 && scanned.ok === 1 && scanned.judged === 12, '隔离后风险计数没减 1，或 judged 被减了')
  require(!scanned.complete && scanned.note === '已达本次扫描上限', '处置改了 complete 或 note')

  let done = readExam(setup, 'e-done')
  require(hitOf(done.apps, FILE_F).action === 'quarantine' && done.summary.riskApps === 4,
    '最近一次 done 的体检没有回写这一行')
  require(!hasPart(done, FILE_F, 'installer') && done.summary.cleanableBytes === 139 &&
    done.summary.cleanableNote === '部分安装包未统计', '隔离安装包没有按 parts 减字节，或改了 cleanableNote')
  let stopped = readExam(setup, 'e-stop')
  require(!hasPart(stopped, FILE_F, 'installer') && stopped.summary.cleanableBytes === 92,
    '首页采用的中断体检没有减掉这条安装包')
  require(hitOf(stopped.apps, 'com.a').action === 'none' && stopped.summary.riskApps === 1,
    '目标不在 apps[] 里的体检被改了应用计数')
  require(text(setup, 'e-other') === otherBefore, '不在回写目标里的旧体检被改了')
  let running = readExam(setup, 'e-run')
  require(!hasPart(running, FILE_F, 'installer') && running.summary.cleanableBytes === 0,
    '正在跑的体检里已有的同一条 parts 没有减')
  require(hitOf(running.apps, FILE_F).action === 'none' && running.summary.riskApps === 1,
    '正在跑的体检被改了 apps[]')
  require(states() === indexBefore, '处置改了作业状态、摘要，或新增了 JobRecord')
  let audit = AuditLog.read()
  require(audit.length === 1 && audit[0].action === '隔离' && audit[0].target === FILE_F &&
    audit[0].result === '成功' && audit[0].jobId === 'm-1', '隔离没有追加一条审计')

  let again = await setup.disposition.quarantine('m-1', FILE_F)
  require(!again.done && again.message === NOT_SETTLED && setup.door.calls.length === 1,
    'action 已不是 none 的行又被隔离了一次')
}

async function checkUninstallFromExam(): Promise<void> {
  let setup = main()
  let result = await setup.disposition.uninstall('e-done', 'com.a')
  require(result.done && setup.installer.calls.join() === 'com.a', '体检里的风险应用没有卸载')
  let done = readExam(setup, 'e-done')
  require(hitOf(done.apps, 'com.a').action === 'uninstall', '卸载后 action 没改成 uninstall')
  require(done.summary.riskApps === 4, '正在看的体检同时是最近一次 done 时风险计数被减了两次')
  require(done.summary.anomalyApps === 0 && done.summary.sensitiveApps === 0,
    '卸载计入异常和敏感的应用后 anomalyApps 或 sensitiveApps 没减')
  require(itemOf(done, 'exam.permission.anomaly').status === 'ok', '异常人数为 0 时授权建议项没改成 ok')
  require(!hasPart(done, 'com.a', 'cache') && hasPart(done, 'com.a', 'installer') &&
    done.summary.cleanableBytes === 79, '卸载没有去掉 kind=cache 的整条，或去掉了 installer')
  let stopped = readExam(setup, 'e-stop')
  require(hitOf(stopped.apps, 'com.a').action === 'uninstall' && stopped.summary.riskApps === 0,
    '首页采用的中断体检里同一个包没有回写')
  require(stopped.state !== 'clear' && itemOf(stopped, 'exam.malware.apps').status === 'unknown',
    'appsComplete=false 时卸掉唯一风险后圆环变成了暂无风险')
  require(Writer.loadIndex().find((row: JobRecord): boolean => row.jobId === 'e-stop')?.state === 'interrupted',
    '处置后中断体检被改成了 done')
  let scanned = readScan(setup, 'm-1')
  require(hitOf(scanned.hits, 'com.a').action === 'none' && scanned.risk === 2,
    '正在看体检时把信誉结果也改了')
}

async function checkUninstallRefused(): Promise<void> {
  let setup = main()
  setup.installer.fail = '13'
  let before = snapshot(setup.files)
  let result = await setup.disposition.uninstall('m-1', 'com.a')
  require(!result.done && result.message.indexOf('返回码 13') >= 0, '系统拒绝卸载时摘要没有返回码')
  let audit = AuditLog.read()
  require(audit.length === 1 && audit[0].action === '卸载' && audit[0].result !== '成功',
    '卸载被拒没有留下非成功的审计')
  require(snapshot(setup.files, 'center/audit.log') === before, '卸载被拒时改了结果或体检')
}

async function checkAppsPage(): Promise<void> {
  let setup = main()
  let indexBefore = states()
  let doneBefore = text(setup, 'e-done')
  let result = await setup.disposition.uninstall('a-1', 'com.z')
  require(result.done, '软件页卸载失败')
  let rows = JSON.parse(text(setup, 'a-1')) as BundleRow[]
  require(rows.length === 1 && rows[0].bundleName === 'com.a', '软件页卸载成功后没有从 BundleRow[] 去掉该行')
  require(states() === indexBefore, '软件页卸载新增了 JobRecord 或改了作业状态')
  require(text(setup, 'e-done') === doneBefore, '不含该包的体检被改了')
  let second = await setup.disposition.uninstall('a-1', 'com.a')
  require(second.done && readExam(setup, 'e-done').summary.riskApps === 4 &&
    readExam(setup, 'e-stop').summary.riskApps === 0, '软件页卸载没有按 examWritebackTargets 回写体检')
  require(AuditLog.read().length === 2, '每次卸载应只追加一条审计')
}

async function checkCache(): Promise<void> {
  let setup = main()
  let doneBefore = text(setup, 'e-done')
  let scanBefore = text(setup, 'm-1')
  setup.cache.fail = '9'
  let failed = await setup.disposition.clearCache('c-1', 'com.b')
  require(!failed.done && failed.message.indexOf('9') >= 0, '清缓存失败没有写原因')
  let clean = JSON.parse(text(setup, 'c-1')) as CleanReport
  require(clean.caches.some((row: CacheRow): boolean => row.bundleName === 'com.b'), '清缓存失败的行没有留下')
  setup.cache.fail = ''
  let result = await setup.disposition.clearCache('c-1', 'com.b')
  require(result.done && setup.own.calls === 0 && setup.door.calls.length === 0,
    '清其它应用缓存走了本应用目录或隔离区')
  clean = JSON.parse(text(setup, 'c-1')) as CleanReport
  require(!clean.caches.some((row: CacheRow): boolean => row.bundleName === 'com.b'), '清除成功的行还在')
  let stopped = readExam(setup, 'e-stop')
  let row = stopped.summary.parts.find((p: CountedByte): boolean => p.id === 'com.b' && p.kind === 'cache')
  require(row !== undefined && row.bytes === 30 && stopped.summary.cleanableBytes === 82 &&
    stopped.summary.cleanableNote === '部分安装包未统计', '清缓存没有按实际字节减 parts 再求和')
  require(text(setup, 'e-done') === doneBefore, 'parts 里没有这一条的体检被改了字节')
  require(text(setup, 'm-1') === scanBefore, '清缓存改了 ScanReport')
  let missing = await setup.disposition.clearCache('c-1', 'com.c')
  require(missing.done && text(setup, 'e-done') === doneBefore && readExam(setup, 'e-stop').summary.cleanableBytes === 82,
    'parts 里没有的缓存被减了字节')

  let own = await setup.disposition.clearCache('c-own', SELF)
  require(own.done && setup.own.calls === 1 && setup.cache.calls.length === 3,
    '只有本应用这一条时没有直接删 cacheDir，或调用了缓存端口')
  stopped = readExam(setup, 'e-stop')
  let self = stopped.summary.parts.find((p: CountedByte): boolean => p.id === SELF)
  require(self !== undefined && self.bytes === 5 && stopped.summary.cleanableBytes === 75,
    '本应用缓存没有按实际清掉的字节减')

  let installer = await setup.disposition.quarantine('c-1', FILE_G)
  require(installer.done && setup.door.calls.join() === FILE_G, '清理页的安装包没有进隔离区')
  clean = JSON.parse(text(setup, 'c-1')) as CleanReport
  let done = readExam(setup, 'e-done')
  require(clean.hits.length === 0 && !hasPart(done, FILE_G, 'installer') && done.summary.riskApps === 5,
    '隔离安装包没有减 parts，或改了应用计数')
}

async function checkTrust(): Promise<void> {
  let setup = main()
  let scanBefore = text(setup, 'm-1')
  let first = setup.disposition.trust('m-1', 'com.s')
  require(first.done && first.button === '已添加信任，下次扫描生效', '可疑应用信任后按钮不是「已添加信任，下次扫描生效」')
  require(text(setup, 'm-1') === scanBefore, '新写入的信任改了该行等级或人数')
  let again = setup.disposition.trust('m-1', 'com.s')
  let trusted = JSON.parse(setup.files.read(TRUST) as string) as Object[]
  require(again.done && again.button === '已信任' && trusted.length === 1, '已经能走到第 7 步的行又写了一条信任')
  let fileTrust = setup.disposition.trust('m-1', FILE_U)
  trusted = JSON.parse(setup.files.read(TRUST) as string) as Object[]
  require(fileTrust.done && fileTrust.button === '已添加信任，下次扫描生效' && trusted.length === 2,
    '文件行没有按 sha256 写入信任')
  for (let id of ['com.mis', 'com.unc', 'com.imp', 'com.black', 'com.nocert', FILE_NOHASH, 'com.a', FILE_OK]) {
    let refused = setup.disposition.trust('m-1', id)
    require(!refused.done && refused.button === '', id + ' 不该提供信任')
  }
  trusted = JSON.parse(setup.files.read(TRUST) as string) as Object[]
  require(trusted.length === 2 && text(setup, 'm-1') === scanBefore, '不提供信任的行写进了信任区')
  require(setup.portCalls() === 0, '信任调用了卸载、隔离或清缓存')
}

async function checkRingRecalc(): Promise<void> {
  for (let complete of [true, false]) {
    let setup = new Setup()
    put(setup, 'x', exam([bundle('com.a', 'risk', '', [BACKGROUND, CAMERA])], [], complete))
    Writer.saveIndex([record('x', 1, 'exam', 'done')])
    let result = await setup.disposition.uninstall('x', 'com.a')
    let report = readExam(setup, 'x')
    require(result.done && report.summary.riskApps === 0, '卸掉唯一风险应用后 riskApps 不是 0')
    if (complete) {
      require(report.state === 'clear' && itemOf(report, 'exam.malware.apps').status === 'ok',
        'appsComplete=true 且没有未知时圆环没有按剩余项重算')
    } else {
      require(report.state === 'incomplete', 'appsComplete=false 时圆环变成了暂无风险')
    }
  }
  let setup = new Setup()
  let report = exam([bundle('com.a', 'risk')], [], true)
  let apps = itemOf(report, 'exam.malware.apps')
  apps.status = 'unsupported'
  apps.countsTowardState = false
  put(setup, 'y', report)
  Writer.saveIndex([record('y', 1, 'exam', 'interrupted')])
  let result = await setup.disposition.uninstall('y', 'com.a')
  let after = readExam(setup, 'y')
  require(result.done && itemOf(after, 'exam.malware.apps').status === 'unsupported' && after.state !== 'clear',
    '已收口的应用信誉项在处置后被改了状态，或圆环变成暂无风险')
  require(Writer.loadIndex()[0].state === 'interrupted', '处置把 interrupted 改成了 done')
}

export async function runDispositionChecks(): Promise<void> {
  await checkRefusals()
  await checkQuarantineFromScan()
  await checkUninstallFromExam()
  await checkUninstallRefused()
  await checkAppsPage()
  await checkCache()
  await checkTrust()
  await checkRingRecalc()
}
