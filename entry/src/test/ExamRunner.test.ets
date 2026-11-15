import type {
  BundleRow, CheckItem, CloudBatch, CloudView, ExamReport, FileGrant, FileSource, JobRecord, JobRequest,
  PermissionFact, PosturePort, ProtectFact, QueryKey, TrustEntry, UseFact
} from '../main/ets/center/CenterTypes'
import { CenterError } from '../main/ets/center/CenterError'
import { AppJudge } from '../main/ets/engine/AppJudge'
import { RulePack } from '../main/ets/engine/RulePack'
import { CancelFlag } from '../main/ets/task/CancelFlag'
import type { ExamContext } from '../main/ets/task/Contexts'
import { RunnerRegistry, RunnerSet } from '../main/ets/task/RunnerRegistry'
import type { ResultHand, RunEnd } from '../main/ets/task/RunnerRegistry'
import { cacheDirBytes, ExamRunner } from '../main/ets/feature/exam/ExamRunner'

const SELF: string = 'com.jinyinhu.securitycenter'
const CAMERA: string = 'ohos.permission.CAMERA'
const BACKGROUND: string = 'ohos.permission.LOCATION_IN_BACKGROUND'
const CONTACTS: string = 'ohos.permission.READ_CONTACTS'
const INTERNET: string = 'ohos.permission.INTERNET'
const JOB: string = 'job-exam-1'
const STEPS: string[] = ['正在检查系统安全', '正在扫描应用', '正在计算可清理空间', '正在检查应用权限']
const RULES: string = JSON.stringify({
  version: '2026.11.12',
  bundles: [{ bundleName: 'com.example.risk', certAlgo: 'platform-fingerprint', certSha256: 'abab', level: 'risk',
    reason: '演示用风险包' }],
  officials: [{ bundleName: 'com.example.official', certAlgo: 'platform-fingerprint', certSha256: ['ccdd'],
    reason: '签名与官方记录不符' }],
  files: [],
  heuristics: [{ id: 'background-location-and-camera', permissions: [BACKGROUND, CAMERA], reason: '后台定位和相机' }]
})

interface Instrumentation {
  __anomalyCalls?: number
  __installers?: InstallerStub
}

interface InstallerHitStub {
  uri: string
  name: string
  size: number
  bundleName: string
  sha256: string
  reason: string
  clazz: string
}

interface InstallerStub {
  hits: InstallerHitStub[]
  stoppedByLimit: boolean
  calls: string[][]
}

function host(): Instrumentation {
  return globalThis as Instrumentation
}

function require(value: boolean, message: string): void {
  if (!value) {
    throw new Error(message)
  }
}

function installers(hits: InstallerHitStub[], stoppedByLimit: boolean): InstallerStub {
  let stub: InstallerStub = { hits: hits, stoppedByLimit: stoppedByLimit, calls: [] }
  host().__installers = stub
  return stub
}

function hap(uri: string, size: number, clazz: string): InstallerHitStub {
  return { uri: uri, name: uri, size: size, bundleName: 'com.example.hap', sha256: 'ff', reason: '', clazz: clazz }
}

class App {
  name: string
  cert: string
  declared: string[]
  granted: string[]
  source: 'system' | 'preinstalled' | 'store' | 'sideload' | 'unknown' = 'unknown'

  constructor(name: string, cert: string, declared: string[], granted: string[]) {
    this.name = name
    this.cert = cert
    this.declared = declared
    this.granted = granted
  }
}

function row(app: App): BundleRow {
  return { bundleName: app.name, version: '1.0', versionCode: 1, certSha256: app.cert,
    certAlgo: app.cert.length > 0 ? 'platform-fingerprint' : 'none', declaredPermissions: app.declared,
    source: app.source, verdict: { level: 'unknown', source: 'system', reason: '', evidence: '', cloud: 'unchecked' } }
}

class Cloud implements CloudBatch {
  mode: string
  keys: QueryKey[] = []

  constructor(mode: string) {
    this.mode = mode
  }

  async query(keys: QueryKey[]): Promise<CloudView[]> {
    for (let key of keys) {
      this.keys.push(key)
    }
    return keys.map((): CloudView => {
      if (this.mode === 'offline') {
        return { state: 'offline', level: 'none', reason: '未联网', evidence: '' }
      }
      if (this.mode === 'unconfigured') {
        return { state: 'offline', level: 'none', reason: '未联网，云服务未配置', evidence: '' }
      }
      return { state: 'reached', level: this.mode === 'unknown' ? 'unknown' : 'ok', reason: '', evidence: 'signed' }
    })
  }
}

class Access {
  apps: App[]
  isReady: boolean
  calls: number = 0

  constructor(apps: App[], isReady: boolean) {
    this.apps = apps
    this.isReady = isReady
  }

  ready(): boolean {
    return this.isReady
  }

  async facts(bundles: BundleRow[]): Promise<PermissionFact[]> {
    this.calls++
    let out: PermissionFact[] = []
    for (let bundle of bundles) {
      let app = this.apps.find((a: App): boolean => a.name === bundle.bundleName)
      for (let permission of bundle.declaredPermissions) {
        let granted = this.isReady && app !== undefined && app.granted.indexOf(permission) >= 0
        out.push({ bundleName: bundle.bundleName, displayName: bundle.bundleName + '标签', permission: permission,
          label: permission, group: '', sensitive: false, declared: true,
          grant: this.isReady ? (granted ? 'granted' : 'denied') : 'unknown', fixed: false, tokenId: 7,
          source: bundle.source })
      }
    }
    return out
  }

  async recentUses(): Promise<UseFact[]> {
    return []
  }
}

class Posture implements PosturePort {
  pure: string
  lock: string
  el: string

  constructor(pure: string = 'ok', lock: string = 'ok', el: string = 'ok') {
    this.pure = pure
    this.lock = lock
    this.el = el
  }

  async pureMode(): Promise<ProtectFact> {
    return fact('pure-mode', this.pure)
  }

  async lockdown(): Promise<ProtectFact> {
    return fact('lockdown', this.lock)
  }

  async el5(): Promise<ProtectFact> {
    return fact('el5', this.el)
  }
}

function fact(id: string, status: string): ProtectFact {
  if (status === 'throw') {
    throw new Error('posture down')
  }
  let detail = status === 'unsupported' ? '无法读取' + id : id + ' ' + status
  return { id: id, status: status === 'ok' ? 'ok' : (status === 'risk' ? 'risk' : 'unsupported'),
    expected: '', actual: '', detail: detail }
}

class Files implements FileSource {
  grants: FileGrant[]

  constructor(granted: boolean) {
    this.grants = granted ? [{ uri: 'file:///storage/Download', displayName: 'Download', persisted: true, at: '' }] : []
  }

  persisted(): FileGrant[] {
    return this.grants
  }

  forget(uri: string): void {
  }
}

class Hand implements ResultHand {
  saves: number = 0
  last: ExamReport | null = null

  save(result: Object): void {
    this.saves++
    this.last = JSON.parse(JSON.stringify(result)) as ExamReport
  }
}

class Setup {
  apps: App[] = []
  cloud: Cloud = new Cloud('ok')
  posture: PosturePort = new Posture()
  censusFails: boolean = false
  grantsReady: boolean = true
  cacheBytes: Map<string, number> = new Map<string, number>()
  cacheUnsupported: boolean = false
  ownCache: number = 300
  ownCacheFails: boolean = false
  filesGranted: boolean = true
  trust: TrustEntry[] = []
  onCache: (flag: CancelFlag) => void = (flag: CancelFlag): void => {}
}

class Outcome {
  report: ExamReport
  end: RunEnd
  messages: string[]
  access: Access
  hand: Hand

  constructor(report: ExamReport, end: RunEnd, messages: string[], access: Access, hand: Hand) {
    this.report = report
    this.end = end
    this.messages = messages
    this.access = access
    this.hand = hand
  }
}

function record(): JobRecord {
  return { jobId: JOB, seq: 1, kind: 'exam', lane: 'heavy', startedAt: '', finishedAt: '', state: 'running',
    itemCount: 0, riskCount: 0, summary: '', resultFile: '' }
}

async function run(setup: Setup): Promise<Outcome> {
  let messages: string[] = []
  let flag = new CancelFlag()
  let access = new Access(setup.apps, setup.grantsReady)
  let request: JobRequest = { kind: 'exam', scope: 'quick', uris: [], focus: '' }
  let ctx: ExamContext = {
    base: { job: record(), request: request, cancel: flag, clock: { nowIso: (): string => '2026-11-15T00:00:00Z' },
      report: (done: number, total: number, message: string): void => {
        messages.push(message)
      } },
    posture: setup.posture,
    census: { list: async (): Promise<BundleRow[]> => {
      if (setup.censusFails) {
        throw new CenterError('unsupported', 'bundles')
      }
      return setup.apps.map((app: App): BundleRow => row(app))
    } },
    cache: { stats: async (name: string): Promise<number> => {
      setup.onCache(flag)
      if (setup.cacheUnsupported) {
        throw new CenterError('unsupported', 'cacheStats')
      }
      let bytes = setup.cacheBytes.get(name)
      if (bytes === undefined) {
        throw new CenterError('io', 'getBundleStats:13900005')
      }
      return bytes
    } },
    files: new Files(setup.filesGranted),
    open: {} as Object as ExamContext['open'],
    access: access,
    judge: new AppJudge(setup.cloud)
  }
  let hand = new Hand()
  let runner = new ExamRunner({
    trust: (): TrustEntry[] => setup.trust,
    ownCache: async (): Promise<number> => {
      if (setup.ownCacheFails) {
        throw new Error('cacheDir unreadable')
      }
      return setup.ownCache
    }
  })
  let end = await runner.run(ctx, hand)
  require(hand.last !== null, '体检写下了结果文件')
  return new Outcome(hand.last as ExamReport, end, messages, access, hand)
}

function itemOf(report: ExamReport, id: string): CheckItem {
  let found = report.items.find((item: CheckItem): boolean => item.id === id)
  if (found === undefined) {
    throw new Error('缺少 ' + id)
  }
  return found
}

function hasItem(report: ExamReport, id: string): boolean {
  return report.items.some((item: CheckItem): boolean => item.id === id)
}

function distinct(messages: string[]): string[] {
  let out: string[] = []
  for (let message of messages) {
    if (out.length === 0 || out[out.length - 1] !== message) {
      out.push(message)
    }
  }
  return out
}

function anomalyCalls(): number {
  return host().__anomalyCalls ?? 0
}

function standardApps(): App[] {
  return [
    new App(SELF, 'eeff', [CAMERA], [CAMERA]),
    new App('com.example.official', 'ccdd', [INTERNET], [INTERNET]),
    new App('com.example.suspect', '1234', [BACKGROUND, CAMERA, INTERNET], [BACKGROUND, CAMERA]),
    new App('com.example.plain', '5678', [CONTACTS], [CONTACTS])
  ]
}

function standard(): Setup {
  let setup = new Setup()
  setup.apps = standardApps()
  setup.cacheBytes.set(SELF, 100)
  setup.cacheBytes.set('com.example.official', 0)
  setup.cacheBytes.set('com.example.suspect', 50)
  setup.cacheBytes.set('com.example.plain', 25)
  installers([hap('file:///storage/Download/a.hap', 1000, 'installer'),
    hap('file:///storage/Download/b.hap', 2000, 'residue')], false)
  return setup
}

async function rulesMissing(): Promise<void> {
  require(RulePack.active().rulesVersion === 'none', '本检查须在任何规则加载之前运行')
  let out = await run(standard())
  let rules = itemOf(out.report, 'exam.rules.version')
  require(rules.kind === 'state' && rules.status === 'risk' && rules.countsTowardState,
    '没有任何一份规则时 exam.rules.version 是计入状态的 risk')
  require(rules.action.route === 'protect' && rules.action.params === 'rules', '规则版本动作是 protect/rules')
  require(out.report.state === 'risk', '规则缺失让体检为 risk')
}

async function fullRun(): Promise<void> {
  RulePack.load(RULES)
  let setup = standard()
  let before = anomalyCalls()
  let out = await run(setup)
  let report = out.report
  require(JSON.stringify(distinct(out.messages)) === JSON.stringify(STEPS), '进度文案按四步依次出现：' +
    distinct(out.messages).join('|'))

  let ids = report.items.map((item: CheckItem): string => item.id)
  require(JSON.stringify(ids) === JSON.stringify(['exam.protect.pure-mode', 'exam.protect.lockdown',
    'exam.protect.el5', 'exam.malware.apps', 'exam.malware.suspicious', 'exam.rules.version',
    'exam.permission.anomaly']), '项目 id：' + ids.join(','))
  for (let id of ['exam.protect.pure-mode', 'exam.protect.lockdown', 'exam.protect.el5']) {
    let item = itemOf(report, id)
    require(item.group === 'protect' && item.kind === 'state' && item.source === 'system' &&
      item.action.route === 'protect' && item.action.params === '' && item.countsTowardState,
      id + ' 是防护组的状态项，动作 protect 空参数')
  }
  let apps = itemOf(report, 'exam.malware.apps')
  require(apps.title === '应用信誉' && apps.group === 'threat' && apps.kind === 'state' &&
    apps.status === 'ok' && apps.countsTowardState && apps.action.route === 'malware' &&
    apps.action.params === JOB, '应用信誉项：threat/state，动作 malware + 本次 jobId')
  let suspicious = itemOf(report, 'exam.malware.suspicious')
  require(suspicious.title === '可疑应用' && suspicious.kind === 'advice' && suspicious.status === 'attention' &&
    !suspicious.countsTowardState && suspicious.action.route === 'malware' && suspicious.action.params === JOB,
    '可疑应用项：advice/attention，动作 malware + 本次 jobId')
  let rules = itemOf(report, 'exam.rules.version')
  require(rules.group === 'rules' && rules.kind === 'advice' && rules.status === 'ok' &&
    rules.detail.indexOf('2026.11.12') >= 0, '规则正常时是 ok 的建议项，写本地版本')
  let anomaly = itemOf(report, 'exam.permission.anomaly')
  require(anomaly.group === 'permission' && anomaly.kind === 'advice' && anomaly.status === 'attention' &&
    anomaly.action.route === 'permission' && anomaly.action.params === 'anomaly:' + JOB,
    '权限异常项：动作 permission + anomaly:jobId')

  require(report.state === 'clear', '可疑和权限异常不改圆环：' + report.state)
  require(report.jobId === JOB && report.appsComplete, '应用循环写完时 appsComplete=true')
  require(report.summary.riskApps === 0 && report.summary.suspiciousApps === 1 &&
    report.summary.unknownApps === 0 && report.summary.okApps === 3, '四个计数按已判定行')
  require(report.advice === 2 && report.skipped === 0, 'advice 是 advice 且不是 ok 的条数，skipped 为 0')
  require(report.summary.sensitiveKnown && report.summary.sensitiveApps === 2,
    'sensitiveApps 不含本应用：' + report.summary.sensitiveApps)
  require(report.summary.anomalyApps === 1 && anomalyCalls() === before + 1, '授权可读时调用一次 Anomaly.count')
  let suspect = report.apps.find((hit) => hit.fingerprint.bundleName === 'com.example.suspect')
  require(suspect !== undefined && suspect.verdict.level === 'suspicious' &&
    JSON.stringify(suspect.granted) === JSON.stringify([BACKGROUND, CAMERA]), '已授予权限写入 ScanHit.granted')
  let official = report.apps.find((hit) => hit.fingerprint.bundleName === 'com.example.official')
  require(official !== undefined && official.verdict.evidence === 'official', '登记相符走同一套 Decide')
  require(report.apps.every((hit) => hit.fingerprint.kind === 'bundle' && hit.action === 'none'),
    '体检只判定已装应用，不处理任何一行')
  require(setup.cloud.keys.length === 4 && setup.cloud.keys.every((key) => key.sha256 === '' &&
    key.bundleName.length > 0), '安装包文件不送进 AppJudge，云查询键全是已装应用')
  require(!hasItem(report, 'exam.permission.sideload'), '来源全是 unknown 时不生成侧载项')
  require(report.items.every((item) => item.detail.indexOf('没有侧载应用') < 0), '不写「没有侧载应用」')

  let stub = host().__installers as InstallerStub
  require(stub.calls.length === 1 && stub.calls[0].length === 4 && stub.calls[0].indexOf(SELF) >= 0,
    '安装包只经 listInstallers 一次，已装集合是包列表')
  let parts = report.summary.parts.map((p) => p.kind + ':' + p.id + ':' + p.bytes).join(',')
  require(parts === 'cache:' + SELF + ':100,cache:com.example.suspect:50,cache:com.example.plain:25,' +
    'installer:file:///storage/Download/a.hap:1000,installer:file:///storage/Download/b.hap:2000',
    '缓存和安装包都写进 parts：' + parts)
  require(report.summary.cleanableBytes === 3175 && report.summary.cleanableKnown &&
    report.summary.cleanableNote === '', 'cleanableBytes 是 parts 之和，测全时备注为空')
  require(out.end.itemCount === 4 && out.end.riskCount === 0 && out.end.summary === '', 'RunEnd 写已判定数')
}

async function riskApp(): Promise<void> {
  RulePack.load(RULES)
  let setup = standard()
  setup.apps.push(new App('com.example.risk', 'abab', [], []))
  setup.cacheBytes.set('com.example.risk', 0)
  let out = await run(setup)
  require(out.report.summary.riskApps === 1 && itemOf(out.report, 'exam.malware.apps').status === 'risk' &&
    out.report.state === 'risk' && out.end.riskCount === 1, '高置信黑规则让应用信誉项和体检为 risk')
  require(setup.cloud.keys.every((key) => key.bundleName !== 'com.example.risk'), '第 2 步结束的包不问云')
}

async function grantsNotReady(): Promise<void> {
  RulePack.load(RULES)
  let setup = standard()
  setup.grantsReady = false
  let before = anomalyCalls()
  let out = await run(setup)
  let report = out.report
  require(!report.summary.sensitiveKnown && report.summary.sensitiveApps === 0, '授权不可读时 sensitiveKnown=false')
  require(anomalyCalls() === before, '授权不可读时不调用 Anomaly.count')
  let anomaly = itemOf(report, 'exam.permission.anomaly')
  require(anomaly.status === 'unsupported' && anomaly.detail === '无法读取授权状态' && !anomaly.countsTowardState,
    '授权不可读时权限异常项暂不支持')
  require(report.apps.every((hit) => hit.granted.length === 0), '授权不可读时 granted 为空数组')
  require(report.summary.suspiciousApps === 0, '授权不可读时已装应用不因权限组合可疑')
  require(report.skipped === 1 && report.state === 'clear', 'skipped 数 unsupported，建议项不改圆环')
}

async function grantsReadyNobody(): Promise<void> {
  RulePack.load(RULES)
  let setup = standard()
  setup.apps = [new App(SELF, 'eeff', [CAMERA], [CAMERA]), new App('com.example.plain', '5678', [CONTACTS], [])]
  let out = await run(setup)
  require(out.report.summary.sensitiveKnown && out.report.summary.sensitiveApps === 0,
    '授权可读且人数为 0 时 sensitiveKnown 仍为 true')
  require(itemOf(out.report, 'exam.permission.anomaly').status === 'ok', '没有异常时权限异常项为 ok')
}

async function sideload(): Promise<void> {
  RulePack.load(RULES)
  let setup = standard()
  let app = new App('com.example.side', '9999', [CAMERA], [CAMERA])
  app.source = 'sideload'
  setup.apps.push(app)
  setup.cacheBytes.set('com.example.side', 0)
  let out = await run(setup)
  let item = itemOf(out.report, 'exam.permission.sideload')
  require(item.status === 'attention' && item.kind === 'advice' && !item.countsTowardState,
    '侧载且持有敏感权限时生成侧载建议')
}

async function bundlesUnavailable(): Promise<void> {
  RulePack.load(RULES)
  let setup = standard()
  setup.censusFails = true
  setup.filesGranted = false
  let stub = installers([hap('file:///x.hap', 5, 'residue')], true)
  let out = await run(setup)
  let report = out.report
  let apps = itemOf(report, 'exam.malware.apps')
  require(apps.status === 'unsupported' && !apps.countsTowardState && apps.detail === '无法获取应用列表',
    '包列表不可用时应用信誉项 unsupported 且不计入')
  require(report.state === 'incomplete' && !report.appsComplete && report.apps.length === 0,
    '姿态全 ok、列不出应用时是未完成')
  require(itemOf(report, 'exam.permission.anomaly').status === 'unsupported', '包列表不可用时权限异常项暂不支持')
  require(out.access.calls === 0, '包列表不可用时不读授权')
  require(stub.calls.length === 0, '没有文件授权时不调用 listInstallers')
  require(report.summary.parts.length === 1 && report.summary.parts[0].id === SELF &&
    report.summary.parts[0].bytes === 300 && report.summary.cleanableKnown,
    '缓存端口用不上时只写本应用 cacheDir')
  require(report.summary.cleanableNote === '仅统计了本应用缓存、目录未授权，安装包未计入',
    '备注：' + report.summary.cleanableNote)
  require(JSON.stringify(distinct(out.messages)) === JSON.stringify(STEPS), '一项失败不中断后面的项')
}

async function postureFailures(): Promise<void> {
  RulePack.load(RULES)
  let setup = standard()
  setup.posture = new Posture('throw', 'unsupported', 'risk')
  let out = await run(setup)
  let report = out.report
  require(itemOf(report, 'exam.protect.pure-mode').status === 'unsupported' &&
    !itemOf(report, 'exam.protect.pure-mode').countsTowardState, '纯净模式读失败只影响该项')
  require(itemOf(report, 'exam.protect.lockdown').status === 'unsupported', 'lockdown 读不到是 unsupported')
  require(itemOf(report, 'exam.protect.el5').status === 'risk', 'el5 不在是 risk')
  require(itemOf(report, 'exam.malware.apps').status === 'ok' && report.state === 'risk',
    '其它项照常，体检为 risk')
  require(report.skipped === 2, 'skipped 是 unsupported 加 unverified 的条数')
}

async function offline(): Promise<void> {
  RulePack.load(RULES)
  let setup = standard()
  setup.cloud = new Cloud('offline')
  let out = await run(setup)
  let apps = itemOf(out.report, 'exam.malware.apps')
  require(apps.detail.indexOf('未联网') >= 0, '登记相符的本地 ok 离线时应用信誉项详情含「未联网」')
  require(apps.status === 'unknown', '其它离线未知行让应用信誉项为 unknown')
  require(itemOf(out.report, 'exam.rules.version').status === 'unknown', '云失败时规则版本项为 unknown')
  require(itemOf(out.report, 'exam.rules.version').kind === 'advice', '云失败时规则版本仍是建议')

  let only = standard()
  only.cloud = new Cloud('offline')
  only.apps = [new App('com.example.suspect', '1234', [BACKGROUND, CAMERA], [BACKGROUND, CAMERA])]
  out = await run(only)
  require(itemOf(out.report, 'exam.malware.apps').detail.indexOf('未联网') < 0,
    '只有可疑行离线时详情不含「未联网」')

  let none = standard()
  none.cloud = new Cloud('unconfigured')
  out = await run(none)
  require(itemOf(out.report, 'exam.rules.version').status === 'ok', '没有配置云服务时只写本地规则结论')
}

async function noCloudResult(): Promise<void> {
  RulePack.load(RULES)
  let setup = standard()
  setup.cloud = new Cloud('unknown')
  setup.apps = [new App('com.example.official', 'ccdd', [], [])]
  let out = await run(setup)
  let apps = itemOf(out.report, 'exam.malware.apps')
  require(apps.status === 'ok' && apps.detail === '云端暂无结果', '写回后再追加「云端暂无结果」：' + apps.detail)
}

async function cleanableVariants(): Promise<void> {
  RulePack.load(RULES)
  let none = standard()
  none.cacheUnsupported = true
  none.ownCacheFails = true
  none.filesGranted = false
  let out = await run(none)
  let summary = out.report.summary
  require(!summary.cleanableKnown && summary.parts.length === 0 && summary.cleanableBytes === 0 &&
    summary.cleanableNote === '', '本应用缓存也失败且没有安装包授权时 cleanableKnown=false、备注为空')

  let limited = standard()
  installers([hap('file:///storage/Download/a.hap', 1000, 'installer')], true)
  out = await run(limited)
  require(out.report.summary.cleanableNote === '部分安装包未统计' && out.report.appsComplete &&
    itemOf(out.report, 'exam.malware.apps').detail.indexOf('本次扫描未完成') < 0,
    'stoppedByLimit 只追加「部分安装包未统计」，不改 appsComplete')

  let empty = standard()
  installers([], false)
  out = await run(empty)
  require(out.report.summary.cleanableNote === '' && out.report.summary.cleanableKnown &&
    out.report.summary.cleanableBytes === 175, 'stoppedByLimit=false 且 hits 为空时不追加')

  let ownOnly = standard()
  ownOnly.cacheUnsupported = true
  ownOnly.ownCache = 42
  installers([], false)
  out = await run(ownOnly)
  require(out.report.summary.parts.length === 1 && out.report.summary.parts[0].bytes === 42 &&
    out.report.summary.cleanableNote === '仅统计了本应用缓存', '缓存端口不可用时退回本应用缓存')
}

async function rulesNotes(): Promise<void> {
  RulePack.load(RULES)
  RulePack.load('{broken')
  let out = await run(standard())
  let item = itemOf(out.report, 'exam.rules.version')
  require(item.kind === 'advice' && item.status === 'attention' && !item.countsTowardState &&
    item.detail.indexOf('规则文件损坏，仍使用上一份') >= 0, '损坏但仍有上一份时保持建议：' + item.detail)
  require(out.report.state === 'clear', '规则损坏的建议不改圆环')

  RulePack.load(JSON.stringify({
    version: '2026.11.12',
    bundles: [{ bundleName: 'com.example.bad', certAlgo: 'md5', certSha256: 'aa', level: 'risk', reason: '' }],
    officials: [{ bundleName: 'com.example.empty', certAlgo: 'platform-fingerprint', certSha256: [], reason: '' }],
    files: [],
    heuristics: [{ id: 'one', permissions: [CAMERA], reason: '' }]
  }))
  out = await run(standard())
  item = itemOf(out.report, 'exam.rules.version')
  require(item.status === 'ok' && item.detail.indexOf('有 1 条规则暂不可用、有 2 条规则未启用') >= 0,
    'N、M 两句写入详情且不改状态：' + item.detail)
}

async function appLimit(): Promise<void> {
  RulePack.load(RULES)
  let setup = new Setup()
  for (let i = 0; i < 5001; i++) {
    setup.apps.push(new App('com.example.many' + i, 'aa' + i, [], []))
  }
  installers([], false)
  let out = await run(setup)
  require(!out.report.appsComplete && out.end.summary === '已达本次扫描上限',
    '应用循环到上限时 appsComplete=false，JobRecord.summary 写「已达本次扫描上限」')
  let apps = itemOf(out.report, 'exam.malware.apps')
  require(apps.status === 'unknown' && apps.detail.indexOf('本次扫描未完成') >= 0, '到上限的应用信誉项不是 ok')
  require(out.report.summary.okApps === 5000 && out.end.itemCount === 5000, '计数等于已判定行')
}

async function truncation(): Promise<void> {
  RulePack.load(RULES)
  let setup = new Setup()
  setup.cloud = new Cloud('unknown')
  for (let i = 0; i < 2100; i++) {
    setup.apps.push(new App('com.example.unknown' + i, 'bb' + i, [], []))
  }
  installers([], false)
  let out = await run(setup)
  require(!out.report.appsComplete && out.end.summary === '结果较多，仅显示部分',
    '截断丢掉 unknown 时 appsComplete=false，summary 写「结果较多，仅显示部分」')
  require(out.report.summary.unknownApps === 2100 && out.report.apps.length === 2000, '计数在截断前写好')

  let oks = new Setup()
  for (let i = 0; i < 2100; i++) {
    oks.apps.push(new App('com.example.fine' + i, 'cc' + i, [], []))
  }
  oks.apps.push(new App('com.example.suspect', '1234', [BACKGROUND, CAMERA], [BACKGROUND, CAMERA]))
  out = await run(oks)
  require(out.report.appsComplete && out.end.summary === '', '只丢掉 ok 时 appsComplete 保持 true')
  require(out.report.summary.okApps === 2100 && out.report.summary.suspiciousApps === 1 &&
    out.report.apps.length === 2000 && out.report.apps[0].verdict.level === 'suspicious',
    '可疑全部留下，okApps 用截断前人数')
  require(itemOf(out.report, 'exam.malware.apps').status === 'ok', '只丢掉 ok 时应用信誉项仍为 ok')
}

async function cancelDuringCleanable(): Promise<void> {
  RulePack.load(RULES)
  let setup = standard()
  setup.onCache = (flag: CancelFlag): void => {
    flag.cancel()
  }
  let out = await run(setup)
  require(out.report.appsComplete && itemOf(out.report, 'exam.malware.apps').detail.indexOf('本次扫描未完成') < 0,
    '统计缓存阶段取消时 appsComplete 仍为 true')
  require(!hasItem(out.report, 'exam.permission.anomaly'), '取消后不再跑后面的项')
  require(out.messages[out.messages.length - 1] === '正在计算可清理空间', '停在统计缓存这一步')
}

function registry(): void {
  RunnerRegistry.registerAll()
  require(!RunnerRegistry.table().has('exam'), '不传 Runner 时表是空的')
  let set = new RunnerSet()
  let runner = new ExamRunner({ trust: (): TrustEntry[] => [], ownCache: async (): Promise<number> => 0 })
  set.exam = (ctx: ExamContext, hand: ResultHand): Promise<RunEnd> => runner.run(ctx, hand)
  RunnerRegistry.registerAll(set)
  let table = RunnerRegistry.table()
  require(table.has('exam'), 'registerAll 登记 exam')
  for (let kind of ['malware', 'clean', 'duplicate', 'large-file', 'permission', 'apps', 'protect']) {
    require(!table.has(kind as 'malware'), 'registerAll 只追加 exam：' + kind)
  }
}

function ownCacheDir(): void {
  require(cacheDirBytes('/cache') === 30, 'cacheDir 字节累加文件大小，不跟随符号链接')
}

export async function runExamRunnerChecks(): Promise<void> {
  await rulesMissing()
  await fullRun()
  await riskApp()
  await grantsNotReady()
  await grantsReadyNobody()
  await sideload()
  await bundlesUnavailable()
  await postureFailures()
  await offline()
  await noCloudResult()
  await cleanableVariants()
  await rulesNotes()
  await appLimit()
  await truncation()
  await cancelDuringCleanable()
  registry()
  ownCacheDir()
}
