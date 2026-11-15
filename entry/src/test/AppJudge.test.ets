import type {
  CancelFlag, CheckItem, CloudBatch, CloudView, ExamReport, Fingerprint, JobRecord,
  PermissionFact, QueryKey, RiskLevel, ScanHit, ScanReport, TrustEntry, Verdict, VerdictSource
} from '../main/ets/center/CenterTypes'
import type { HomeCandidate } from '../main/ets/feature/exam/ExamState'
import { Anomaly } from '../main/ets/center/Anomaly'
import { isSensitive } from '../main/ets/center/SensitiveCatalog'
import { reasonMax } from '../main/ets/center/CenterLimits'
import { decide } from '../main/ets/engine/Decide'
import type {
  GrantChange, GrantedResultStore, JudgeInput, ScanCandidate
} from '../main/ets/engine/AppJudge'
import {
  AppJudge, grantChangesFromFacts, rejudgeGranted, rejudgeGrantedResults
} from '../main/ets/engine/AppJudge'
import { BundleRule, FileRule, HeuristicRule, OfficialRule, RuleLoad } from '../main/ets/engine/RulePack'

const CAMERA: string = 'ohos.permission.CAMERA'
const BACKGROUND: string = 'ohos.permission.LOCATION_IN_BACKGROUND'
const CONTACTS: string = 'ohos.permission.READ_CONTACTS'

interface Instrumentation {
  __centerDecideCalls?: number
  __centerAppsStatusCalls?: number
  __centerAppendCalls?: number
  __centerStateCalls?: number
  __centerHilog?: string[]
}

function counters(): Instrumentation {
  return globalThis as Instrumentation
}

function resetCounters(): void {
  let host = counters()
  host.__centerDecideCalls = 0
  host.__centerAppsStatusCalls = 0
  host.__centerAppendCalls = 0
  host.__centerStateCalls = 0
  host.__centerHilog = []
}

function require(value: boolean, message: string): void {
  if (!value) {
    throw new Error(message)
  }
}

function fingerprint(name: string = 'com.example.app'): Fingerprint {
  return { kind: 'bundle', id: name, bundleName: name, version: '1', versionCode: 1,
    certSha256: 'aabb', certAlgo: 'platform-fingerprint', sha256: '', size: 0, label: '应用' }
}

function input(name: string): JudgeInput {
  return { fingerprint: fingerprint(name), declared: [], granted: [], grantsReady: true }
}

function cloud(level: 'ok' | 'unknown' | 'risk' | 'none' = 'unknown'): CloudView {
  return { state: 'reached', level: level, reason: '', evidence: 'signed' }
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

function official(name: string, algo: string = 'platform-fingerprint'): OfficialRule {
  let row = new OfficialRule()
  row.bundleName = name
  row.certAlgo = algo
  row.certSha256 = ['ccdd']
  return row
}

function nameRule(name: string, reason: string = '仅包名'): BundleRule {
  let row = new BundleRule()
  row.bundleName = name
  row.certAlgo = 'platform-fingerprint'
  row.step = 12
  row.level = 'unknown'
  row.reason = reason
  return row
}

function hit(name: string = 'com.example.app', level: RiskLevel = 'suspicious',
  reason: string = '已允许：后台定位和相机'): ScanHit {
  let verdict: Verdict = { level: level, source: 'local-rule', reason: reason,
    evidence: level === 'suspicious' ? 'heuristic' : '', cloud: 'reached' }
  return { fingerprint: fingerprint(name), displayName: name, verdict: verdict,
    quarantined: false, action: 'none', granted: [BACKGROUND, CAMERA] }
}

function scan(hits: ScanHit[], complete: boolean = true): ScanReport {
  return { hits: hits, complete: complete, note: complete ? '' : '已达本次扫描上限',
    judged: hits.length, risk: count(hits, 'risk'), suspicious: count(hits, 'suspicious'),
    unknown: count(hits, 'unknown'), ok: count(hits, 'ok') }
}

function count(hits: ScanHit[], level: RiskLevel): number {
  return hits.filter((row: ScanHit): boolean => row.action === 'none' && row.verdict.level === level).length
}

function item(id: string, advice: boolean = false): CheckItem {
  return { id: id, title: '', group: 'threat', status: advice ? 'attention' : 'ok',
    kind: advice ? 'advice' : 'state', source: 'local-rule', detail: '',
    action: { route: '', params: '' }, countsTowardState: !advice }
}

function exam(hits: ScanHit[], complete: boolean = true): ExamReport {
  return { jobId: '', state: 'clear', apps: hits, appsComplete: complete,
    items: [item('exam.malware.apps'), item('exam.malware.suspicious', true),
      item('exam.permission.anomaly', true)],
    summary: { riskApps: count(hits, 'risk'), suspiciousApps: count(hits, 'suspicious'),
      unknownApps: count(hits, 'unknown'), okApps: count(hits, 'ok'), parts: [],
      cleanableBytes: 0, cleanableKnown: false, cleanableNote: '',
      sensitiveApps: hits.filter((row: ScanHit): boolean => row.fingerprint.kind === 'bundle' &&
        row.fingerprint.bundleName !== 'com.jinyinhu.securitycenter' && row.action === 'none' &&
        row.granted.some((permission: string): boolean => isSensitive(permission))).length,
      sensitiveKnown: true, anomalyApps: Anomaly.count(hits, rules()) },
    skipped: 0, advice: 2, generatedAt: '' }
}

function remove(name: string = 'com.example.app', permissions: string[] = [CAMERA]): GrantChange[] {
  return [{ bundleName: name, mode: 'remove', permissions: permissions }]
}

function replace(name: string, permissions: string[]): GrantChange[] {
  return [{ bundleName: name, mode: 'replace', permissions: permissions }]
}

class FakeCloud implements CloudBatch {
  calls: QueryKey[][] = []
  cancellations: CancelFlag[] = []
  response: (keys: QueryKey[], cancel: CancelFlag) => Promise<CloudView[]>

  constructor(response: (keys: QueryKey[], cancel: CancelFlag) => Promise<CloudView[]>) {
    this.response = response
  }

  async query(keys: QueryKey[], cancel: CancelFlag): Promise<CloudView[]> {
    this.calls.push(keys)
    this.cancellations.push(cancel)
    return this.response(keys, cancel)
  }
}

class TestCancel implements CancelFlag {
  stopped: boolean = false
}

async function checkBatches(): Promise<void> {
  resetCounters()
  let pack = new RuleLoad()
  let black = new BundleRule()
  black.bundleName = 'com.black'
  black.certAlgo = 'platform-fingerprint'
  black.certSha256 = 'aabb'
  black.level = 'risk'
  pack.bundles = [black]
  let registration = official('com.example.item0')
  registration.certSha256 = ['aabb']
  pack.officials = [registration]
  let white = new FileRule()
  white.sha256 = 'white-hash'
  white.level = 'ok'
  pack.files = [white]
  let inputs: JudgeInput[] = [input('com.black')]
  for (let i = 0; i < 101; i++) {
    inputs.push(input('com.example.item' + i))
  }
  inputs[4].fingerprint.kind = 'file'
  inputs[4].fingerprint.id = 'file://private-user-path/installer.hap'
  inputs[4].fingerprint.bundleName = ''
  inputs[4].fingerprint.sha256 = 'white-hash'
  inputs[4].granted = [BACKGROUND, CAMERA]
  let trust: TrustEntry[] = [{ kind: 'bundle', fingerprint: 'aabb', id: 'com.example.item1',
    versionCode: 1, at: '' }]
  let queriedBefore = 0
  let service = new FakeCloud(async (keys: QueryKey[]): Promise<CloudView[]> => {
    require(counters().__centerDecideCalls === queriedBefore, 'decide 必须等本批云状态确定后才调用')
    queriedBefore += keys.length
    return keys.map((key: QueryKey): CloudView => cloud(key.bundleName === 'com.example.item2' ? 'risk' : 'unknown'))
  })
  let cancel = new TestCancel()
  let published: ScanHit[] = []
  let result = await new AppJudge(service).judge(inputs, pack, trust, cancel,
    (): boolean => cancel.stopped, (row: ScanHit): void => { published.push(row) })
  require(result.complete && result.hits.length === 102 && published.length === 102,
    '所有对象必须各产出一行，onHit 必须逐条通知')
  require(service.calls.map((batch: QueryKey[]): number => batch.length).join(',') === '50,50,1',
    '云查询必须按 50 个非 terminal 键分组')
  require(service.calls[0][0].bundleName === 'com.example.item0' &&
    result.hits[0].verdict.source === 'local-black' && result.hits[3].verdict.source === 'cloud' &&
    result.hits[3].verdict.level === 'risk', 'terminal 不占云下标，risk 必须回填发出该键的对象')
  require(result.hits[1].verdict.evidence === 'official' && result.hits[2].verdict.source === 'trust' &&
    result.hits[4].verdict.level === 'ok', '登记相符、信任和白哈希都应先查询云再收口')
  require(result.hits[4].granted.length === 0, '文件的 granted 必须恒为空')
  require(counters().__centerDecideCalls === 101 && counters().__centerHilog?.length === 0,
    '每个非 terminal 对象仅调用一次 decide，不能先传 unchecked')
  for (let batch of service.calls) {
    for (let key of batch) {
      require(Object.keys(key).sort().join(',') === 'bundleName,certSha256,sha256,versionCode',
        'QueryKey 只能包含四个上传字段')
    }
  }
  require(JSON.stringify(service.calls).indexOf('file://') < 0 &&
    service.cancellations.every((flag: CancelFlag): boolean => flag === cancel),
    '不能上传 uri，且每一批必须使用本次传入的 cancel')
  require(trust.length === 1 && trust[0].fingerprint === 'aabb', '判定不能删除或改写信任区')

  inputs = [input('com.black'), input('com.empty'), input('com.empty.file')]
  inputs[1].fingerprint.id = ''
  inputs[2].fingerprint.kind = 'file'
  service.calls = []
  resetCounters()
  result = await new AppJudge(service).judge(inputs, pack, [], cancel,
    (): boolean => false, (): void => {})
  require(result.complete && result.hits.length === 3 && service.calls.length === 0 &&
    counters().__centerDecideCalls === 0, '所有对象均 terminal 时不能发云请求或调用 decide')
}

async function checkCloudFailuresAndCancellation(): Promise<void> {
  let inputs = [input('com.example.app')]
  let cancel = new TestCancel()
  let service = new FakeCloud(async (): Promise<CloudView[]> => { throw new Error('offline') })
  let judge = new AppJudge(service)
  let result = await judge.judge(inputs, new RuleLoad(), [], cancel, (): boolean => false, (): void => {})
  require(result.complete && result.hits[0].verdict.cloud === 'offline' &&
    result.hits[0].verdict.reason === '未联网', '云抛错应收为行内 offline，仍完成本批对象')
  service.response = async (): Promise<CloudView[]> => []
  result = await judge.judge(inputs, new RuleLoad(), [], cancel, (): boolean => false, (): void => {})
  require(result.hits[0].verdict.reason === '未联网，云端结果无效', '错误条目数不能套错云下标')
  service.response = async (): Promise<CloudView[]> =>
    [{ state: 'unchecked', level: 'none', reason: '', evidence: '' }]
  resetCounters()
  result = await judge.judge(inputs, new RuleLoad(), [], cancel, (): boolean => false, (): void => {})
  require(result.hits[0].verdict.cloud === 'offline' && counters().__centerHilog?.length === 0,
    '注入端口返回 unchecked 时也不能把它传给 decide')

  inputs = []
  for (let i = 0; i < 101; i++) {
    inputs.push(input('com.example.item' + i))
  }
  service.calls = []
  service.response = async (keys: QueryKey[]): Promise<CloudView[]> => keys.map((): CloudView => cloud())
  let emitted = 0
  result = await judge.judge(inputs, new RuleLoad(), [], cancel, (): boolean => cancel.stopped, (): void => {
    emitted++
    if (emitted === 3) { cancel.stopped = true }
  })
  require(!result.complete && result.hits.length === 3 && service.calls.length === 1,
    '取消后不能开始后续云批次，已处理条数必须保留')
  service.calls = []
  result = await judge.judge(inputs, new RuleLoad(), [], cancel, (): boolean => true, (): void => {})
  require(result.hits.length === 0 && service.calls.length === 0, '开始前已取消不能查询云')
  cancel.stopped = false
  service.response = async (keys: QueryKey[]): Promise<CloudView[]> => {
    cancel.stopped = true
    return keys.map((): CloudView => cloud())
  }
  result = await judge.judge(inputs, new RuleLoad(), [], cancel, (): boolean => cancel.stopped, (): void => {})
  require(!result.complete && result.hits.length === 0, '云请求飞行期间取消不能继续处理对象')

  let pack = new RuleLoad()
  let black = new BundleRule()
  black.bundleName = 'com.known.risk'
  black.certAlgo = 'platform-fingerprint'
  black.certSha256 = 'aabb'
  black.level = 'risk'
  pack.bundles = [black]
  cancel.stopped = false
  let savedRisk = 0
  inputs = [input('com.pending.cloud'), input('com.known.risk')]
  result = await judge.judge(inputs, pack, [], cancel, (): boolean => cancel.stopped, (row: ScanHit): void => {
    if (row.verdict.level === 'risk') { savedRisk++ }
  })
  require(!result.complete && result.hits.length === 1 && result.hits[0].verdict.level === 'risk' && savedRisk === 1,
    '云飞行期间取消必须保留此前 terminal 已发现并通知写入的风险')

  inputs = [input('com.example.app')]
  inputs[0].granted = [BACKGROUND, CAMERA]
  service.response = async (): Promise<CloudView[]> => {
    inputs[0].fingerprint.bundleName = 'com.changed.during.query'
    inputs[0].granted = []
    return [cloud('ok')]
  }
  result = await judge.judge(inputs, rules(), [], cancel, (): boolean => false, (): void => {})
  require(result.hits[0].fingerprint.bundleName === 'com.example.app' &&
    result.hits[0].verdict.level === 'suspicious' && result.hits[0].granted.length === 2,
    '云请求期间不能把被改动的输入拼进已查询的快照')
}

function checkProtectedRows(): void {
  let variants: ScanHit[] = []
  let row = hit()
  row.verdict.level = 'risk'
  variants.push(row)
  let sources: VerdictSource[] = ['trust', 'local-black']
  for (let source of sources) {
    row = hit()
    row.verdict.source = source
    variants.push(row)
  }
  for (let evidence of ['official', 'impersonation', 'cert-uncompared', 'bundle-cert-mismatch', 'empty-fingerprint']) {
    row = hit()
    row.verdict.evidence = evidence
    variants.push(row)
  }
  for (let protectedRow of variants) {
    let report = exam([protectedRow])
    let old = protectedRow.verdict
    let countsBefore = [report.summary.riskApps, report.summary.suspiciousApps,
      report.summary.unknownApps, report.summary.okApps].join(',')
    rejudgeGranted(report, remove(), rules())
    require(protectedRow.verdict === old && protectedRow.granted.join(',') === BACKGROUND,
      'risk/trust/local-black/受保护 evidence 只能修改 granted')
    require([report.summary.riskApps, report.summary.suspiciousApps,
      report.summary.unknownApps, report.summary.okApps].join(',') === countsBefore,
      '受保护行不能改变等级计数')
    require(report.summary.anomalyApps === 0 && report.summary.sensitiveApps === 1,
      '受保护行仍按前后授权增减异常人数和敏感人数')
  }
  let file = hit()
  file.fingerprint.kind = 'file'
  let removed = hit()
  removed.action = 'uninstall'
  let report = scan([file, removed])
  let before = JSON.stringify(report)
  require(!rejudgeGranted(report, remove(), rules()) && JSON.stringify(report) === before,
    '文件和 action 不为 none 的行完全不改')
  report = scan([hit()])
  before = JSON.stringify(report)
  require(!rejudgeGranted(report, remove('com.absent'), rules()) && JSON.stringify(report) === before,
    '新授权里没有的包必须保持原样')
}

function checkStepEightAndSuspicious(): void {
  let levels: RiskLevel[] = ['suspicious', 'ok', 'unknown']
  for (let level of levels) {
    let row = hit('com.example.app', level, '原原因、云端暂无结果')
    let report = scan([row])
    let pack = rules()
    pack.officials = [official('com.example.apq', 'sha256-of-cert-bytes')]
    resetCounters()
    rejudgeGranted(report, replace(row.fingerprint.bundleName, [BACKGROUND, CAMERA]), pack)
    require(row.verdict.level === 'unknown' && row.verdict.evidence === 'cert-uncompared' &&
      row.verdict.reason === '证书无法比对、云端暂无结果' && report.unknown === 1 &&
      report.suspicious === 0 && report.ok === 0, '第 8 步必须先于仍命中的权限组合并正确移动计数')
    require(counters().__centerDecideCalls === 0 && counters().__centerAppsStatusCalls === 0,
      '撤权重判不能调用整张 decide，ScanReport 不能调用 examAppsStatus')
  }
  for (let level of levels) {
    let row = hit('com.example.app', level)
    row.verdict.source = level === 'ok' ? 'cloud' : 'local-rule'
    row.verdict.reason = level === 'ok' ? '其它云端短句' : '原原因、云端查询正常'
    let report = scan([row])
    rejudgeGranted(report, replace(row.fingerprint.bundleName, [BACKGROUND, CAMERA]), rules())
    require(row.verdict.level === 'suspicious' && row.verdict.evidence === 'heuristic' &&
      row.verdict.reason.endsWith('云端查询正常') && report.suspicious === 1 &&
      report.unknown === 0 && report.ok === 0, '仍命中启发式时应成为可疑并保留云端正常尾句')
  }
  let row = hit()
  let pack = rules()
  pack.officials = [official('com.example.apq')]
  let report = scan([row])
  rejudgeGranted(report, replace('com.example.app', [BACKGROUND, CAMERA]), pack)
  require(row.verdict.evidence === 'heuristic+lookalike', '同时命中两项时 evidence 必须合并')
  rejudgeGranted(report, remove('com.example.app', [BACKGROUND, CAMERA]), pack)
  require(row.verdict.level === 'suspicious' && row.verdict.evidence === 'lookalike' &&
    report.suspicious === 1, '撤权后相似包名仍命中时必须留在可疑')
  pack.heuristics[0].reason = '长'.repeat(reasonMax + 30)
  for (let tail of ['未联网', '未联网，云服务未配置', '未联网，云端结果无效', '云端查询正常']) {
    row = hit('com.example.app', 'suspicious', '旧结论、' + tail)
    row.verdict.cloud = tail === '云端查询正常' ? 'reached' : 'offline'
    report = scan([row])
    rejudgeGranted(report, replace('com.example.app', [BACKGROUND, CAMERA]), pack)
    require(row.verdict.reason.length <= reasonMax && row.verdict.reason.indexOf('com.example.apq') >= 0 &&
      row.verdict.reason.endsWith(tail) && row.verdict.evidence === 'heuristic+lookalike',
      '长启发式与相似包名混合时必须保留官方包名和完整云尾句')
  }
  let longName = 'com.' + 'a'.repeat(reasonMax + 20)
  row = hit(longName + 'b', 'suspicious', '旧结论、未联网')
  row.verdict.cloud = 'offline'
  pack.officials = [official(longName + 'c')]
  report = scan([row])
  rejudgeGranted(report, replace(row.fingerprint.bundleName, [BACKGROUND, CAMERA]), pack)
  require(row.verdict.reason.length <= reasonMax && row.verdict.reason.endsWith('未联网'),
    '相似说明自身很长时仍必须遵守 reasonMax 并保留云尾句')
}

function checkLeavingSuspicious(): void {
  let row = hit('com.example.app', 'suspicious', '已允许：后台定位和相机、云端查询正常')
  let pack = rules()
  pack.bundles = [nameRule('com.example.app')]
  let report = scan([row], false)
  report.judged = 99
  rejudgeGranted(report, remove(), pack)
  require(row.verdict.level === 'ok' && row.verdict.source === 'cloud' &&
    row.verdict.reason === '云端查询正常' && report.suspicious === 0 && report.ok === 1 &&
    report.unknown === 0 && !report.complete && report.judged === 99 && report.note === '已达本次扫描上限',
    '离开可疑必须先尝试证书可用的云端正常，并保留 complete/note/judged')
  row = hit()
  report = scan([row])
  rejudgeGranted(report, remove(), pack)
  require(row.verdict.evidence === 'match=name-only' && row.verdict.reason === '仅包名、云端暂无结果' &&
    report.unknown === 1 && report.suspicious === 0 && report.ok === 0,
    '没有云端正常时应优先落到仅包名未知')
  pack.bundles[0].reason = ''
  row = hit()
  report = scan([row])
  rejudgeGranted(report, remove(), pack)
  require(row.verdict.reason === '云端暂无结果', '空的仅包名原因不能另造本地短句')

  for (let failure of ['未联网', '未联网，云服务未配置', '未联网，云端结果无效']) {
    row = hit('com.example.app', 'suspicious', '旧可疑、' + failure)
    row.verdict.cloud = 'offline'
    report = scan([row])
    rejudgeGranted(report, remove(), rules())
    require(row.verdict.level === 'unknown' && row.verdict.source === 'local-rule' &&
      row.verdict.evidence === 'heuristic-cleared' && row.verdict.reason === '风险权限已关闭、' + failure &&
      report.unknown === 1 && report.ok === 0, '无其它命中时必须成为未知并保留云失败固定尾句')
    pack.bundles[0].reason = '长'.repeat(reasonMax + 30)
    row = hit('com.example.app', 'suspicious', failure)
    row.verdict.cloud = 'offline'
    report = scan([row])
    rejudgeGranted(report, remove(), pack)
    require(row.verdict.reason.length <= reasonMax && row.verdict.reason.endsWith(failure),
      'reasonMax 截断不能截掉云失败尾句')
  }
  for (let noCertificate of [true, false]) {
    row = hit('com.example.app', 'suspicious', '旧可疑、云端查询正常')
    if (noCertificate) { row.fingerprint.certSha256 = '' } else { row.fingerprint.certAlgo = 'none' }
    report = scan([row])
    rejudgeGranted(report, remove(), rules())
    require(row.verdict.level === 'unknown' && row.verdict.evidence === 'heuristic-cleared' && report.ok === 0,
      '证书为空或 certAlgo=none 时不能从可疑变成云端正常')
  }
  row = hit('com.example.app', 'suspicious', '旧可疑、云端暂无结果')
  report = scan([row])
  rejudgeGranted(report, remove(), rules())
  require(row.verdict.reason === '风险权限已关闭、云端暂无结果', '关闭权限后应保留已有云端暂无结果尾句')
  let again = decide(row.fingerprint, [], row.granted, true, rules(), [], cloud())
  require(again.level === 'unknown' && again.evidence !== 'heuristic-cleared',
    '下次完整扫描没有新命中时仍为未知，heuristic-cleared 只属于本次撤权')
  for (let level of ['unknown', 'ok'] as RiskLevel[]) {
    row = hit('com.example.app', level, '原结论')
    row.granted = []
    report = scan([row])
    let previous = row.verdict
    rejudgeGranted(report, remove(), rules())
    require(row.verdict === previous && report.ok === (level === 'ok' ? 1 : 0) &&
      report.unknown === (level === 'unknown' ? 1 : 0), '原来不是可疑且两项都不命中时不能改结论和计数')
  }
}

function checkExamFinishing(): void {
  let first = hit('com.one')
  let second = hit('com.two')
  let localOk = hit('com.local', 'ok', '已加入信任、未联网')
  localOk.verdict.source = 'trust'
  localOk.verdict.cloud = 'offline'
  let officialOk = hit('com.official', 'ok', '签名与官方记录一致、云端暂无结果')
  officialOk.verdict.evidence = 'official'
  let report = exam([first, second, localOk, officialOk], false)
  let changes: GrantChange[] = report.apps.map((row: ScanHit): GrantChange =>
    ({ bundleName: row.fingerprint.bundleName, mode: 'replace', permissions: [] }))
  report.summary.okApps = 2001
  report.items[2].status = 'unsupported'
  resetCounters()
  rejudgeGranted(report, changes, rules())
  require(report.summary.suspiciousApps === 0 && report.summary.unknownApps === 2 &&
    report.summary.okApps === 2001 && !report.appsComplete && report.summary.anomalyApps === 0 &&
    report.summary.sensitiveApps === 0, '多行重判应按前后增减，并保持截断前计数和原 appsComplete')
  require(report.items[0].status === 'unknown' && report.items[0].detail ===
    '本次扫描未完成、未联网、云端暂无结果、部分应用暂无法确认', '体检详情必须一次收尾并按固定顺序追加四句')
  require(report.items[1].status === 'ok' && report.items[2].status === 'unsupported' &&
    report.advice === 1 && report.state === 'incomplete', '可疑建议、授权不可用项、advice 和圆环应正确收尾')
  require(counters().__centerAppsStatusCalls === 1 && counters().__centerAppendCalls === 1 &&
    counters().__centerStateCalls === 1, '同一份多行体检必须先改完所有行再调用各收尾函数一次')
  require(counters().__centerDecideCalls === 0, '体检撤权不能调用整张 decide')

  report = exam([hit()])
  report.items = [report.items[0]]
  report.summary.suspiciousApps = 0
  rejudgeGranted(report, remove(), rules())
  require(report.items.length === 1 && report.summary.suspiciousApps === 0 && report.appsComplete &&
    report.state === 'incomplete' && report.items[0].detail === '部分应用暂无法确认',
    '不补可疑建议项，不把计数减成负数，原 appsComplete=true 必须保持')
  report = exam([hit()])
  report.items[0].status = 'unsupported'
  report.items[0].countsTowardState = false
  report.items[0].detail = '无法获取应用列表'
  rejudgeGranted(report, remove(), rules())
  require(report.items[0].status === 'unsupported' && report.items[0].detail === '无法获取应用列表',
    '已经不可用的应用信誉项不得被新授权改写成可用')
  let self = hit('com.jinyinhu.securitycenter')
  report = exam([self])
  rejudgeGranted(report, remove(self.fingerprint.bundleName, [BACKGROUND, CAMERA]), rules())
  require(report.summary.anomalyApps === 0 && report.summary.sensitiveApps === 0,
    '本应用不参与异常人数和敏感人数增减')
  let newlyGranted = hit('com.new.grants', 'unknown', '暂无匹配结果')
  newlyGranted.granted = []
  report = exam([newlyGranted])
  report.summary.unknownApps = 5000
  rejudgeGranted(report, replace(newlyGranted.fingerprint.bundleName, [BACKGROUND, CAMERA]), rules())
  require(report.summary.suspiciousApps === 1 && report.summary.unknownApps === 4999 &&
    report.summary.anomalyApps === 1 && report.summary.sensitiveApps === 1,
    '设置里新增权限时应增加异常和敏感人数，并在原截断前计数上移动等级')
  rejudgeGranted(report, replace(newlyGranted.fingerprint.bundleName, ['ohos.permission.READ_MEDIA']), rules())
  require(report.summary.anomalyApps === 0 && report.summary.sensitiveApps === 1,
    '单独 READ_MEDIA 仍属于敏感权限，但不能产生权限异常')
  rejudgeGranted(report, replace(newlyGranted.fingerprint.bundleName, []), rules())
  require(report.summary.sensitiveApps === 0, '最后一项已授予敏感权限关闭后人数应减少')
  for (let risky of [true, false]) {
    let partial = hit('com.example.app', risky ? 'risk' : 'suspicious')
    report = exam([partial], false)
    report.items = [item('exam.protect.pure-mode')]
    report.state = risky ? 'risk' : 'incomplete'
    report.summary.riskApps = 0
    rejudgeGranted(report, remove(), rules())
    require(report.state === (risky ? 'risk' : 'incomplete') && report.items.length === 1 &&
      report.summary.riskApps === 0 && !report.appsComplete,
      '缺应用项的半成品体检必须保留实际风险或未完成，不补通过项，也不改 riskApps/appsComplete')
  }
}

function fact(name: string, permission: string, grant: 'granted' | 'denied' | 'unknown'): PermissionFact {
  return { bundleName: name, displayName: '', permission: permission, label: '', group: '',
    sensitive: isSensitive(permission), declared: true, grant: grant, fixed: false,
    tokenId: 1, source: 'unknown' }
}

function record(id: string, seq: number, kind: 'exam' | 'malware',
  state: 'queued' | 'running' | 'done' | 'interrupted' | 'cancelled' | 'failed'): JobRecord {
  return { jobId: id, seq: seq, kind: kind, lane: 'heavy', startedAt: '', finishedAt: '',
    state: state, itemCount: 0, riskCount: 0, summary: '', resultFile: 'center/jobs/' + id + '.json' }
}

class MemoryResults implements GrantedResultStore {
  examRows: HomeCandidate[] = []
  scanRows: ScanCandidate[] = []
  saved: string[] = []
  inside: boolean = false
  transactions: number = 0

  exclusive(work: () => void): void {
    this.transactions++
    this.inside = true
    try { work() } finally { this.inside = false }
  }

  exams(): HomeCandidate[] {
    require(this.inside, '候选体检必须在 Writer 独占队列中读取')
    return this.examRows
  }

  scans(): ScanCandidate[] {
    require(this.inside, '候选信誉必须在 Writer 独占队列中读取')
    return this.scanRows
  }

  saveExam(job: JobRecord, report: ExamReport): void {
    require(this.inside && job.jobId === report.jobId, '体检读改写必须在同一次独占队列中')
    this.saved.push(job.jobId)
  }

  saveScan(job: JobRecord, report: ScanReport): void {
    require(this.inside && report.hits.length > 0, '信誉写回必须在独占队列中')
    this.saved.push(job.jobId)
  }
}

function checkWritebackTargets(): void {
  let store = new MemoryResults()
  for (let entry of [['view', '1', 'done'], ['done', '5', 'done'],
    ['home', '7', 'interrupted'], ['running', '9', 'running'], ['unrelated', '3', 'done']]) {
    let job = record(entry[0], Number(entry[1]), 'exam', entry[2] as 'done' | 'interrupted' | 'running')
    let body = exam([hit()])
    body.jobId = job.jobId
    if (job.jobId === 'home') { body.state = 'risk' }
    store.examRows.push({ record: job, report: body })
  }
  for (let entry of [['scan-view', '1', 'cancelled'], ['scan-done', '5', 'done'],
    ['scan-running', '9', 'running'], ['scan-failed', '8', 'failed'], ['scan-old', '3', 'done']]) {
    store.scanRows.push({ record: record(entry[0], Number(entry[1]), 'malware',
      entry[2] as 'done' | 'cancelled' | 'running' | 'failed'), report: scan([hit()]) })
  }
  let records = JSON.stringify(store.examRows.map((row: HomeCandidate): JobRecord => row.record)) +
    JSON.stringify(store.scanRows.map((row: ScanCandidate): JobRecord => row.record))
  rejudgeGrantedResults(store, 'scan-view', 'anomaly:view', remove(), rules())
  require(store.saved.sort().join(',') === 'done,home,scan-done,scan-view,view' && store.transactions === 1,
    '必须回写查看体检、最近 done、settledHome、查看已收口信誉和最近 done 信誉')
  require(records === JSON.stringify(store.examRows.map((row: HomeCandidate): JobRecord => row.record)) +
    JSON.stringify(store.scanRows.map((row: ScanCandidate): JobRecord => row.record)),
    '授权写回不能新增或改变 JobRecord，也不能改中断作业状态')
  require(store.examRows[3].report?.apps[0].granted.length === 2 &&
    store.scanRows[2].report?.hits[0].granted.length === 2, '不能修改 queued/running 的结果')
  require(store.examRows[4].report?.apps[0].granted.length === 2 &&
    store.scanRows[4].report?.hits[0].granted.length === 2, '不能修改选中目标以外的旧结果')

  let facts = [fact('com.example.app', CAMERA, 'denied'), fact('com.other', CONTACTS, 'granted'),
    fact('com.other', CONTACTS, 'granted')]
  let changes = grantChangesFromFacts(facts)
  require(changes.length === 2 && changes[0].permissions.length === 0 &&
    changes[1].permissions.join(',') === CONTACTS, '刷新应包含拒绝包且只收集已授予、去重的权限名')
  let present = hit()
  let absent = hit('com.not.in.new.facts')
  let report = scan([present, absent])
  rejudgeGranted(report, changes, rules())
  require(present.granted.length === 0 && absent.granted.length === 2,
    '设置返回后新结果里没有的包不能改 granted')
  let older = hit()
  older.granted.push(CONTACTS)
  report = scan([older])
  rejudgeGranted(report, remove(), rules())
  require(older.granted.indexOf(CONTACTS) >= 0 && older.granted.indexOf(BACKGROUND) >= 0,
    '撤销一项权限只能从各份快照去掉该项，不能覆盖其它历史授权')
  let sequential: GrantChange[] = [
    { bundleName: 'com.example.app', mode: 'replace', permissions: [BACKGROUND, CAMERA, CONTACTS] },
    { bundleName: 'com.example.app', mode: 'remove', permissions: [CAMERA] },
    { bundleName: 'com.example.app', mode: 'remove', permissions: [CONTACTS] }
  ]
  rejudgeGranted(report, sequential, rules())
  require(older.granted.join(',') === BACKGROUND, '同包的多条修改必须保持输入顺序')
}

export async function runAppJudgeChecks(): Promise<void> {
  await checkBatches()
  await checkCloudFailuresAndCancellation()
  checkProtectedRows()
  checkStepEightAndSuspicious()
  checkLeavingSuspicious()
  checkExamFinishing()
  checkWritebackTargets()
}
