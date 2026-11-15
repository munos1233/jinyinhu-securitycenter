import type {
  ActionRef,
  CheckGroup,
  CheckItem,
  CheckKind,
  CheckStatus,
  ExamReport,
  ExamState,
  ExamSummary,
  JobKind,
  JobProgress,
  JobRecord,
  JobState,
  Lane,
  ScanHit
} from '../main/ets/center/CenterTypes'
import type { HomeCandidate } from '../main/ets/feature/exam/ExamState'
import {
  examNotes,
  examReportOf,
  examRequest,
  formatBytes,
  homeLook,
  protectLine,
  ringText,
  summaryLines
} from '../main/ets/pages/HomeView'
import { examGroups, examLook, examSection, itemTarget } from '../main/ets/pages/ExamView'
import { PAGE_ROUTES, PENDING_ROUTES, routeParams, routeTitle } from '../main/ets/pages/Index'

const BANNED: string[] = ['已安全', '暂无风险', '有风险', '未完成']

class Item implements CheckItem {
  id: string = ''
  title: string = ''
  group: CheckGroup = 'protect'
  status: CheckStatus = 'ok'
  kind: CheckKind = 'state'
  source: 'system' | 'local-rule' | 'cloud' | 'probe' | 'trust' | 'local-black' = 'system'
  detail: string = ''
  action: ActionRef = { route: '', params: '' }
  countsTowardState: boolean = false
}

class RecordRow implements JobRecord {
  jobId: string = ''
  seq: number = 0
  kind: JobKind = 'exam'
  lane: Lane = 'heavy'
  startedAt: string = ''
  finishedAt: string = ''
  state: JobState = 'done'
  itemCount: number = 0
  riskCount: number = 0
  summary: string = ''
  resultFile: string = ''
}

class Summary implements ExamSummary {
  riskApps: number = 0
  suspiciousApps: number = 0
  unknownApps: number = 0
  okApps: number = 0
  parts = []
  cleanableBytes: number = 0
  cleanableKnown: boolean = false
  cleanableNote: string = ''
  sensitiveApps: number = 0
  sensitiveKnown: boolean = false
  anomalyApps: number = 0
}

class Report implements ExamReport {
  jobId: string = ''
  state: ExamState = 'clear'
  items: CheckItem[] = []
  apps: ScanHit[] = []
  appsComplete: boolean = true
  summary: ExamSummary = new Summary()
  skipped: number = 0
  advice: number = 0
  generatedAt: string = ''
}

class Progress implements JobProgress {
  jobId: string = ''
  kind: JobKind = 'exam'
  lane: Lane = 'heavy'
  state: JobState = 'done'
  done: number = 0
  total: number = 0
  message: string = ''
}

function fail(message: string): void {
  throw new Error(message)
}

function item(id: string, group: CheckGroup, kind: CheckKind, status: CheckStatus, detail: string = ''): CheckItem {
  let value = new Item()
  value.id = id
  value.group = group
  value.kind = kind
  value.status = status
  value.detail = detail
  return value
}

function report(jobId: string, state: ExamState): Report {
  let value = new Report()
  value.jobId = jobId
  value.state = state
  return value
}

function row(jobId: string, seq: number, state: JobState, value: ExamReport | null, kind: JobKind = 'exam'): HomeCandidate {
  let record = new RecordRow()
  record.jobId = jobId
  record.seq = seq
  record.state = state
  record.kind = kind
  return { record: record, report: value }
}

function idle(): Progress {
  return new Progress()
}

function progress(jobId: string, kind: JobKind, state: JobState, message: string): Progress {
  let value = new Progress()
  value.jobId = jobId
  value.kind = kind
  value.state = state
  value.message = message
  value.done = 1
  value.total = 4
  return value
}

function protectItems(): CheckItem[] {
  return [
    item('exam.protect.pure-mode', 'protect', 'state', 'ok'),
    item('exam.protect.lockdown', 'protect', 'state', 'risk'),
    item('exam.protect.el5', 'protect', 'state', 'unsupported')
  ]
}

function lookText(look: { headline: string, notes: string[], numbers: string[] }): string {
  return [look.headline].concat(look.notes).concat(look.numbers).join('|')
}

function checkFreshHome(): void {
  let look = homeLook([], idle())
  if (look.headline !== '尚未体检' || look.notes.length !== 0 || look.numbers.length !== 0 ||
    look.protect !== '尚未检测' || look.running) {
    fail('打开应用没有体检时只写「尚未体检」，第五行是「尚未检测」，没有三句数字')
  }
  if (lookText(look).indexOf('暂无风险') >= 0 || lookText(look).indexOf('已安全') >= 0) {
    fail('没有体检时不得出现「暂无风险」或「已安全」')
  }
  if (ringText('not-run') !== '尚未体检' || ringText('clear') !== '暂无风险' || ringText('risk') !== '有风险' ||
    ringText('incomplete') !== '未完成') {
    fail('圆环只有四句')
  }
  let unparsed = homeLook([row('job-1-aaaaaaaa', 1, 'done', null)], idle())
  if (unparsed.headline !== '尚未体检' || unparsed.numbers.length !== 0) {
    fail('结果文件解析不成 ExamReport 时首页不采用它')
  }
}

function checkRunningExam(): void {
  let clear = report('job-1-aaaaaaaa', 'clear')
  clear.summary.riskApps = 2
  clear.summary.cleanableKnown = true
  clear.summary.cleanableBytes = 4096
  clear.summary.sensitiveKnown = true
  clear.summary.sensitiveApps = 5
  clear.items = protectItems()
  let done = row('job-1-aaaaaaaa', 1, 'done', clear)
  let running = row('job-2-bbbbbbbb', 2, 'running', null)
  let look = homeLook([done, running], progress('job-2-bbbbbbbb', 'exam', 'running', '正在扫描应用'))
  if (!look.running || look.headline !== '正在扫描应用' || look.openId !== 'job-2-bbbbbbbb') {
    fail('体检运行时状态句只用这条作业的 message')
  }
  if (look.notes.length !== 0 || look.numbers.length !== 0) {
    fail('体检运行时不显示上一份的附加句和三句数字')
  }
  for (let i = 0; i < BANNED.length; i++) {
    if (lookText(look).indexOf(BANNED[i]) >= 0) {
      fail('体检运行时出现了「' + BANNED[i] + '」')
    }
  }
  let queued = homeLook([done, row('job-2-bbbbbbbb', 2, 'queued', null)], idle())
  if (!queued.running || queued.headline !== '' || queued.numbers.length !== 0) {
    fail('索引里体检 queued、还没有进度时，状态句只用这条作业的 message，不补别的句子')
  }
  let published = homeLook([done], progress('job-2-bbbbbbbb', 'exam', 'queued', '正在检查系统安全'))
  if (!published.running || published.headline !== '正在检查系统安全') {
    fail('进度已发布、索引还没读到时仍按运行中显示')
  }
  let other = homeLook([done], progress('job-3-cccccccc', 'malware', 'running', '正在扫描'))
  if (other.running || other.headline !== '暂无风险' || other.busy !== '正在扫描' || other.numbers.length !== 3) {
    fail('其它重作业进行时仍显示 homeExam() 的圆环，进度句另外显示')
  }
  let after = homeLook([done, row('job-2-bbbbbbbb', 2, 'done', report('job-2-bbbbbbbb', 'risk'))],
    progress('job-2-bbbbbbbb', 'exam', 'done', '已完成'))
  if (after.running || after.headline !== '有风险' || after.openId !== 'job-2-bbbbbbbb') {
    fail('这次变成 done 之后才改读新结果')
  }
}

function checkBanner(): void {
  let clear = report('job-1-aaaaaaaa', 'clear')
  let only = homeLook([row('job-1-aaaaaaaa', 1, 'done', clear)], idle())
  if (only.notes.indexOf('本次体检未完成') >= 0 || only.notes.indexOf('上次体检未完成') >= 0) {
    fail('banner 为空串时不写「体检未完成」')
  }
  if (only.notes[0] !== '本次只检查了已安装应用') {
    fail('clear 的圆环下方先写「本次只检查了已安装应用」')
  }
  let riskStop = homeLook([row('job-1-aaaaaaaa', 1, 'done', clear),
    row('job-2-bbbbbbbb', 2, 'interrupted', report('job-2-bbbbbbbb', 'risk'))], idle())
  if (riskStop.headline !== '有风险' || riskStop.notes[0] !== '本次体检未完成') {
    fail('中断的有风险体检被采用时圆环下写「本次体检未完成」')
  }
  let softStop = homeLook([row('job-1-aaaaaaaa', 1, 'done', clear),
    row('job-2-bbbbbbbb', 2, 'cancelled', report('job-2-bbbbbbbb', 'incomplete'))], idle())
  if (softStop.headline !== '暂无风险' || softStop.notes[0] !== '上次体检未完成') {
    fail('最近一份不是 done 且不是风险时仍用上一份 done，并写「上次体检未完成」')
  }
}

function checkNotes(): void {
  let clear = report('job-1-aaaaaaaa', 'clear')
  clear.skipped = 2
  clear.advice = 1
  clear.summary.suspiciousApps = 3
  clear.items = [item('exam.malware.apps', 'threat', 'state', 'ok', '未联网、云端暂无结果')]
  let notes = examNotes(clear)
  let want = ['本次只检查了已安装应用', '另有 2 项暂无法检查', '有 1 条建议', '发现 3 个可疑应用',
    '部分应用未联网，结果来自本地', '部分应用云端暂无结果']
  if (notes.join('|') !== want.join('|')) {
    fail('第 8 节附加句不对：' + notes.join('|'))
  }
  let unknown = report('job-1-aaaaaaaa', 'incomplete')
  unknown.items = [item('exam.malware.apps', 'threat', 'state', 'unknown', '未联网、部分应用暂无法确认')]
  let partial = examNotes(unknown)
  if (partial.join('|') !== '部分应用暂无法确认') {
    fail('该项不是 ok 时不重复「未联网」；detail 含「部分应用暂无法确认」时写这一句')
  }
  let notOk = report('job-1-aaaaaaaa', 'clear')
  notOk.items = [item('exam.malware.apps', 'threat', 'state', 'unknown', '未联网、云端暂无结果')]
  let notOkNotes = examNotes(notOk).join('|')
  if (notOkNotes.indexOf('部分应用未联网') >= 0 || notOkNotes.indexOf('部分应用云端暂无结果') >= 0) {
    fail('应用信誉项不是 ok 时圆环下方不重复「未联网」和「云端暂无结果」')
  }
  let plain = report('job-1-aaaaaaaa', 'incomplete')
  plain.items = [item('exam.malware.apps', 'threat', 'state', 'unknown', '本次扫描未完成')]
  if (examNotes(plain).length !== 0) {
    fail('detail 不含「部分应用暂无法确认」时不写这一句')
  }
}

function checkNumbers(): void {
  let summary = new Summary()
  summary.riskApps = 4
  summary.anomalyApps = 7
  let lines = summaryLines(summary)
  if (lines.length !== 1 || lines[0] !== '风险应用 4 个') {
    fail('cleanableKnown、sensitiveKnown 为 false 时那两句不出现，也不显示 0')
  }
  summary.cleanableKnown = true
  summary.cleanableBytes = 1536
  summary.cleanableNote = '仅统计了本应用缓存'
  summary.sensitiveKnown = true
  summary.sensitiveApps = 0
  lines = summaryLines(summary)
  if (lines[1] !== '可清理 1.5 KB，仅统计了本应用缓存') {
    fail('cleanableNote 接在可清理字节后面：' + lines[1])
  }
  if (lines[2] !== '0 个应用持有敏感权限') {
    fail('sensitiveKnown 为 true 时人数为 0 也显示')
  }
  summary.sensitiveApps = 3
  summary.cleanableNote = ''
  lines = summaryLines(summary)
  if (lines[1] !== '可清理 1.5 KB' || lines[2] !== '3 个应用持有敏感权限' || lines.join('|').indexOf('7') >= 0) {
    fail('敏感人数取 sensitiveApps，禁止填 anomalyApps')
  }
  if (formatBytes(0) !== '0 B' || formatBytes(1048576) !== '1 MB') {
    fail('字节格式不对')
  }
  let adopted = report('job-1-aaaaaaaa', 'risk')
  adopted.summary.riskApps = 6
  let look = homeLook([row('job-1-aaaaaaaa', 1, 'done', adopted)], idle())
  if (look.numbers[0] !== '风险应用 6 个') {
    fail('首页风险应用个数与 summary.riskApps 一致')
  }
}

function checkProtectRow(): void {
  if (protectLine([]) !== '尚未检测') {
    fail('这份体检没有防护项时第五行是「尚未检测」')
  }
  if (protectLine(protectItems()) !== '正常 1 · 有风险 1 · 暂不支持 1') {
    fail('第五行只读纯净模式、lockdown、el5')
  }
  let exam = report('job-1-aaaaaaaa', 'risk')
  exam.items = protectItems()
  let rows = [row('job-1-aaaaaaaa', 1, 'done', exam), row('job-2-bbbbbbbb', 2, 'done', null, 'protect')]
  if (homeLook(rows, idle()).protect !== '正常 1 · 有风险 1 · 暂不支持 1') {
    fail('之后单独跑完的防护作业不改首页')
  }
}

function checkParse(): void {
  if (examReportOf(null) !== null || examReportOf('{') !== null || examReportOf('{"state":"safe"}') !== null ||
    examReportOf('{"state":"clear","items":[],"apps":[]}') !== null) {
    fail('解析不成 ExamReport 的结果不采用')
  }
  let parsed = examReportOf('{"state":"clear","items":[],"apps":[],"summary":{"riskApps":1}}')
  if (parsed === null || parsed.summary.cleanableKnown !== false || parsed.summary.sensitiveKnown !== false) {
    fail('缺少的标志按 false 读')
  }
  let request = examRequest()
  if (request.kind !== 'exam' || request.scope !== 'quick' || request.uris.length !== 0 || request.focus !== '') {
    fail('开始体检只入队 exam')
  }
}

function checkSections(): void {
  let cases: [CheckKind, CheckStatus, string][] = [
    ['state', 'risk', 'pending'], ['state', 'unknown', 'pending'],
    ['advice', 'attention', 'advice'], ['advice', 'unknown', 'advice'],
    ['state', 'ok', 'normal'], ['advice', 'ok', 'normal'],
    ['state', 'unverified', 'unsupported'], ['state', 'unsupported', 'unsupported'],
    ['advice', 'unsupported', 'unsupported']
  ]
  for (let i = 0; i < cases.length; i++) {
    let got = examSection(item('x', 'threat', cases[i][0], cases[i][1]))
    if (got !== cases[i][2]) {
      fail('分截不对：' + cases[i][0] + '/' + cases[i][1] + ' → ' + got)
    }
  }
  let items = [
    item('exam.rules.version', 'rules', 'advice', 'ok'),
    item('exam.malware.suspicious', 'threat', 'advice', 'attention'),
    item('exam.protect.el5', 'protect', 'state', 'unsupported'),
    item('exam.malware.apps', 'threat', 'state', 'risk'),
    item('exam.protect.pure-mode', 'protect', 'state', 'ok')
  ]
  let groups = examGroups(items)
  let shape = groups.map((g) => g.title + ':' + g.sections.map((s) => s.title + '=' +
    s.items.map((x) => x.id).join(',')).join(';')).join(' / ')
  let want = '应用信誉:待处理=exam.malware.apps;建议=exam.malware.suspicious / ' +
    '系统防护:正常=exam.protect.pure-mode;暂不支持=exam.protect.el5 / 规则:正常=exam.rules.version'
  if (shape !== want) {
    fail('按组渲染、组内四截：' + shape)
  }
}

function checkTargets(): void {
  let apps = item('exam.malware.apps', 'threat', 'state', 'risk')
  apps.action = { route: 'malware', params: 'malware' }
  let target = itemTarget(apps, 'job-4-dddddddd')
  if (target.route !== 'malware' || target.params !== 'job-4-dddddddd') {
    fail('从体检进入信誉页时 params 是那次 jobId，不是路由名')
  }
  let anomaly = item('exam.permission.anomaly', 'permission', 'advice', 'attention')
  anomaly.action = { route: 'permission', params: 'anomaly:job-4-dddddddd' }
  if (itemTarget(anomaly, 'job-4-dddddddd').params !== 'anomaly:job-4-dddddddd') {
    fail('其它动作原样传 params')
  }
}

function checkExamLook(): void {
  if (examLook('', null, null, idle()).headline !== '尚未体检') {
    fail('没有 jobId 时是「尚未体检」')
  }
  let record = new RecordRow()
  record.jobId = 'job-5-eeeeeeee'
  record.state = 'running'
  let running = examLook('job-5-eeeeeeee', record, null,
    progress('job-5-eeeeeeee', 'exam', 'running', '正在计算可清理空间'))
  if (!running.running || running.headline !== '正在计算可清理空间' || running.groups.length !== 0) {
    fail('体检页在体检运行时只显示 message')
  }
  record.state = 'done'
  if (examLook('job-5-eeeeeeee', record, null, idle()).headline !== '无法读取该结果') {
    fail('结果文件解析失败时写「无法读取该结果」，不显示成空的通过')
  }
  record.state = 'interrupted'
  let stopped = report('job-5-eeeeeeee', 'risk')
  stopped.items = [item('exam.malware.apps', 'threat', 'state', 'risk')]
  let look = examLook('job-5-eeeeeeee', record, stopped, idle())
  if (look.headline !== '有风险' || look.notes[0] !== '本次体检未完成' || look.groups.length !== 1) {
    fail('中断的体检先写「本次体检未完成」，再按组列出')
  }
}

function checkRoutes(): void {
  let wantPages = ['home', 'exam', 'malware', 'clean', 'permission', 'apps', 'protect', 'quarantine', 'job', 'P1', 'P2', 'P3', 'ledger', 'report',
    'archive', 'device', 'about']
  let wantPending: string[] = []
  if (PAGE_ROUTES.slice().sort().join(',') !== wantPages.slice().sort().join(',') ||
    PENDING_ROUTES.slice().sort().join(',') !== wantPending.slice().sort().join(',')) {
    fail('路由登记不对')
  }
  if (routeParams('job-4-dddddddd') !== 'job-4-dddddddd' || routeParams('') !== '' ||
    routeParams(undefined) !== '' || routeParams(null) !== '' || routeParams({}) !== '') {
    fail('params 是独立字符串，没有则为空串')
  }
  if (routeTitle('malware') !== '应用信誉' || routeTitle('exam') !== '体检') {
    fail('信誉页标题是「应用信誉」')
  }
}

export function runHomeRouteChecks(): void {
  checkFreshHome()
  checkRunningExam()
  checkBanner()
  checkNotes()
  checkNumbers()
  checkProtectRow()
  checkParse()
  checkSections()
  checkTargets()
  checkExamLook()
  checkRoutes()
}
