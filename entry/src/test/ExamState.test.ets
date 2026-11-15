import { lockdownOk, pureModeOk } from '../main/ets/center/PostureRule'
import type {
  ActionRef,
  CheckItem,
  CheckKind,
  CheckStatus,
  ExamReport,
  ExamState,
  ExamSummary,
  Fingerprint,
  JobRecord,
  JobState,
  ScanHit,
  Verdict
} from '../main/ets/center/CenterTypes'
import type { HomeCandidate } from '../main/ets/feature/exam/ExamState'
import {
  appendExamAppsDetail,
  examAnyOffline,
  examAppsStatus,
  examWritebackTargets,
  homeExam,
  settledHome,
  settleStoppedExam,
  stateOf
} from '../main/ets/feature/exam/ExamState'

class Item implements CheckItem {
  id: string = ''
  title: string = ''
  group: 'threat' | 'clean' | 'permission' | 'protect' | 'rules' = 'protect'
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
  kind: 'exam' | 'malware' | 'clean' | 'duplicate' | 'large-file' | 'permission' | 'apps' | 'protect' = 'exam'
  lane: 'light' | 'heavy' = 'heavy'
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

class Finger implements Fingerprint {
  kind: 'bundle' | 'file' = 'bundle'
  id: string = ''
  bundleName: string = ''
  version: string = ''
  versionCode: number = 0
  certSha256: string = ''
  certAlgo: 'none' | 'platform-fingerprint' | 'sha256-of-cert-bytes' = 'none'
  sha256: string = ''
  size: number = 0
  label: string = ''
}

class VerdictValue implements Verdict {
  level: 'ok' | 'unknown' | 'suspicious' | 'risk' = 'ok'
  source: 'local-rule' | 'cloud' | 'system' | 'trust' | 'local-black' | 'probe' = 'local-rule'
  reason: string = ''
  evidence: string = ''
  cloud: 'unchecked' | 'offline' | 'reached' = 'unchecked'
}

class Hit implements ScanHit {
  fingerprint: Fingerprint = new Finger()
  displayName: string = ''
  verdict: Verdict = new VerdictValue()
  quarantined: boolean = false
  action: 'none' | 'quarantine' | 'uninstall' | 'cleared' | 'revoked' = 'none'
  granted: string[] = []
}

function fail(message: string): void {
  throw new Error(message)
}

function item(id: string, status: CheckStatus, toward: boolean, kind: CheckKind): CheckItem {
  let value = new Item()
  value.id = id
  value.status = status
  value.countsTowardState = toward
  value.kind = kind
  return value
}

function candidate(jobId: string, seq: number, state: JobState, exam: ExamState | null,
  finishedAt: string): HomeCandidate {
  let record = new RecordRow()
  record.jobId = jobId
  record.seq = seq
  record.state = state
  record.finishedAt = finishedAt
  let row: HomeCandidate = { record: record, report: null }
  if (exam !== null) {
    let report = new Report()
    report.jobId = jobId
    report.state = exam
    row.report = report
  }
  return row
}

function hit(action: 'none' | 'quarantine', level: 'ok' | 'suspicious', reason: string,
  evidence: string): ScanHit {
  let value = new Hit()
  value.action = action
  let verdict = new VerdictValue()
  verdict.level = level
  verdict.reason = reason
  verdict.evidence = evidence
  value.verdict = verdict
  return value
}

function row(level: 'ok' | 'unknown' | 'suspicious' | 'risk', action: 'none' | 'quarantine'): ScanHit {
  let value = new Hit()
  value.action = action
  let verdict = new VerdictValue()
  verdict.level = level
  value.verdict = verdict
  return value
}

function offlineRow(level: 'ok' | 'suspicious', source: 'local-rule' | 'cloud'): ScanHit {
  let value = row(level, 'none')
  value.verdict.source = source
  value.verdict.cloud = 'offline'
  return value
}

function appsItem(status: CheckStatus, detail: string): CheckItem {
  let value = item('exam.malware.apps', status, status !== 'unsupported', 'state')
  value.group = 'threat'
  value.detail = detail
  return value
}

function stopped(items: CheckItem[], apps: ScanHit[], appsComplete: boolean): Report {
  let report = new Report()
  report.jobId = 'job-9-00000000'
  report.state = 'clear'
  report.items = items
  report.apps = apps
  report.appsComplete = appsComplete
  return report
}

function findIn(report: ExamReport, id: string): CheckItem | null {
  for (let i = 0; i < report.items.length; i++) {
    if (report.items[i].id === id) {
      return report.items[i]
    }
  }
  return null
}

function settleChecks(): void {
  let pure = item('exam.protect.pure-mode', 'ok', true, 'state')
  let hidden = stopped([pure, appsItem('ok', '')], [row('risk', 'none'), row('ok', 'none')], false)
  settleStoppedExam(hidden, 'job-9-00000000')
  let hiddenApps = findIn(hidden, 'exam.malware.apps')
  if (hidden.summary.riskApps !== 1 || hidden.state !== 'risk' || hiddenApps === null ||
    hiddenApps.status !== 'risk') {
    fail('riskApps 为 0 而 apps[] 有 action===none 的 risk 时，收口后应是 risk，riskApps 等于行数')
  }
  if (hidden.appsComplete || hiddenApps.detail.indexOf('本次扫描未完成') < 0) {
    fail('appsComplete 为 false 时应保持 false，详情含本次扫描未完成')
  }

  let quarantined = stopped([item('exam.protect.pure-mode', 'ok', true, 'state'), appsItem('ok', '')],
    [row('risk', 'quarantine')], true)
  settleStoppedExam(quarantined, 'job-9-00000000')
  if (quarantined.summary.riskApps !== 0 || quarantined.state !== 'clear') {
    fail('已处理的 risk 行不应计入 riskApps 或把 state 改成 risk')
  }

  let truncated = stopped([item('exam.protect.pure-mode', 'ok', true, 'state'), appsItem('ok', '')],
    [row('ok', 'none'), row('ok', 'none')], true)
  truncated.summary.okApps = 120
  truncated.summary.riskApps = 3
  truncated.summary.unknownApps = 4
  settleStoppedExam(truncated, 'job-9-00000000')
  if (truncated.summary.okApps !== 120 || truncated.summary.riskApps !== 3 || truncated.summary.unknownApps !== 4) {
    fail('settleStoppedExam 把计数改小了')
  }
  if (truncated.state !== 'risk') {
    fail('summary.riskApps 已大于 0 时应用信誉项应是 risk')
  }

  let mixed = stopped([item('exam.protect.pure-mode', 'ok', true, 'state'), appsItem('ok', '')],
    [row('risk', 'none'), row('ok', 'none')], true)
  mixed.summary.okApps = 120
  mixed.summary.unknownApps = 4
  settleStoppedExam(mixed, 'job-9-00000000')
  if (mixed.summary.riskApps !== 1 || mixed.summary.okApps !== 120 || mixed.summary.unknownApps !== 4) {
    fail('抬高 riskApps 时不得顺带把 okApps 或 unknownApps 改成 apps[] 的行数')
  }

  let noItemRisk = stopped([item('exam.protect.pure-mode', 'ok', true, 'state')], [row('risk', 'none')], false)
  settleStoppedExam(noItemRisk, 'job-9-00000000')
  let blockedRisk = stopped([item('exam.protect.pure-mode', 'ok', true, 'state'),
    appsItem('unsupported', '无法获取应用列表')], [row('risk', 'none')], false)
  settleStoppedExam(blockedRisk, 'job-9-00000000')
  if (noItemRisk.state !== 'risk' || blockedRisk.state !== 'risk') {
    fail('apps[] 已有 action===none 的 risk 时，没有或暂不支持应用信誉项也应是 risk')
  }

  let cacheStage = stopped([item('exam.protect.pure-mode', 'ok', true, 'state'), appsItem('ok', '')],
    [row('ok', 'none')], true)
  settleStoppedExam(cacheStage, 'job-9-00000000')
  let cacheApps = findIn(cacheStage, 'exam.malware.apps')
  if (!cacheStage.appsComplete || cacheApps === null || cacheApps.detail.indexOf('本次扫描未完成') >= 0 ||
    cacheApps.status !== 'ok' || cacheStage.state !== 'clear') {
    fail('应用循环已写完时取消，appsComplete 应保持 true，详情不含本次扫描未完成')
  }
  if (cacheStage.summary.okApps !== 1) {
    fail('四个数都是 0 时应按 apps[] 行数抬高')
  }

  let noApps = stopped([item('exam.protect.pure-mode', 'ok', true, 'state')], [], false)
  settleStoppedExam(noApps, 'job-9-00000000')
  if (noApps.state !== 'incomplete' || findIn(noApps, 'exam.malware.apps') !== null) {
    fail('还没有应用信誉项时不补通过项，state 不能是 clear')
  }

  let unsupported = appsItem('unsupported', '无法获取应用列表')
  let blocked = stopped([item('exam.protect.pure-mode', 'ok', true, 'state'), unsupported], [], false)
  settleStoppedExam(blocked, 'job-9-00000000')
  if (unsupported.status !== 'unsupported' || unsupported.countsTowardState ||
    unsupported.detail !== '无法获取应用列表' || blocked.state !== 'incomplete') {
    fail('unsupported 的应用信誉项不应被改写')
  }

  let suspect = stopped([item('exam.protect.pure-mode', 'ok', true, 'state'), appsItem('ok', '')],
    [row('suspicious', 'none'), row('ok', 'none')], true)
  settleStoppedExam(suspect, 'job-9-00000000')
  let added = findIn(suspect, 'exam.malware.suspicious')
  if (added === null || added.title !== '可疑应用' || added.source !== 'local-rule' || added.detail !== '' ||
    added.status !== 'attention' || added.group !== 'threat' || added.kind !== 'advice' ||
    added.countsTowardState || added.action.route !== 'malware' || added.action.params !== 'job-9-00000000') {
    fail('suspiciousApps>0 且缺失时应补上 exam.malware.suspicious')
  }
  if (suspect.summary.suspiciousApps !== 1 || suspect.state !== 'clear' || suspect.advice !== 1) {
    fail('可疑项不改圆环，advice 计数应包含它')
  }

  let cleared = item('exam.malware.suspicious', 'attention', false, 'advice')
  let gone = stopped([item('exam.protect.pure-mode', 'ok', true, 'state'), appsItem('ok', ''), cleared],
    [row('ok', 'none')], true)
  gone.advice = 1
  settleStoppedExam(gone, 'job-9-00000000')
  if (cleared.status !== 'ok' || gone.advice !== 0) {
    fail('已有可疑项且 suspiciousApps 为 0 时应是 ok')
  }
  let none = stopped([item('exam.protect.pure-mode', 'ok', true, 'state'), appsItem('ok', '')], [], true)
  settleStoppedExam(none, 'job-9-00000000')
  if (findIn(none, 'exam.malware.suspicious') !== null) {
    fail('suspiciousApps 为 0 且不存在时不补')
  }

  if (!examAnyOffline([offlineRow('ok', 'local-rule')]) || examAnyOffline([offlineRow('suspicious', 'local-rule')]) ||
    examAnyOffline([offlineRow('ok', 'cloud')])) {
    fail('anyOffline 只看 action===none、level===ok、source 不是 cloud、cloud===offline 的行')
  }
  let local = stopped([appsItem('ok', '')], [offlineRow('ok', 'local-rule')], true)
  settleStoppedExam(local, 'job-9-00000000')
  let localApps = findIn(local, 'exam.malware.apps')
  if (localApps === null || localApps.detail !== '未联网') {
    fail('本地 ok 离线行应让详情含未联网')
  }
  let onlySuspect = stopped([appsItem('ok', '')], [offlineRow('suspicious', 'local-rule')], true)
  settleStoppedExam(onlySuspect, 'job-9-00000000')
  let suspectApps = findIn(onlySuspect, 'exam.malware.apps')
  if (suspectApps === null || suspectApps.detail.indexOf('未联网') >= 0) {
    fail('只有可疑行离线时详情不含未联网')
  }

  let noCloud = row('ok', 'none')
  noCloud.verdict.reason = '登记相符，云端暂无结果'
  let heuristic = row('unknown', 'none')
  heuristic.verdict.evidence = 'heuristic-cleared'
  let tail = stopped([appsItem('ok', '')], [noCloud, heuristic], false)
  settleStoppedExam(tail, 'job-9-00000000')
  let tailApps = findIn(tail, 'exam.malware.apps')
  if (tailApps === null || tailApps.status !== 'unknown' ||
    tailApps.detail !== '本次扫描未完成、云端暂无结果、部分应用暂无法确认') {
    fail('examAppsStatus 之后应补云端暂无结果和部分应用暂无法确认：' + (tailApps === null ? '' : tailApps.detail))
  }
}

export function runExamStateChecks(): void {
  settleChecks()
  if (!pureModeOk(1) || !pureModeOk(true) || !pureModeOk('1')) {
    fail('pureModeOk 应接受 1、true、字符串 1')
  }
  if (pureModeOk(0) || pureModeOk(false) || pureModeOk('0') || pureModeOk('true') || pureModeOk('')) {
    fail('pureModeOk 把其它已读到的值当成通过')
  }
  if (!lockdownOk(' confidentiality ') || lockdownOk('Confidentiality') || lockdownOk('none')) {
    fail('lockdownOk 只在去掉首尾空白后等于 confidentiality')
  }

  let risk = stateOf([
    item('exam.protect.pure-mode', 'ok', true, 'state'),
    item('exam.protect.lockdown', 'risk', true, 'state')
  ])
  if (risk !== 'risk') {
    fail('计入状态的 risk 应得到 risk')
  }
  let adviceRisk = stateOf([item('exam.malware.suspicious', 'risk', true, 'advice')])
  if (adviceRisk !== 'incomplete') {
    fail('advice 不应参与 stateOf')
  }
  let unsupportedApps = stateOf([
    item('exam.protect.pure-mode', 'ok', true, 'state'),
    item('exam.malware.apps', 'unsupported', false, 'state')
  ])
  if (unsupportedApps !== 'incomplete') {
    fail('应用列表暂不支持时应是 incomplete，不是 clear')
  }
  let unknown = stateOf([item('exam.protect.el5', 'unknown', true, 'state')])
  if (unknown !== 'incomplete') {
    fail('计入状态的 unknown 应是 incomplete')
  }
  if (stateOf([]) !== 'incomplete') {
    fail('没有计入项应是 incomplete')
  }
  let clear = stateOf([
    item('exam.protect.pure-mode', 'ok', true, 'state'),
    item('exam.malware.suspicious', 'attention', false, 'advice')
  ])
  if (clear !== 'clear') {
    fail('全部计入项为 ok 时应是 clear，attention 不参与')
  }
  let illegal = stateOf([item('exam.protect.pure-mode', 'attention', true, 'state')])
  if (illegal !== 'incomplete') {
    fail('计入项出现 attention 应是 incomplete')
  }

  let blocked = examAppsStatus(false, false, 3, 2, true)
  if (blocked.status !== 'unsupported' || blocked.countsTowardState ||
    blocked.detail !== '无法获取应用列表') {
    fail('bundlesReady 为 false 时不应看另外四个参数')
  }
  let riskDone = examAppsStatus(true, true, 2, 0, false)
  if (riskDone.status !== 'risk' || !riskDone.countsTowardState || riskDone.detail !== '') {
    fail('riskApps>0 且 appsComplete 为 true 时详情不应含本次扫描未完成')
  }
  let riskOpen = examAppsStatus(true, false, 2, 0, true)
  if (riskOpen.status !== 'risk' || riskOpen.detail !== '本次扫描未完成、未联网') {
    fail('未完成且未联网的顺序不对')
  }
  let unknownOpen = examAppsStatus(true, true, 0, 1, false)
  if (unknownOpen.status !== 'unknown' || unknownOpen.detail !== '') {
    fail('unknownApps>0 且已扫完时应是 unknown，详情为空')
  }
  let ok = examAppsStatus(true, true, 0, 0, false)
  if (ok.status !== 'ok' || ok.detail !== '') {
    fail('没有风险、未知和未完成时应是 ok')
  }

  let kept = appendExamAppsDetail('本次扫描未完成、未联网', [
    hit('quarantine', 'ok', '云端暂无结果', ''),
    hit('none', 'suspicious', '云端暂无结果', 'heuristic-cleared')
  ])
  if (kept !== '本次扫描未完成、未联网、部分应用暂无法确认') {
    fail('action 不是 none 的云端暂无结果被写进详情，或 heuristic-cleared 没补上')
  }
  let added = appendExamAppsDetail('', [
    hit('none', 'ok', '本地，云端暂无结果', ''),
    hit('none', 'unknown', '', 'heuristic-cleared')
  ])
  if (added !== '云端暂无结果、部分应用暂无法确认') {
    fail('后两句的顺序不对')
  }
  let once = appendExamAppsDetail('云端暂无结果', [hit('none', 'ok', '云端暂无结果', '')])
  if (once !== '云端暂无结果') {
    fail('已有的句子被重复')
  }

  let doneOld = candidate('old', 1, 'done', 'clear', '2099-01-01T00:00:00+08:00')
  let doneNew = candidate('new', 2, 'done', 'risk', '2000-01-01T00:00:00+08:00')
  let bySeq = homeExam([doneOld, doneNew])
  if (bySeq.jobId !== 'new' || bySeq.banner !== '') {
    fail('homeExam 用了 finishedAt，或唯一采用的 done 带了 banner')
  }
  let tieFirst = candidate('a', 4, 'done', 'clear', '')
  let tieSecond = candidate('b', 4, 'done', 'risk', '')
  if (homeExam([tieFirst, tieSecond]).jobId !== 'b') {
    fail('seq 相同时应取数组里靠后的一条')
  }
  let hidden = candidate('bad', 9, 'done', null, '')
  let visible = candidate('ok', 3, 'done', 'clear', '')
  if (homeExam([hidden, visible]).jobId !== 'ok') {
    fail('report 为 null 的行被当成了 latest')
  }
  let olderDone = candidate('done', 1, 'done', 'clear', '')
  let interrupted = candidate('stop', 5, 'interrupted', 'risk', '1999-01-01T00:00:00+08:00')
  let riskHome = homeExam([olderDone, interrupted])
  if (riskHome.jobId !== 'stop' || riskHome.banner !== '本次体检未完成') {
    fail('未完成但有风险的体检应盖过上一份 done')
  }
  let incomplete = candidate('half', 6, 'failed', 'incomplete', '')
  let keptDone = homeExam([olderDone, incomplete])
  if (keptDone.jobId !== 'done' || keptDone.banner !== '上次体检未完成') {
    fail('非风险的未完成体检应留着上一份 done，并写上次体检未完成')
  }
  let running = candidate('run', 8, 'running', 'clear', '')
  if (homeExam([olderDone, running]).jobId !== '' || homeExam([olderDone, running]).banner !== '') {
    fail('有排队或运行中的体检时 homeExam 仍采用了已结束结果')
  }
  if (settledHome([olderDone, running]) !== 'done') {
    fail('运行中的体检不应让 settledHome 变成空')
  }
  if (homeExam([]).jobId !== '' || settledHome([]) !== '') {
    fail('没有体检时应为空')
  }

  let targets = examWritebackTargets([olderDone, interrupted, running], 'stop')
  if (targets.length !== 2 || targets[0] !== 'stop' || targets[1] !== 'done') {
    fail('examWritebackTargets 没有按正在看的、seq 最大的 done、settledHome 去重')
  }
  let same = examWritebackTargets([olderDone], '')
  if (same.length !== 1 || same[0] !== 'done') {
    fail('同一份体检被 examWritebackTargets 算了多次')
  }
  let runningView = examWritebackTargets([olderDone, running], 'run')
  if (runningView.length !== 1 || runningView[0] !== 'done') {
    fail('queued 或 running 进入了 examWritebackTargets')
  }
}
