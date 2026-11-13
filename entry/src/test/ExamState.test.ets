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
  examAppsStatus,
  examWritebackTargets,
  homeExam,
  settledHome,
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

export function runExamStateChecks(): void {
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
