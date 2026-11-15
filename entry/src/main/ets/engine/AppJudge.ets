import type {
  CancelFlag, CheckItem, CloudBatch, CloudView, ExamReport, Fingerprint, JobRecord, PermissionFact,
  QueryKey, RiskLevel, ScanHit, ScanReport, TrustEntry, Verdict
} from '../center/CenterTypes'
import { cloudBatch, reasonMax } from '../center/CenterLimits'
import { Anomaly } from '../center/Anomaly'
import { isSensitive } from '../center/SensitiveCatalog'
import {
  appendExamAppsDetail, examAppsStatus, examWritebackTargets, stateOf
} from '../feature/exam/ExamState'
import type { HomeCandidate } from '../feature/exam/ExamState'
import type { RuleLoad } from './RulePack'
import { canonicalCert, decide, terminalBeforeCloud } from './Decide'
import { toQueryKey } from './QueryKey'
import { Heuristic } from './Heuristic'
import { LocalRuleEngine } from './LocalRuleEngine'
import { Lookalike } from './Lookalike'

const SELF: string = 'com.jinyinhu.securitycenter'
const NORMAL: string = '云端查询正常'
const NO_RESULT: string = '云端暂无结果'
const INVALID_CLOUD: string = '未联网，云端结果无效'
const PROTECTED: string[] = [
  'official', 'impersonation', 'cert-uncompared', 'bundle-cert-mismatch', 'empty-fingerprint'
]

export interface JudgeInput {
  fingerprint: Fingerprint
  declared: string[]
  granted: string[]
  grantsReady: boolean
}

export class JudgeResult {
  hits: ScanHit[] = []
  complete: boolean = false
}

interface PendingInput {
  input: JudgeInput
  index: number
  cloudIndex: number
}

export class AppJudge {
  private cloud: CloudBatch

  constructor(cloud: CloudBatch) {
    this.cloud = cloud
  }

  async judge(inputs: JudgeInput[], rules: RuleLoad, trust: TrustEntry[], cancel: CancelFlag,
    stopped: () => boolean, onHit: (hit: ScanHit) => void): Promise<JudgeResult> {
    let result = new JudgeResult()
    let completed: Map<number, ScanHit> = new Map()
    let publish = (index: number, input: JudgeInput, verdict: Verdict): void => {
      let hit: ScanHit = {
        fingerprint: input.fingerprint, displayName: input.fingerprint.label, verdict: verdict,
        quarantined: false, action: 'none', granted: input.grantsReady ? input.granted.slice() : []
      }
      completed.set(index, hit)
      onHit(hit)
    }
    let cursor = 0
    while (cursor < inputs.length && !stopped()) {
      let pending: PendingInput[] = []
      let keys: QueryKey[] = []
      while (cursor < inputs.length && keys.length < cloudBatch && !stopped()) {
        let input = snapshot(inputs[cursor])
        let terminal = terminalBeforeCloud(input.fingerprint, rules)
        if (terminal === null) {
          pending.push({ input: input, index: cursor, cloudIndex: keys.length })
          keys.push(toQueryKey(input.fingerprint))
        } else {
          publish(cursor, input, terminal)
        }
        cursor++
      }
      if (stopped()) {
        break
      }
      let views = await this.query(keys, cancel)
      for (let row of pending) {
        if (stopped()) {
          break
        }
        let input = row.input
        let verdict = decide(input.fingerprint, input.declared, input.granted, input.grantsReady,
          rules, trust, settledCloud(views[row.cloudIndex]))
        publish(row.index, input, verdict)
      }
    }
    for (let i = 0; i < inputs.length; i++) {
      let hit = completed.get(i)
      if (hit !== undefined) {
        result.hits.push(hit)
      }
    }
    result.complete = result.hits.length === inputs.length
    return result
  }

  private async query(keys: QueryKey[], cancel: CancelFlag): Promise<CloudView[]> {
    if (keys.length === 0) {
      return []
    }
    try {
      let views = await this.cloud.query(keys, cancel)
      if (views instanceof Array && views.length === keys.length) {
        return views
      }
      return keys.map((): CloudView => offline(INVALID_CLOUD))
    } catch (err) {
      return keys.map((): CloudView => offline('未联网'))
    }
  }
}

function snapshot(input: JudgeInput): JudgeInput {
  let fp = input.fingerprint
  let fingerprint: Fingerprint = {
    kind: fp.kind, id: fp.id, bundleName: fp.bundleName, version: fp.version,
    versionCode: fp.versionCode, certSha256: fp.certSha256, certAlgo: fp.certAlgo,
    sha256: fp.sha256, size: fp.size, label: fp.label
  }
  return { fingerprint: fingerprint, declared: input.declared.slice(), granted: input.granted.slice(),
    grantsReady: fp.kind === 'bundle' && input.grantsReady }
}

function offline(reason: string): CloudView {
  return { state: 'offline', level: 'none', reason: reason, evidence: '' }
}

function settledCloud(view: CloudView | undefined): CloudView {
  if (view === undefined || view === null ||
    (view.state !== 'reached' && view.state !== 'offline')) {
    return offline(INVALID_CLOUD)
  }
  return view
}

export interface GrantChange {
  bundleName: string
  mode: 'replace' | 'remove'
  permissions: string[]
}

class LevelCounts {
  suspicious: number = 0
  unknown: number = 0
  ok: number = 0
}

class RejudgeDelta {
  touched: boolean = false
  anomaly: number = 0
  sensitive: number = 0
}

export function grantChangesFromFacts(facts: PermissionFact[]): GrantChange[] {
  let byBundle: Map<string, GrantChange> = new Map()
  for (let fact of facts) {
    let change = byBundle.get(fact.bundleName)
    if (change === undefined) {
      change = { bundleName: fact.bundleName, mode: 'replace', permissions: [] }
      byBundle.set(fact.bundleName, change)
    }
    if (fact.grant === 'granted' && change.permissions.indexOf(fact.permission) < 0) {
      change.permissions.push(fact.permission)
    }
  }
  return Array.from(byBundle.values())
}

/** 只改已存在的结果对象。调用方把整次读改写放进 Writer 的独占队列。 */
export function rejudgeGranted(report: ExamReport | ScanReport, changes: GrantChange[],
  rules: RuleLoad): boolean {
  let exam = report as ExamReport
  if (exam.apps instanceof Array) {
    let counts = new LevelCounts()
    counts.suspicious = exam.summary.suspiciousApps
    counts.unknown = exam.summary.unknownApps
    counts.ok = exam.summary.okApps
    let delta = rejudgeRows(exam.apps, changes, rules, counts)
    if (!delta.touched) {
      return false
    }
    exam.summary.suspiciousApps = counts.suspicious
    exam.summary.unknownApps = counts.unknown
    exam.summary.okApps = counts.ok
    exam.summary.anomalyApps = Math.max(0, exam.summary.anomalyApps + delta.anomaly)
    exam.summary.sensitiveApps = Math.max(0, exam.summary.sensitiveApps + delta.sensitive)
    finishExam(exam)
    return true
  }
  let scan = report as ScanReport
  let counts = new LevelCounts()
  counts.suspicious = scan.suspicious
  counts.unknown = scan.unknown
  counts.ok = scan.ok
  let delta = rejudgeRows(scan.hits, changes, rules, counts)
  if (!delta.touched) {
    return false
  }
  scan.suspicious = counts.suspicious
  scan.unknown = counts.unknown
  scan.ok = counts.ok
  return true
}

function rejudgeRows(hits: ScanHit[], changes: GrantChange[], rules: RuleLoad,
  counts: LevelCounts): RejudgeDelta {
  let delta = new RejudgeDelta()
  let byBundle: Map<string, GrantChange[]> = new Map()
  for (let change of changes) {
    let grouped = byBundle.get(change.bundleName)
    if (grouped === undefined) {
      grouped = []
      byBundle.set(change.bundleName, grouped)
    }
    grouped.push(change)
  }
  for (let hit of hits) {
    if (hit.fingerprint.kind !== 'bundle' || hit.action !== 'none') {
      continue
    }
    let matching = byBundle.get(hit.fingerprint.bundleName)
    if (matching === undefined) {
      continue
    }
    let anomalyBefore = Anomaly.count([hit], rules)
    let sensitiveBefore = sensitiveHit(hit)
    let previous = hit.verdict
    for (let change of matching) {
      hit.granted = change.mode === 'replace' ? change.permissions.slice() :
        hit.granted.filter((permission: string): boolean => change.permissions.indexOf(permission) < 0)
    }
    hit.verdict = rejudgeVerdict(hit, previous, rules)
    moveCount(counts, previous.level, hit.verdict.level)
    delta.anomaly += Anomaly.count([hit], rules) - anomalyBefore
    delta.sensitive += sensitiveHit(hit) - sensitiveBefore
    delta.touched = true
  }
  return delta
}

function sensitiveHit(hit: ScanHit): number {
  if (hit.fingerprint.bundleName === SELF) {
    return 0
  }
  return hit.granted.some((permission: string): boolean => isSensitive(permission)) ? 1 : 0
}

function rejudgeVerdict(hit: ScanHit, previous: Verdict, rules: RuleLoad): Verdict {
  if (previous.level === 'risk' || previous.source === 'trust' || previous.source === 'local-black' ||
    PROTECTED.indexOf(previous.evidence) >= 0) {
    return previous
  }
  let pick = Lookalike.select(hit.fingerprint, rules)
  if (LocalRuleEngine.certUncompared(hit.fingerprint, rules, pick)) {
    return localRejudgment(previous, '证书无法比对', 'cert-uncompared')
  }
  let heuristic = Heuristic.matches(hit.fingerprint, [], hit.granted, true, rules)
  let lookalike = Lookalike.matches(pick, hit.fingerprint)
  if (heuristic.matched || lookalike) {
    let suffix = ''
    if (lookalike) {
      suffix = '包名与 ' + pick.bundleName + ' 相似'
    }
    if (previous.cloud === 'offline') {
      suffix = appendReason(suffix, offlineReason(previous.reason))
    } else if ((previous.source === 'cloud' && previous.level === 'ok') ||
      previous.reason.indexOf(NORMAL) >= 0) {
      suffix = appendReason(suffix, NORMAL)
    }
    let evidence = heuristic.matched ? 'heuristic' : 'lookalike'
    if (heuristic.matched && lookalike) {
      evidence = 'heuristic+lookalike'
    }
    return { level: 'suspicious', source: 'local-rule', reason: appendReason(heuristic.reason, suffix),
      evidence: evidence, cloud: previous.cloud }
  }
  if (previous.level !== 'suspicious') {
    return previous
  }
  if (previous.cloud === 'reached' && previous.reason.indexOf(NORMAL) >= 0 &&
    canonicalCert(hit.fingerprint.certSha256).length > 0 && hit.fingerprint.certAlgo !== 'none') {
    return { level: 'ok', source: 'cloud', reason: NORMAL, evidence: '', cloud: previous.cloud }
  }
  let nameOnly = LocalRuleEngine.nameOnly(hit.fingerprint, rules)
  if (nameOnly !== null) {
    return localRejudgment(previous, nameOnly.reason, 'match=name-only')
  }
  return localRejudgment(previous, '风险权限已关闭', 'heuristic-cleared')
}

function localRejudgment(previous: Verdict, reason: string, evidence: string): Verdict {
  if (previous.cloud === 'offline') {
    reason = appendReason(reason, offlineReason(previous.reason))
  } else if (previous.cloud === 'reached' &&
    (evidence === 'match=name-only' || previous.reason.indexOf(NO_RESULT) >= 0)) {
    reason = appendReason(reason, NO_RESULT)
  }
  return { level: 'unknown', source: 'local-rule', reason: reason.substring(0, reasonMax),
    evidence: evidence, cloud: previous.cloud }
}

function offlineReason(reason: string): string {
  if (reason.indexOf('未联网，云服务未配置') >= 0) {
    return '未联网，云服务未配置'
  }
  if (reason.indexOf(INVALID_CLOUD) >= 0) {
    return INVALID_CLOUD
  }
  return '未联网'
}

function appendReason(local: string, suffix: string): string {
  if (suffix.length === 0) {
    return local.substring(0, reasonMax)
  }
  if (local.length === 0) {
    return suffix.substring(0, reasonMax)
  }
  let room = reasonMax - suffix.length - 1
  if (room <= 0) {
    return suffix.substring(0, reasonMax)
  }
  return local.substring(0, room) + '、' + suffix
}

function moveCount(counts: LevelCounts, previous: RiskLevel, next: RiskLevel): void {
  if (previous === next) {
    return
  }
  if (previous === 'suspicious') {
    counts.suspicious = Math.max(0, counts.suspicious - 1)
  } else if (previous === 'unknown') {
    counts.unknown = Math.max(0, counts.unknown - 1)
  } else if (previous === 'ok') {
    counts.ok = Math.max(0, counts.ok - 1)
  }
  if (next === 'suspicious') {
    counts.suspicious++
  } else if (next === 'unknown') {
    counts.unknown++
  } else if (next === 'ok') {
    counts.ok++
  }
}

function finishExam(report: ExamReport): void {
  let apps = report.items.find((item: CheckItem): boolean => item.id === 'exam.malware.apps')
  if (apps !== undefined && apps.status !== 'unsupported') {
    let anyOffline = report.apps.some((hit: ScanHit): boolean => hit.action === 'none' &&
      hit.verdict.level === 'ok' && hit.verdict.source !== 'cloud' && hit.verdict.cloud === 'offline')
    let status = examAppsStatus(apps.countsTowardState, report.appsComplete,
      report.summary.riskApps, report.summary.unknownApps, anyOffline)
    if (status.status !== 'unsupported') {
      apps.status = status.status
      apps.countsTowardState = status.countsTowardState
      apps.detail = status.detail
    }
    apps.detail = appendExamAppsDetail(apps.detail, report.apps)
  }
  for (let item of report.items) {
    if (item.id === 'exam.malware.suspicious') {
      item.status = report.summary.suspiciousApps > 0 ? 'attention' : 'ok'
    }
    if (item.id === 'exam.permission.anomaly' && item.status !== 'unsupported') {
      item.status = report.summary.anomalyApps > 0 ? 'attention' : 'ok'
    }
  }
  report.advice = report.items.filter((item: CheckItem): boolean => item.kind === 'advice' && item.status !== 'ok').length
  report.state = stateOf(report.items)
  if (report.summary.riskApps > 0 || report.apps.some((hit: ScanHit): boolean =>
    hit.action === 'none' && hit.verdict.level === 'risk')) {
    report.state = 'risk'
  } else if (apps === undefined && report.state === 'clear') {
    report.state = 'incomplete'
  }
}

export interface ScanCandidate {
  record: JobRecord
  report: ScanReport | null
}

export interface GrantedResultStore {
  exclusive(work: () => void): void
  exams(): HomeCandidate[]
  scans(): ScanCandidate[]
  saveExam(record: JobRecord, report: ExamReport): void
  saveScan(record: JobRecord, report: ScanReport): void
}

export function rejudgeGrantedResults(store: GrantedResultStore, viewingJobId: string, focus: string,
  changes: GrantChange[], rules: RuleLoad): void {
  store.exclusive(() => {
    let exams = store.exams()
    let viewingExam = focus.startsWith('anomaly:') ? focus.substring('anomaly:'.length) : viewingJobId
    let targets = examWritebackTargets(exams, viewingExam)
    for (let jobId of targets) {
      let candidate = exams.find((row: HomeCandidate): boolean => row.record.jobId === jobId && row.report !== null)
      if (candidate !== undefined && candidate.report !== null &&
        rejudgeGranted(candidate.report, changes, rules)) {
        store.saveExam(candidate.record, candidate.report)
      }
    }
    let scans = store.scans()
    let latest: ScanCandidate | null = null
    for (let candidate of scans) {
      if (candidate.record.kind === 'malware' && candidate.record.state === 'done' && candidate.report !== null &&
        (latest === null || candidate.record.seq >= latest.record.seq)) {
        latest = candidate
      }
    }
    let seen: string[] = []
    for (let candidate of scans) {
      let record = candidate.record
      if (record.kind !== 'malware' || record.state === 'queued' || record.state === 'running' ||
        candidate.report === null || seen.indexOf(record.jobId) >= 0 ||
        (record.jobId !== viewingJobId && (latest === null || record.jobId !== latest.record.jobId))) {
        continue
      }
      seen.push(record.jobId)
      if (rejudgeGranted(candidate.report, changes, rules)) {
        store.saveScan(record, candidate.report)
      }
    }
  })
}
