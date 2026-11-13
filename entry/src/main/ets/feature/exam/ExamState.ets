import { hilog } from '@kit.PerformanceAnalysisKit';
import type {
  AppsItemStatus,
  CheckItem,
  CheckStatus,
  ExamReport,
  ExamState,
  JobRecord,
  ScanHit
} from '../../center/CenterTypes'

const DOMAIN: number = 0x4A59
const TAG: string = 'Center'
const THIS_EXAM: string = '本次体检未完成'
const LAST_EXAM: string = '上次体检未完成'
const UNFINISHED: string = '本次扫描未完成'
const OFFLINE: string = '未联网'
const NO_CLOUD: string = '云端暂无结果'
const UNCONFIRMED: string = '部分应用暂无法确认'

export interface HomeCandidate {
  record: JobRecord
  report: ExamReport | null
}

export interface HomePick {
  jobId: string
  banner: string
}

class AppsItemStatusValue implements AppsItemStatus {
  status: CheckStatus = 'unsupported'
  countsTowardState: boolean = false
  detail: string = ''
}

class HomePickValue implements HomePick {
  jobId: string = ''
  banner: string = ''
}

function pick(jobId: string, banner: string): HomePick {
  let value = new HomePickValue()
  value.jobId = jobId
  value.banner = banner
  return value
}

function counts(item: CheckItem): boolean {
  return item.countsTowardState && item.kind !== 'advice'
}

function settled(state: string): boolean {
  return state === 'done' || state === 'failed' || state === 'cancelled' || state === 'interrupted'
}

function isExam(row: HomeCandidate): boolean {
  return row.record.kind === 'exam'
}

function runningExam(rows: HomeCandidate[]): boolean {
  for (let i = 0; i < rows.length; i++) {
    let state = rows[i].record.state
    if (isExam(rows[i]) && (state === 'queued' || state === 'running')) {
      return true
    }
  }
  return false
}

function prefer(current: HomeCandidate, currentAt: number, next: HomeCandidate, nextAt: number): boolean {
  if (next.record.seq > current.record.seq) {
    return true
  }
  return next.record.seq === current.record.seq && nextAt > currentAt
}

function latestSettled(rows: HomeCandidate[]): HomeCandidate | null {
  let found: HomeCandidate | null = null
  let foundAt = -1
  for (let i = 0; i < rows.length; i++) {
    let row = rows[i]
    if (!isExam(row) || row.report === null || !settled(row.record.state)) {
      continue
    }
    if (found === null || prefer(found, foundAt, row, i)) {
      found = row
      foundAt = i
    }
  }
  return found
}

function latestDone(rows: HomeCandidate[]): HomeCandidate | null {
  let found: HomeCandidate | null = null
  let foundAt = -1
  for (let i = 0; i < rows.length; i++) {
    let row = rows[i]
    if (!isExam(row) || row.report === null || row.record.state !== 'done') {
      continue
    }
    if (found === null || prefer(found, foundAt, row, i)) {
      found = row
      foundAt = i
    }
  }
  return found
}

function pickSettled(rows: HomeCandidate[]): HomePick {
  let latest = latestSettled(rows)
  let done = latestDone(rows)
  if (latest !== null && latest.record.state !== 'done' && latest.report !== null &&
    latest.report.state === 'risk') {
    return pick(latest.record.jobId, THIS_EXAM)
  }
  if (done !== null) {
    let banner = ''
    if (latest === null || latest.record.jobId !== done.record.jobId) {
      banner = LAST_EXAM
    }
    return pick(done.record.jobId, banner)
  }
  if (latest !== null) {
    return pick(latest.record.jobId, THIS_EXAM)
  }
  return pick('', '')
}

function hasSentence(detail: string, sentence: string): boolean {
  return detail.indexOf(sentence) >= 0
}

function joinSentences(unfinished: boolean, offline: boolean, noCloud: boolean, unconfirmed: boolean): string {
  let parts: string[] = []
  if (unfinished) {
    parts.push(UNFINISHED)
  }
  if (offline) {
    parts.push(OFFLINE)
  }
  if (noCloud) {
    parts.push(NO_CLOUD)
  }
  if (unconfirmed) {
    parts.push(UNCONFIRMED)
  }
  let text = ''
  for (let i = 0; i < parts.length; i++) {
    if (i > 0) {
      text += '、'
    }
    text += parts[i]
  }
  return text
}

export function stateOf(items: CheckItem[]): ExamState {
  let counting: CheckItem[] = []
  for (let i = 0; i < items.length; i++) {
    if (counts(items[i])) {
      counting.push(items[i])
    }
  }
  for (let i = 0; i < counting.length; i++) {
    if (counting[i].status === 'risk') {
      return 'risk'
    }
  }
  for (let i = 0; i < items.length; i++) {
    if (items[i].id === 'exam.malware.apps' && items[i].status === 'unsupported') {
      return 'incomplete'
    }
  }
  for (let i = 0; i < counting.length; i++) {
    if (counting[i].status === 'unknown') {
      return 'incomplete'
    }
  }
  if (counting.length === 0) {
    return 'incomplete'
  }
  let allOk = true
  for (let i = 0; i < counting.length; i++) {
    if (counting[i].status !== 'ok') {
      allOk = false
    }
  }
  if (allOk) {
    return 'clear'
  }
  hilog.error(DOMAIN, TAG, 'stateOf counting status is not ok, risk, or unknown')
  return 'incomplete'
}

export function examAppsStatus(bundlesReady: boolean, appsComplete: boolean, riskApps: number,
  unknownApps: number, anyOffline: boolean): AppsItemStatus {
  let status = new AppsItemStatusValue()
  if (!bundlesReady) {
    status.status = 'unsupported'
    status.countsTowardState = false
    status.detail = '无法获取应用列表'
    return status
  }
  status.countsTowardState = true
  if (riskApps > 0) {
    status.status = 'risk'
  } else if (!appsComplete || unknownApps > 0) {
    status.status = 'unknown'
  } else {
    status.status = 'ok'
  }
  let unfinished = !appsComplete
  status.detail = joinSentences(unfinished, anyOffline, false, false)
  return status
}

export function appendExamAppsDetail(detail: string, apps: ScanHit[]): string {
  let noCloud = hasSentence(detail, NO_CLOUD)
  let unconfirmed = hasSentence(detail, UNCONFIRMED)
  for (let i = 0; i < apps.length; i++) {
    if (apps[i].action !== 'none') {
      continue
    }
    if (apps[i].verdict.level === 'ok' && apps[i].verdict.reason.indexOf(NO_CLOUD) >= 0) {
      noCloud = true
    }
    if (apps[i].verdict.evidence === 'heuristic-cleared') {
      unconfirmed = true
    }
  }
  return joinSentences(hasSentence(detail, UNFINISHED), hasSentence(detail, OFFLINE), noCloud, unconfirmed)
}

export function homeExam(rows: HomeCandidate[]): HomePick {
  if (runningExam(rows)) {
    return pick('', '')
  }
  return pickSettled(rows)
}

export function settledHome(rows: HomeCandidate[]): string {
  return pickSettled(rows).jobId
}

export function examWritebackTargets(rows: HomeCandidate[], viewingJobId: string): string[] {
  let ids: string[] = []
  if (viewingJobId !== '') {
    for (let i = 0; i < rows.length; i++) {
      let row = rows[i]
      if (row.record.jobId === viewingJobId && isExam(row) && settled(row.record.state) &&
        row.report !== null) {
        ids.push(row.record.jobId)
        break
      }
    }
  }
  let done = latestDone(rows)
  if (done !== null) {
    let seen = false
    for (let i = 0; i < ids.length; i++) {
      if (ids[i] === done.record.jobId) {
        seen = true
      }
    }
    if (!seen) {
      ids.push(done.record.jobId)
    }
  }
  let home = settledHome(rows)
  if (home !== '') {
    let seen = false
    for (let i = 0; i < ids.length; i++) {
      if (ids[i] === home) {
        seen = true
      }
    }
    if (!seen) {
      ids.push(home)
    }
  }
  return ids
}
