import fs from '@ohos.file.fs';
import { hilog } from '@kit.PerformanceAnalysisKit';
import { Anomaly } from '../center/Anomaly'
import { CenterError } from '../center/CenterError'
import { subtractPart, sumParts } from '../center/CleanMath'
import { isSensitive } from '../center/SensitiveCatalog'
import type {
  AuditLine, BundleRow, CacheClear, CacheRow, CheckItem, CleanReport, CountedByte, ExamReport, FileHit,
  HitAction, InstallerPort, JobRecord, QuarantineEntry, RiskLevel, ScanHit, ScanReport
} from '../center/CenterTypes'
import { canonicalCert } from '../engine/Decide'
import type { RuleLoad } from '../engine/RulePack'
import {
  appendExamAppsDetail, examAnyOffline, examAppsStatus, examWritebackTargets, stateOf
} from '../feature/exam/ExamState'
import type { HomeCandidate } from '../feature/exam/ExamState'
import { AuditLog } from './AuditLog'
import { TrustList } from './TrustList'
import { Writer } from './Writer'
import type { PermissionActions } from './PermissionActions'

const DOMAIN: number = 0x4A59
const TAG: string = 'Center'
const SELF: string = 'com.jinyinhu.securitycenter'
const NOT_SETTLED: string = '扫描尚未完成'
const VIEW_ONLY: string = '仅查看，不删除'
const UNSUPPORTED: string = '暂不支持'
const SUCCESS: string = '成功'
const TRUSTED: string = '已信任'
const TRUST_ADDED: string = '已添加信任，下次扫描生效'
const APPS_ID: string = 'exam.malware.apps'
const SUSPICIOUS_ID: string = 'exam.malware.suspicious'
const ANOMALY_ID: string = 'exam.permission.anomaly'
const NO_TRUST: string[] = ['impersonation', 'cert-uncompared', 'bundle-cert-mismatch']

/** 隔离入口。授权根和 HUKS 状态由组合根绑定，这里只给出源 uri。 */
export interface QuarantineDoor {
  put(from: string, size: number, sha256: string, reason: string): CenterError | QuarantineEntry
}

/** 只删除本应用 cacheDir 里的文件，返回实际删掉的字节。 */
export interface OwnCache {
  clear(): Promise<number>
}

export interface DispositionPorts {
  installer: InstallerPort
  cache: CacheClear
  ownCache: OwnCache
  quarantine: QuarantineDoor
  rules: () => RuleLoad
}

export class DispositionResult {
  done: boolean = false
  message: string = ''
  button: string = ''
}

class Located {
  record: JobRecord
  text: string

  constructor(record: JobRecord, text: string) {
    this.record = record
    this.text = text
  }
}

class ExamTouch {
  hitAction: HitAction = 'none'
  appsId: string = ''
  appsKind: 'bundle' | 'file' = 'bundle'
  partId: string = ''
  partKind: 'cache' | 'installer' = 'cache'
  /** 小于 0 表示把这条整段减掉。 */
  partBytes: number = 0
}

class ExamRow implements HomeCandidate {
  record: JobRecord
  report: ExamReport | null

  constructor(record: JobRecord, report: ExamReport | null) {
    this.record = record
    this.report = report
  }
}

export class Disposition {
  private ports: DispositionPorts
  private permissions: PermissionActions | null = null

  constructor(ports: DispositionPorts) {
    this.ports = ports
  }

  /** 权限端口由组合根在创建后绑定。 */
  bindPermissions(permissions: PermissionActions): void {
    this.permissions = permissions
  }

  /** 用户确认后交给权限操作服务重新读取授权并执行关闭。 */
  async closePermission(jobId: string, bundleName: string, permission: string,
    focus: string): Promise<DispositionResult> {
    if (this.permissions === null) {
      return refuse(UNSUPPORTED)
    }
    let result = await this.permissions.revoke(jobId, bundleName, permission, focus)
    let out = new DispositionResult()
    out.done = result.done
    out.message = result.message
    out.button = result.done ? '已关闭' : ''
    return out
  }

  /** 信誉、体检或软件结果里的已装应用。 */
  async uninstall(jobId: string, bundleName: string): Promise<DispositionResult> {
    let found = locate(jobId)
    if (found instanceof DispositionResult) {
      return found
    }
    let located: Located = found
    let kind = located.record.kind
    if (kind === 'apps') {
      if (findBundleRow(parseArray(located.text), bundleName) < 0) {
        return refuse(NOT_SETTLED)
      }
    } else if (kind === 'malware' || kind === 'exam') {
      let hit = findHit(hitsOf(located), 'bundle', bundleName)
      if (hit === null || !actionable(hit)) {
        return refuse(NOT_SETTLED)
      }
    } else {
      return refuse(NOT_SETTLED)
    }
    try {
      await this.ports.installer.uninstall(bundleName)
    } catch (err) {
      let result = refuse('卸载失败，返回码 ' + returnCode(err as Object))
      audit(located.record, '卸载', bundleName, result.message, false)
      return result
    }
    let touch = new ExamTouch()
    touch.hitAction = 'uninstall'
    touch.appsId = bundleName
    touch.appsKind = 'bundle'
    touch.partId = bundleName
    touch.partKind = 'cache'
    touch.partBytes = -1
    Writer.exclusive(() => {
      this.updateViewing(located.record, touch)
      this.writeBack(located.record, touch)
    })
    audit(located.record, '卸载', bundleName, SUCCESS, true)
    return succeed('')
  }

  /** 信誉或体检里的文件行，或清理结果里的安装包。 */
  async quarantine(jobId: string, uri: string): Promise<DispositionResult> {
    let found = locate(jobId)
    if (found instanceof DispositionResult) {
      return found
    }
    let located: Located = found
    let size = 0
    let sha256 = ''
    let reason = ''
    let kind = located.record.kind
    if (kind === 'malware' || kind === 'exam') {
      let hit = findHit(hitsOf(located), 'file', uri)
      if (hit === null || !actionable(hit)) {
        return refuse(NOT_SETTLED)
      }
      size = hit.fingerprint.size
      sha256 = hit.fingerprint.sha256
      reason = hit.verdict.reason
    } else if (kind === 'clean') {
      let clean = parseClean(located.text)
      let index = clean === null ? -1 : findFileHit(clean.hits, uri)
      if (clean === null || index < 0) {
        return refuse(NOT_SETTLED)
      }
      size = clean.hits[index].size
      sha256 = clean.hits[index].sha256
      reason = clean.hits[index].reason
    } else {
      return refuse(NOT_SETTLED)
    }
    let put = this.ports.quarantine.put(uri, size, sha256, reason)
    if (put instanceof CenterError) {
      audit(located.record, '隔离', uri, put.message, false)
      return refuse(put.message)
    }
    let touch = new ExamTouch()
    touch.hitAction = 'quarantine'
    touch.appsId = uri
    touch.appsKind = 'file'
    touch.partId = uri
    touch.partKind = 'installer'
    touch.partBytes = size
    Writer.exclusive(() => {
      this.updateViewing(located.record, touch)
      this.writeBack(located.record, touch)
    })
    audit(located.record, '隔离', uri, SUCCESS, true)
    return succeed('')
  }

  /** 清理结果里的一行缓存。只清缓存，不进隔离区。 */
  async clearCache(jobId: string, bundleName: string): Promise<DispositionResult> {
    let found = locate(jobId)
    if (found instanceof DispositionResult) {
      return found
    }
    let located: Located = found
    if (located.record.kind !== 'clean') {
      return refuse(NOT_SETTLED)
    }
    let clean = parseClean(located.text)
    let index = clean === null ? -1 : findCacheRow(clean.caches, bundleName)
    if (clean === null || index < 0) {
      return refuse(NOT_SETTLED)
    }
    let ownOnly = clean.caches.length === 1 && bundleName === SELF
    let cleared = 0
    try {
      if (ownOnly) {
        cleared = await this.ports.ownCache.clear()
      } else {
        await this.ports.cache.clear(bundleName)
        cleared = clean.caches[index].cacheBytes
      }
    } catch (err) {
      let message = err instanceof CenterError && err.code === 'unsupported' ? UNSUPPORTED :
        '清除失败，返回码 ' + returnCode(err as Object)
      audit(located.record, '清缓存', bundleName, message, false)
      return refuse(message)
    }
    let touch = new ExamTouch()
    touch.hitAction = 'cleared'
    touch.partId = bundleName
    touch.partKind = 'cache'
    touch.partBytes = cleared
    Writer.exclusive(() => {
      this.updateViewing(located.record, touch)
      this.writeBack(located.record, touch)
    })
    audit(located.record, '清缓存', bundleName, SUCCESS, true)
    return succeed('')
  }

  /** 只写信任区。不改这一行的等级、计数和按钮。 */
  trust(jobId: string, id: string): DispositionResult {
    let found = locate(jobId)
    if (found instanceof DispositionResult) {
      return found
    }
    let located: Located = found
    if (located.record.kind !== 'malware' && located.record.kind !== 'exam') {
      return refuse(NOT_SETTLED)
    }
    let hits = hitsOf(located)
    let hit = findHit(hits, 'bundle', id)
    if (hit === null) {
      hit = findHit(hits, 'file', id)
    }
    if (hit === null || hit.action !== 'none') {
      return refuse(NOT_SETTLED)
    }
    if (!trustable(hit)) {
      return refuse(UNSUPPORTED)
    }
    let fp = hit.fingerprint
    let file = fp.kind === 'file'
    let already = file ? TrustList.matchesFile(fp.sha256) :
      TrustList.matchesBundle(fp.certSha256, fp.bundleName, fp.versionCode)
    if (already) {
      let result = succeed('')
      result.button = TRUSTED
      return result
    }
    let written = file ? TrustList.trustFile(fp.sha256, fp.id) :
      TrustList.trustBundle(fp.certSha256, fp.certAlgo, fp.bundleName, fp.versionCode)
    if (!written) {
      audit(located.record, '信任', id, '信任区无法写入', false)
      return refuse('信任区无法写入')
    }
    audit(located.record, '信任', id, SUCCESS, true)
    let result = succeed('')
    result.button = TRUST_ADDED
    return result
  }

  private updateViewing(record: JobRecord, touch: ExamTouch): void {
    if (record.kind === 'exam') {
      return
    }
    let text = Writer.readText(Writer.resultFileOf(record.jobId))
    if (text === null) {
      return
    }
    if (record.kind === 'malware') {
      let scan = parseScan(text)
      if (scan === null) {
        return
      }
      let hit = findHit(scan.hits, touch.appsKind, touch.appsId)
      if (hit === null) {
        return
      }
      if (hit.action === 'none') {
        decrementScan(scan, hit.verdict.level)
      }
      markHit(hit, touch.hitAction)
      Writer.commit(record, JSON.stringify(scan))
      return
    }
    if (record.kind === 'apps') {
      let rows = parseArray(text) as BundleRow[]
      let index = findBundleRow(rows, touch.appsId)
      if (index >= 0) {
        rows.splice(index, 1)
        Writer.commit(record, JSON.stringify(rows))
      }
      return
    }
    if (record.kind === 'clean') {
      let clean = parseClean(text)
      if (clean === null) {
        return
      }
      if (touch.partKind === 'cache') {
        let index = findCacheRow(clean.caches, touch.partId)
        if (index >= 0) {
          clean.caches.splice(index, 1)
        }
      } else {
        let index = findFileHit(clean.hits, touch.partId)
        if (index >= 0) {
          clean.hits.splice(index, 1)
        }
      }
      Writer.commit(record, JSON.stringify(clean))
    }
  }

  private writeBack(viewing: JobRecord, touch: ExamTouch): void {
    let rows = examRows()
    let viewingExam = viewing.kind === 'exam' ? viewing.jobId : ''
    let targets = examWritebackTargets(rows, viewingExam)
    let rules = this.ports.rules()
    for (let row of rows) {
      let report = row.report
      if (report === null) {
        continue
      }
      let state = row.record.state
      if (targets.indexOf(row.record.jobId) >= 0) {
        if (touchExam(report, touch, rules)) {
          Writer.commit(row.record, JSON.stringify(report))
        }
      } else if (state === 'queued' || state === 'running') {
        if (subtractExamPart(report, touch)) {
          Writer.commit(row.record, JSON.stringify(report))
        }
      }
    }
  }
}

/** 本应用 cacheDir 的直接删除。不调用任何会删除应用数据的接口。 */
export class FsOwnCache implements OwnCache {
  private dir: string

  constructor(cacheDir: string) {
    this.dir = cacheDir
  }

  async clear(): Promise<number> {
    let names = fs.listFileSync(this.dir, { recursion: true })
    let cleared = 0
    for (let name of names) {
      let path = this.dir + (name.charAt(0) === '/' ? '' : '/') + name
      let size = 0
      try {
        let stat = fs.lstatSync(path)
        if (!stat.isFile()) {
          continue
        }
        size = stat.size
        fs.unlinkSync(path)
      } catch (err) {
        hilog.warn(DOMAIN, TAG, 'own cache file not removed')
        continue
      }
      cleared += size
    }
    return cleared
  }
}

function locate(jobId: string): Located | DispositionResult {
  let record = findRecord(jobId)
  if (record === null) {
    return refuse(NOT_SETTLED)
  }
  if (record.kind === 'duplicate' || record.kind === 'large-file') {
    return refuse(VIEW_ONLY)
  }
  if (record.state === 'queued' || record.state === 'running') {
    return refuse(NOT_SETTLED)
  }
  let text = Writer.readText(Writer.resultFileOf(record.jobId))
  if (text === null) {
    return refuse(NOT_SETTLED)
  }
  return new Located(record, text)
}

function findRecord(jobId: string): JobRecord | null {
  if (jobId.length === 0) {
    return null
  }
  let records = Writer.loadIndex()
  for (let record of records) {
    if (record.jobId === jobId) {
      return record
    }
  }
  return null
}

function refuse(message: string): DispositionResult {
  let result = new DispositionResult()
  result.message = message
  return result
}

function succeed(message: string): DispositionResult {
  let result = new DispositionResult()
  result.done = true
  result.message = message
  return result
}

function audit(record: JobRecord, action: string, target: string, result: string, succeeded: boolean): void {
  let line: AuditLine = { at: '', kind: record.kind, action: action, jobId: record.jobId, target: target,
    result: result }
  AuditLog.append(line, succeeded)
  if (!succeeded) {
    hilog.warn(DOMAIN, TAG, 'disposition %{public}s refused', action)
  }
}

function returnCode(err: Object): string {
  if (err instanceof CenterError) {
    let colon = err.raw.lastIndexOf(':')
    return colon >= 0 ? err.raw.substring(colon + 1) : err.raw
  }
  let code = (err as CenterError).code as Object
  return code === undefined || code === null ? 'error' : String(code)
}

/** 信誉和体检只处理风险、可疑或未知行。 */
function actionable(hit: ScanHit): boolean {
  let level = hit.verdict.level
  return hit.action === 'none' && (level === 'risk' || level === 'suspicious' || level === 'unknown')
}

function trustable(hit: ScanHit): boolean {
  let verdict = hit.verdict
  if (verdict.level !== 'suspicious' && verdict.level !== 'unknown') {
    return false
  }
  if (verdict.source === 'local-black' || NO_TRUST.indexOf(verdict.evidence) >= 0) {
    return false
  }
  let fp = hit.fingerprint
  if (fp.kind === 'file') {
    return canonicalCert(fp.sha256).length > 0
  }
  return canonicalCert(fp.certSha256).length > 0 && fp.certAlgo !== 'none'
}

function hitsOf(located: Located): ScanHit[] {
  if (located.record.kind === 'exam') {
    let exam = parseExam(located.text)
    return exam === null ? [] : exam.apps
  }
  let scan = parseScan(located.text)
  return scan === null ? [] : scan.hits
}

function findHit(hits: ScanHit[], kind: 'bundle' | 'file', id: string): ScanHit | null {
  if (id.length === 0) {
    return null
  }
  for (let hit of hits) {
    if (hit !== null && typeof hit === 'object' && hit.fingerprint !== null &&
      typeof hit.fingerprint === 'object' && hit.fingerprint.kind === kind && hit.fingerprint.id === id) {
      return hit
    }
  }
  return null
}

function findBundleRow(rows: Object[], bundleName: string): number {
  for (let i = 0; i < rows.length; i++) {
    let row = rows[i] as BundleRow
    if (row !== null && typeof row === 'object' && row.bundleName === bundleName && bundleName.length > 0) {
      return i
    }
  }
  return -1
}

function findCacheRow(rows: CacheRow[], bundleName: string): number {
  for (let i = 0; i < rows.length; i++) {
    if (rows[i].bundleName === bundleName && bundleName.length > 0) {
      return i
    }
  }
  return -1
}

function findFileHit(hits: FileHit[], uri: string): number {
  for (let i = 0; i < hits.length; i++) {
    let hit = hits[i]
    if (hit.uri === uri && uri.length > 0 && (hit.clazz === 'installer' || hit.clazz === 'residue')) {
      return i
    }
  }
  return -1
}

function markHit(hit: ScanHit, action: HitAction): void {
  hit.action = action
  if (action === 'quarantine') {
    hit.quarantined = true
  }
}

function decrementScan(scan: ScanReport, level: RiskLevel): void {
  if (level === 'risk') {
    scan.risk = Math.max(0, scan.risk - 1)
  } else if (level === 'suspicious') {
    scan.suspicious = Math.max(0, scan.suspicious - 1)
  } else if (level === 'unknown') {
    scan.unknown = Math.max(0, scan.unknown - 1)
  } else {
    scan.ok = Math.max(0, scan.ok - 1)
  }
}

function examRows(): ExamRow[] {
  let rows: ExamRow[] = []
  for (let record of Writer.loadIndex()) {
    if (record.kind !== 'exam') {
      continue
    }
    let text = Writer.readText(Writer.resultFileOf(record.jobId))
    rows.push(new ExamRow(record, text === null ? null : parseExam(text)))
  }
  return rows
}

/** 只在这份体检真正含有目标时改它。返回是否改过。 */
function touchExam(report: ExamReport, touch: ExamTouch, rules: RuleLoad): boolean {
  let changed = subtractExamPart(report, touch)
  if (touch.appsId.length === 0) {
    return changed
  }
  let hit = findHit(report.apps, touch.appsKind, touch.appsId)
  if (hit === null) {
    return changed
  }
  if (hit.action !== 'none') {
    return changed
  }
  let summary = report.summary
  let anomalyBefore = Anomaly.count([hit], rules)
  let sensitiveBefore = hit.fingerprint.kind === 'bundle' && hit.fingerprint.bundleName !== SELF &&
    hit.granted.some((permission: string): boolean => isSensitive(permission))
  let level = hit.verdict.level
  if (level === 'risk') {
    summary.riskApps = Math.max(0, summary.riskApps - 1)
  } else if (level === 'suspicious') {
    summary.suspiciousApps = Math.max(0, summary.suspiciousApps - 1)
  } else if (level === 'unknown') {
    summary.unknownApps = Math.max(0, summary.unknownApps - 1)
  } else {
    summary.okApps = Math.max(0, summary.okApps - 1)
  }
  if (anomalyBefore > 0) {
    summary.anomalyApps = Math.max(0, summary.anomalyApps - anomalyBefore)
  }
  if (sensitiveBefore) {
    summary.sensitiveApps = Math.max(0, summary.sensitiveApps - 1)
  }
  markHit(hit, touch.hitAction)
  settleExam(report)
  return true
}

function subtractExamPart(report: ExamReport, touch: ExamTouch): boolean {
  let summary = report.summary
  if (touch.partId.length === 0 || !(summary.parts instanceof Array)) {
    return false
  }
  let bytes = touch.partBytes
  if (bytes < 0) {
    bytes = partBytes(summary.parts, touch.partId, touch.partKind)
  }
  let next = subtractPart(summary.parts, touch.partId, touch.partKind, bytes)
  if (next === summary.parts) {
    return false
  }
  summary.parts = next
  summary.cleanableBytes = sumParts(next)
  return true
}

function partBytes(parts: CountedByte[], id: string, kind: 'cache' | 'installer'): number {
  for (let part of parts) {
    if (part.id === id && part.kind === kind) {
      return part.bytes
    }
  }
  return 0
}

function findItem(items: CheckItem[], id: string): CheckItem | null {
  for (let item of items) {
    if (item.id === id) {
      return item
    }
  }
  return null
}

function settleExam(report: ExamReport): void {
  let summary = report.summary
  let apps = findItem(report.items, APPS_ID)
  if (apps !== null && apps.status !== 'unsupported') {
    let status = examAppsStatus(apps.countsTowardState, report.appsComplete, summary.riskApps,
      summary.unknownApps, examAnyOffline(report.apps))
    if (status.status !== 'unsupported') {
      apps.status = status.status
      apps.detail = appendExamAppsDetail(status.detail, report.apps)
    }
  }
  let anomaly = findItem(report.items, ANOMALY_ID)
  if (anomaly !== null && anomaly.status !== 'unsupported') {
    anomaly.status = summary.anomalyApps > 0 ? 'attention' : 'ok'
  }
  let suspicious = findItem(report.items, SUSPICIOUS_ID)
  if (suspicious !== null) {
    suspicious.status = summary.suspiciousApps > 0 ? 'attention' : 'ok'
  }
  let advice = 0
  for (let item of report.items) {
    if (item.kind === 'advice' && item.status !== 'ok') {
      advice++
    }
  }
  report.advice = advice
  let state = stateOf(report.items)
  if (apps === null && state === 'clear') {
    state = 'incomplete'
  }
  report.state = state
}

function parseArray(text: string): Object[] {
  try {
    let parsed = JSON.parse(text) as Object[]
    return parsed instanceof Array ? parsed : []
  } catch (err) {
    return []
  }
}

function parseObject(text: string): Object | null {
  try {
    let parsed = JSON.parse(text) as Object
    return parsed !== null && typeof parsed === 'object' && !(parsed instanceof Array) ? parsed : null
  } catch (err) {
    return null
  }
}

function parseExam(text: string): ExamReport | null {
  let parsed = parseObject(text) as ExamReport | null
  if (parsed === null || !(parsed.items instanceof Array) || !(parsed.apps instanceof Array) ||
    parsed.summary === null || typeof parsed.summary !== 'object') {
    return null
  }
  return parsed
}

function parseScan(text: string): ScanReport | null {
  let parsed = parseObject(text) as ScanReport | null
  if (parsed === null || !(parsed.hits instanceof Array) || typeof parsed.risk !== 'number') {
    return null
  }
  return parsed
}

function parseClean(text: string): CleanReport | null {
  let parsed = parseObject(text) as CleanReport | null
  if (parsed === null || !(parsed.caches instanceof Array) || !(parsed.hits instanceof Array)) {
    return null
  }
  return parsed
}
