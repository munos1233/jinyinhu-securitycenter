import { hilog } from '@kit.PerformanceAnalysisKit'
import { Anomaly } from '../center/Anomaly'
import { nowIso } from '../center/Clock'
import { groupOf } from '../center/SensitiveCatalog'
import type {
  AccessFacts, AccessRevoke, BundleRow, ExamReport, Gate, JobRecord, PermissionFact, ScanHit, ScanReport, UseFact
} from '../center/CenterTypes'
import { grantChangesFromFacts, rejudgeGrantedResults } from '../engine/AppJudge'
import type { GrantedResultStore, ScanCandidate } from '../engine/AppJudge'
import { RulePack } from '../engine/RulePack'
import type { HomeCandidate } from '../feature/exam/ExamState'
import { AuditLog } from './AuditLog'
import { Writer } from './Writer'

const DOMAIN: number = 0x4A59
const TAG: string = 'Center'
const CANNOT: string = '无法关闭此权限'
const UNREADABLE: string = '无法读取授权'
const NO_RECORD: string = '没有该应用的记录'
const NO_EXAM: string = '没有该次体检记录'
const GROUPS: string[] = ['位置', '相机', '麦克风', '通讯录', '日历', '短信', '电话', '媒体', '其它', 'sensitive']

export interface PermissionCensus {
  list(): Promise<BundleRow[]>
}

export interface PermissionGate {
  grants(): Gate
  revoke(): Gate
  usedStats(): Gate
  stale(): boolean
}

export interface PermissionAccess extends AccessFacts, AccessRevoke {
  canRevoke(tokenId: number, permission: string): Promise<boolean>
}

export interface PermissionActionPorts {
  census: PermissionCensus
  access: PermissionAccess
  gate: PermissionGate
  userGrant(permission: string): Promise<boolean>
}

export class PermissionActionResult {
  done: boolean = false
  message: string = ''
}

class GroupCount {
  group: string = ''
  count: number = 0
  known: boolean = false
}

class PermissionFile {
  facts: PermissionFact[] = []
  uses: UseFact[] = []
  counts: GroupCount[] = []
  bundlesAvailable: boolean = false
  usesAvailable: boolean = false
}

class ResultStore implements GrantedResultStore {
  exclusive(work: () => void): void {
    Writer.exclusive(work)
  }

  exams(): HomeCandidate[] {
    let result: HomeCandidate[] = []
    for (let record of Writer.loadIndex()) {
      if (record.kind === 'exam') {
        result.push({ record: record, report: readExam(record) })
      }
    }
    return result
  }

  scans(): ScanCandidate[] {
    let result: ScanCandidate[] = []
    for (let record of Writer.loadIndex()) {
      if (record.kind === 'malware') {
        result.push({ record: record, report: readScan(record) })
      }
    }
    return result
  }

  saveExam(record: JobRecord, report: ExamReport): void {
    Writer.commit(record, JSON.stringify(report))
  }

  saveScan(record: JobRecord, report: ScanReport): void {
    Writer.commit(record, JSON.stringify(report))
  }
}

/** 页面经此服务读取当前授权。撤权永远重新读 token，不采用结果文件中的旧值。 */
export class PermissionActions {
  private ports: PermissionActionPorts
  private labelOf: ((permission: string) => Promise<string>) | null
  private pending: Set<string> = new Set<string>()

  constructor(ports: PermissionActionPorts, labelOf: ((permission: string) => Promise<string>) | null = null) {
    this.ports = ports
    this.labelOf = labelOf
  }

  revokeReady(): boolean {
    return this.ports.gate.revoke().status === 'ready'
  }

  grantsReady(): boolean {
    return this.ports.gate.grants().status === 'ready'
  }

  usesReady(): boolean {
    return this.ports.gate.usedStats().status === 'ready'
  }

  stale(): boolean {
    return this.ports.gate.stale()
  }

  async recentUses(): Promise<UseFact[]> {
    return this.usesReady() ? await this.ports.access.recentUses() : []
  }

  async exists(bundleName: string): Promise<boolean> {
    try {
      return (await this.ports.census.list()).some((row: BundleRow): boolean => row.bundleName === bundleName)
    } catch (err) {
      return false
    }
  }

  async canRevoke(fact: PermissionFact): Promise<boolean> {
    if (fact.tokenId <= 0 || fact.grant !== 'granted' || fact.fixed ||
      !this.grantsReady() || !this.revokeReady()) {
      return false
    }
    try {
      let allowed = await this.ports.access.canRevoke(fact.tokenId, fact.permission)
      return allowed && this.grantsReady() && this.revokeReady()
    } catch (err) {
      return false
    }
  }

  async userGrant(permission: string): Promise<boolean> {
    try {
      return await this.ports.userGrant(permission)
    } catch (err) {
      return false
    }
  }

  async current(bundleName: string, names: string[]): Promise<PermissionFact[]> {
    let bundle: BundleRow = fallback(bundleName, names)
    try {
      let found = (await this.ports.census.list()).find((row: BundleRow): boolean => row.bundleName === bundleName)
      if (found !== undefined) {
        bundle = found
      }
    } catch (err) {
      // A known snapshot name can still be queried by bundle name when enumeration is unavailable.
    }
    let facts: PermissionFact[]
    try {
      facts = await this.ports.access.facts([bundle])
    } catch (err) {
      return []
    }
    let result: PermissionFact[] = []
    for (let fact of facts) {
      if (fact.bundleName !== bundleName) {
        continue
      }
      let copy = copyFact(fact)
      if (!this.grantsReady()) {
        copy.grant = 'unknown'
        copy.fixed = false
      }
      if (this.labelOf !== null) {
        try {
          let label = await this.labelOf(copy.permission)
          if (label.length > 0) {
            copy.label = label
          }
        } catch (err) {
        }
      }
      result.push(copy)
    }
    return result
  }

  /** 只对本次有结果的包重新读取完整声明，防止 limitFacts 截断被误当成已撤权。 */
  async reconcile(viewingJobId: string, focus: string, facts: PermissionFact[]): Promise<void> {
    if (!this.grantsReady()) {
      return
    }
    let names = new Set<string>(facts.map((fact: PermissionFact): string => fact.bundleName))
    let bundles: BundleRow[]
    try {
      bundles = (await this.ports.census.list()).filter((row: BundleRow): boolean => names.has(row.bundleName))
      let full = await this.ports.access.facts(bundles)
      if (!this.grantsReady()) {
        return
      }
      let complete: PermissionFact[] = []
      for (let bundle of bundles) {
        let rows = full.filter((fact: PermissionFact): boolean => fact.bundleName === bundle.bundleName)
        if (bundle.declaredPermissions.every((permission: string): boolean => rows.some(
          (fact: PermissionFact): boolean => fact.permission === permission && fact.tokenId > 0 &&
            fact.grant !== 'unknown')) && rows.length > 0 && rows.every(
          (fact: PermissionFact): boolean => fact.tokenId > 0 && fact.grant !== 'unknown')) {
          complete.push(...rows)
        }
      }
      rejudgeGrantedResults(new ResultStore(), viewingJobId, focus, grantChangesFromFacts(complete), RulePack.active())
    } catch (err) {
      hilog.warn(DOMAIN, TAG, 'permission refresh could not read complete grants')
    }
  }

  /** No-history bundle routes require an actual current declaration, never the names fallback. */
  private async liveTargetFacts(bundleName: string, permission: string): Promise<PermissionFact[] | null> {
    try {
      let bundle = (await this.ports.census.list()).find((row: BundleRow): boolean =>
        row.bundleName === bundleName && row.declaredPermissions.indexOf(permission) >= 0)
      if (bundle === undefined) {
        return null
      }
      let declaredPermissions = bundle.declaredPermissions
      let facts = await this.ports.access.facts([bundle])
      let target = facts.find((fact: PermissionFact): boolean =>
        fact.bundleName === bundleName && fact.permission === permission && fact.declared)
      return target === undefined ? null : facts.filter((fact: PermissionFact): boolean =>
        fact.bundleName === bundleName && declaredPermissions.indexOf(fact.permission) >= 0)
    } catch (err) {
      return null
    }
  }

  async revoke(jobId: string, bundleName: string, permission: string, focus: string): Promise<PermissionActionResult> {
    let key = bundleName + '\n' + permission
    if (this.pending.has(key)) {
      return outcome(false, CANNOT)
    }
    this.pending.add(key)
    try {
      if (!this.revokeReady() || !await this.userGrant(permission)) {
        return outcome(false, CANNOT)
      }
      let recorded = allowedTarget(jobId, focus, bundleName, permission)
      let live = !recorded && focus === bundleName ? await this.liveTargetFacts(bundleName, permission) : null
      if (!recorded && live === null) {
        return outcome(false, focus.startsWith('anomaly:') ? NO_EXAM : NO_RECORD)
      }
      let facts = live === null ? await this.current(bundleName, [permission]) : live
      let current = facts.find((fact: PermissionFact): boolean => fact.permission === permission)
      if (current === undefined || current.tokenId <= 0) {
        return outcome(false, UNREADABLE)
      }
      if (!this.revokeReady() || !this.grantsReady() || current.grant === 'unknown') {
        return outcome(false, CANNOT)
      }
      if (current.fixed) {
        return outcome(false, '受系统限制，无法关闭')
      }
      if (current.grant !== 'granted') {
        return outcome(false, '已关闭')
      }
      if (!await this.canRevoke(current)) {
        return outcome(false, CANNOT)
      }
      // The target may have been replaced while the fresh grant read was pending.
      if (live === null && !allowedTarget(jobId, focus, bundleName, permission)) {
        return outcome(false, NO_RECORD)
      }
      try {
        await this.ports.access.revoke(current.tokenId, permission)
      } catch (err) {
        let message = '关闭权限失败，返回码 ' + returnCode(err as Object)
        Writer.exclusive(() => {
          let record = permissionRecord(jobId)
          let body = record === null ? null : readPermission(record)
          if (record !== null && body !== null) {
            record.summary = message
            Writer.commit(record, JSON.stringify(body))
          }
          audit(jobId, bundleName, permission, message, false)
        })
        return outcome(false, message)
      }
      Writer.exclusive(() => {
        updatePermission(jobId, bundleName, permission, facts)
        rejudgeGrantedResults(new ResultStore(), jobId, focus,
          [{ bundleName: bundleName, mode: 'remove', permissions: [permission] }], RulePack.active())
        audit(jobId, bundleName, permission, '成功', true)
      })
      return outcome(true, '已关闭')
    } finally {
      this.pending.delete(key)
    }
  }
}

function outcome(done: boolean, message: string): PermissionActionResult {
  let result = new PermissionActionResult()
  result.done = done
  result.message = message
  return result
}

function fallback(bundleName: string, names: string[]): BundleRow {
  return { bundleName: bundleName, version: '', versionCode: 0, certSha256: '', certAlgo: 'none',
    declaredPermissions: Array.from(new Set<string>(names)), source: 'unknown',
    verdict: { level: 'unknown', source: 'system', reason: '', evidence: '', cloud: 'unchecked' } }
}

function copyFact(fact: PermissionFact): PermissionFact {
  return { bundleName: fact.bundleName, displayName: fact.displayName, permission: fact.permission,
    label: fact.label, group: fact.group, sensitive: fact.sensitive, declared: fact.declared,
    grant: fact.grant, fixed: fact.fixed, tokenId: fact.tokenId, source: fact.source }
}

function settled(record: JobRecord): boolean {
  return record.state !== 'queued' && record.state !== 'running'
}

function permissionRecord(jobId: string): JobRecord | null {
  return Writer.loadIndex().find((record: JobRecord): boolean =>
    record.jobId === jobId && record.kind === 'permission' && settled(record)) || null
}

function readPermission(record: JobRecord): PermissionFile | null {
  try {
    let body = JSON.parse(Writer.readText(Writer.resultFileOf(record.jobId)) || '') as PermissionFile
    return body !== null && body.facts instanceof Array && body.uses instanceof Array ? body : null
  } catch (err) {
    return null
  }
}

function readExam(record: JobRecord): ExamReport | null {
  try {
    let body = JSON.parse(Writer.readText(Writer.resultFileOf(record.jobId)) || '') as ExamReport
    return body !== null && body.apps instanceof Array && body.items instanceof Array &&
      body.summary !== null && typeof body.summary === 'object' ? body : null
  } catch (err) {
    return null
  }
}

function readScan(record: JobRecord): ScanReport | null {
  try {
    let body = JSON.parse(Writer.readText(Writer.resultFileOf(record.jobId)) || '') as ScanReport
    return body !== null && body.hits instanceof Array ? body : null
  } catch (err) {
    return null
  }
}

function allowedTarget(jobId: string, focus: string, bundleName: string, permission: string): boolean {
  let records = Writer.loadIndex()
  if (focus.startsWith('anomaly:')) {
    let record = records.find((row: JobRecord): boolean => row.jobId === focus.substring(8) &&
      row.kind === 'exam' && settled(row))
    let report = record === undefined ? null : readExam(record)
    return report !== null && report.apps.some((hit: ScanHit): boolean => hit.fingerprint.bundleName === bundleName &&
      hit.granted.indexOf(permission) >= 0 && Anomaly.count([hit], RulePack.active()) > 0)
  }
  if (focus.length > 0 && GROUPS.indexOf(focus) < 0 && focus !== bundleName) {
    return false
  }
  let record = permissionRecord(jobId)
  let report = record === null ? null : readPermission(record)
  if (report !== null && report.facts.some((fact: PermissionFact): boolean =>
    fact.bundleName === bundleName && fact.permission === permission)) {
    return true
  }
  // A bundle route can open before its first permission job. Accept only names
  // actually present in a recent settled scan, not arbitrary caller-supplied names.
  if (focus !== bundleName) {
    return false
  }
  for (let kind of ['exam', 'malware']) {
    let latest = records.filter((row: JobRecord): boolean => row.kind === kind && row.state === 'done')
      .sort((a: JobRecord, b: JobRecord): number => b.seq - a.seq)[0]
    if (latest === undefined) {
      continue
    }
    let hits = kind === 'exam' ? readExam(latest)?.apps : readScan(latest)?.hits
    if (hits !== undefined && hits.some((hit: ScanHit): boolean => hit.fingerprint.kind === 'bundle' &&
      hit.fingerprint.bundleName === bundleName && hit.action === 'none' && hit.granted.indexOf(permission) >= 0)) {
      return true
    }
  }
  return false
}

function updatePermission(jobId: string, bundleName: string, permission: string, current: PermissionFact[]): void {
  let record = permissionRecord(jobId)
  let body = record === null ? null : readPermission(record)
  if (record === null || body === null) {
    return
  }
  let found = body.facts.find((fact: PermissionFact): boolean =>
    fact.bundleName === bundleName && fact.permission === permission)
  if (found === undefined) {
    return
  }
  let wasGranted = found.grant === 'granted'
  found.grant = 'denied'
  let group = groupOf(permission)
  let remaining = current.some((fact: PermissionFact): boolean =>
    fact.permission !== permission && fact.grant === 'granted' && groupOf(fact.permission) === group)
  if (wasGranted && !remaining && body.counts instanceof Array) {
    let count = body.counts.find((row: GroupCount): boolean => row.group === group)
    if (count !== undefined) {
      count.count = Math.max(0, count.count - 1)
    }
  }
  record.summary = '已关闭'
  Writer.commit(record, JSON.stringify(body))
}

function audit(jobId: string, bundleName: string, permission: string, result: string, succeeded: boolean): void {
  AuditLog.append({ at: nowIso(), kind: 'permission', action: '关闭权限', jobId: jobId,
    target: bundleName + ':' + permission, result: result }, succeeded)
}

function returnCode(error: Object): string {
  let coded = error as ErrorWithCode
  if (coded.raw !== undefined && coded.raw.length > 0) {
    return coded.raw
  }
  return coded.code === undefined ? 'error' : String(coded.code)
}

interface ErrorWithCode {
  code: number | string
  raw: string
}
