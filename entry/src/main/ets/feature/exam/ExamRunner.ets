import fs from '@ohos.file.fs'
import { hilog } from '@kit.PerformanceAnalysisKit'
import { Anomaly } from '../../center/Anomaly'
import { CenterError } from '../../center/CenterError'
import { cloudBatch, heavyBudgetMs, heavyMaxBytes, heavyMaxFiles, listMax } from '../../center/CenterLimits'
import { sumParts } from '../../center/CleanMath'
import { isSensitive } from '../../center/SensitiveCatalog'
import type {
  AccessFacts, ActionRef, AppsItemStatus, BundleRow, CheckGroup, CheckItem, CheckKind, CheckStatus, CountedByte,
  ExamReport, ExamState, ExamSummary, FileGrant, Fingerprint, PermissionFact, ProtectFact, RiskLevel, ScanHit,
  TrustEntry, VerdictSource
} from '../../center/CenterTypes'
import type { JudgeInput, JudgeResult } from '../../engine/AppJudge'
import { listInstallers } from '../../engine/InstallerScan'
import type { InstallerScanResult } from '../../engine/InstallerScan'
import { RulePack } from '../../engine/RulePack'
import type { RuleLoad } from '../../engine/RulePack'
import type { ExamContext } from '../../task/Contexts'
import { RunEnd } from '../../task/RunnerRegistry'
import type { ResultHand } from '../../task/RunnerRegistry'
import { appendExamAppsDetail, examAnyOffline, examAppsStatus, stateOf } from './ExamState'

const DOMAIN: number = 0x4A59
const TAG: string = 'Center'
const SELF: string = 'com.jinyinhu.securitycenter'

const STEP_PROTECT: string = '正在检查系统安全'
const STEP_APPS: string = '正在扫描应用'
const STEP_CLEAN: string = '正在计算可清理空间'
const STEP_PERMISSION: string = '正在检查应用权限'

const AT_LIMIT: string = '已达本次扫描上限'
const TRUNCATED: string = '结果较多，仅显示部分'
const OWN_CACHE_ONLY: string = '仅统计了本应用缓存'
const NO_FILE_GRANT: string = '目录未授权，安装包未计入'
const INSTALLERS_PARTIAL: string = '部分安装包未统计'
const NO_BUNDLES: string = '无法获取应用列表'
const NO_GRANTS: string = '无法读取授权状态'
const UNREADABLE: string = '暂不支持'
const RULES_MISSING: string = '本地规则不可用'
const CLOUD_UNCONFIGURED: string = '未联网，云服务未配置'
const CLOUD_VERSION_OFFLINE: string = '未联网，无法比对云端规则版本'

const PURE_MODE_ID: string = 'exam.protect.pure-mode'
const LOCKDOWN_ID: string = 'exam.protect.lockdown'
const EL5_ID: string = 'exam.protect.el5'
const APPS_ID: string = 'exam.malware.apps'
const SUSPICIOUS_ID: string = 'exam.malware.suspicious'
const RULES_ID: string = 'exam.rules.version'
const ANOMALY_ID: string = 'exam.permission.anomaly'
const SIDELOAD_ID: string = 'exam.permission.sideload'

/**
 * ExamContext 里没有的两样由组合根给出：信任区快照，以及缓存端口不可用时本应用 cacheDir 的字节。
 * 规则用 RulePack.active()，安装包只经 InstallerScan.listInstallers。
 */
export interface ExamSources {
  trust(): TrustEntry[]
  ownCache(): Promise<number>
}

/** AccessPort 同时实现 GrantLookup。ready() 与 SystemGate.grants() 一致。 */
interface GrantsGate {
  ready(): boolean
}

class Action implements ActionRef {
  route: string = ''
  params: string = ''
}

class Item implements CheckItem {
  id: string = ''
  title: string = ''
  group: CheckGroup = 'protect'
  status: CheckStatus = 'unsupported'
  kind: CheckKind = 'state'
  source: VerdictSource = 'system'
  detail: string = ''
  action: ActionRef = new Action()
  countsTowardState: boolean = false
}

class Summary implements ExamSummary {
  riskApps: number = 0
  suspiciousApps: number = 0
  unknownApps: number = 0
  okApps: number = 0
  parts: CountedByte[] = []
  cleanableBytes: number = 0
  cleanableKnown: boolean = false
  cleanableNote: string = ''
  sensitiveApps: number = 0
  sensitiveKnown: boolean = false
  anomalyApps: number = 0
}

class Report implements ExamReport {
  jobId: string = ''
  state: ExamState = 'incomplete'
  items: CheckItem[] = []
  apps: ScanHit[] = []
  appsComplete: boolean = false
  summary: ExamSummary = new Summary()
  skipped: number = 0
  advice: number = 0
  generatedAt: string = ''
}

class Part implements CountedByte {
  id: string = ''
  bytes: number = 0
  kind: 'cache' | 'installer' = 'cache'
}

class Input implements JudgeInput {
  fingerprint: Fingerprint
  declared: string[]
  granted: string[]
  grantsReady: boolean

  constructor(fingerprint: Fingerprint, declared: string[], granted: string[], grantsReady: boolean) {
    this.fingerprint = fingerprint
    this.declared = declared
    this.granted = granted
    this.grantsReady = grantsReady
  }
}

class Finger implements Fingerprint {
  kind: 'bundle' | 'file' = 'bundle'
  id: string = ''
  bundleName: string = ''
  version: string = ''
  versionCode: number = 0
  certSha256: string = ''
  certAlgo: 'platform-fingerprint' | 'sha256-of-cert-bytes' | 'none' = 'none'
  sha256: string = ''
  size: number = 0
  label: string = ''
}

class LevelCounts {
  risk: number = 0
  suspicious: number = 0
  unknown: number = 0
  ok: number = 0
}

/** 应用这一步留给后面几步的材料。snapshot 是截断前的全部已判定行。 */
class AppsStep {
  bundlesReady: boolean = false
  grantsReady: boolean = false
  rows: BundleRow[] = []
  granted: Map<string, string[]> = new Map<string, string[]>()
  snapshot: ScanHit[] = []
  judged: number = 0
  notes: string[] = []
}

export class ExamRunner {
  private sources: ExamSources

  constructor(sources: ExamSources) {
    this.sources = sources
  }

  /** 只读：不隔离、不卸载、不清缓存、不关闭权限、不改信任区。 */
  async run(ctx: ExamContext, hand: ResultHand): Promise<RunEnd> {
    let report = new Report()
    report.jobId = ctx.base.job.jobId
    report.generatedAt = ctx.base.clock.nowIso()
    let end = new RunEnd()
    let save = (): void => {
      refresh(report)
      hand.save(report)
    }

    ctx.base.report(0, 0, STEP_PROTECT)
    await this.protect(ctx, report)
    save()
    if (ctx.base.cancel.cancelled()) {
      return end
    }

    ctx.base.report(0, 0, STEP_APPS)
    let rules = RulePack.active()
    let step = await this.apps(ctx, report, rules, save)
    end.itemCount = step.judged
    end.riskCount = report.summary.riskApps
    end.summary = joinWith(step.notes, '、')
    if (ctx.base.cancel.cancelled()) {
      save()
      return end
    }
    report.items.push(rulesItem(rules, step.snapshot))
    save()

    ctx.base.report(step.judged, step.rows.length, STEP_CLEAN)
    await this.cleanable(ctx, report, step)
    save()
    if (ctx.base.cancel.cancelled()) {
      return end
    }

    ctx.base.report(step.judged, step.rows.length, STEP_PERMISSION)
    this.permission(report, step, rules)
    save()
    return end
  }

  private async protect(ctx: ExamContext, report: Report): Promise<void> {
    report.items.push(protectItem(PURE_MODE_ID, '纯净模式', await readFact(() => ctx.posture.pureMode())))
    report.items.push(protectItem(LOCKDOWN_ID, 'lockdown', await readFact(() => ctx.posture.lockdown())))
    report.items.push(protectItem(EL5_ID, 'el5', await readFact(() => ctx.posture.el5())))
  }

  private async apps(ctx: ExamContext, report: Report, rules: RuleLoad, save: () => void): Promise<AppsStep> {
    let step = new AppsStep()
    let jobId = report.jobId
    try {
      step.rows = await ctx.census.list()
      step.bundlesReady = true
    } catch (err) {
      rethrowCancel(err as Object)
      hilog.warn(DOMAIN, TAG, 'exam census unavailable: %{public}s', reasonOf(err as Object))
    }
    if (!step.bundlesReady) {
      report.items.push(appsItem(examAppsStatus(false, false, 0, 0, false), jobId))
      let suspicious = suspiciousItem(0, jobId)
      suspicious.status = 'unsupported'
      suspicious.detail = NO_BUNDLES
      report.items.push(suspicious)
      return step
    }

    let facts: PermissionFact[] = []
    let factsRead = false
    try {
      facts = await ctx.access.facts(step.rows)
      factsRead = true
    } catch (err) {
      rethrowCancel(err as Object)
      hilog.warn(DOMAIN, TAG, 'exam grants unreadable: %{public}s', reasonOf(err as Object))
    }
    step.grantsReady = factsRead && grantsReady(ctx.access, facts)
    let labels = new Map<string, string>()
    for (let fact of facts) {
      if (fact.displayName.length > 0) {
        labels.set(fact.bundleName, fact.displayName)
      }
      if (step.grantsReady && fact.grant === 'granted') {
        let names = step.granted.get(fact.bundleName)
        if (names === undefined) {
          names = []
          step.granted.set(fact.bundleName, names)
        }
        if (names.indexOf(fact.permission) < 0) {
          names.push(fact.permission)
        }
      }
    }
    let inputs: JudgeInput[] = []
    for (let row of step.rows) {
      let label = labels.get(row.bundleName)
      let granted = step.granted.get(row.bundleName)
      inputs.push(new Input(fingerprintOf(row, label === undefined ? row.bundleName : label),
        row.declaredPermissions.slice(), granted === undefined ? [] : granted.slice(), step.grantsReady))
    }

    let started = Date.now()
    let bytes = 0
    let sinceSave = 0
    let stopped = (): boolean => ctx.base.cancel.cancelled() || step.judged >= heavyMaxFiles ||
      bytes >= heavyMaxBytes || Date.now() - started >= heavyBudgetMs
    let summary = report.summary
    let onHit = (hit: ScanHit): void => {
      step.judged++
      bytes += hit.fingerprint.size
      report.apps.push(hit)
      addLevel(summary, hit.verdict.level)
      ctx.base.report(step.judged, step.rows.length, STEP_APPS)
      sinceSave++
      if (hit.verdict.level === 'risk' || hit.verdict.level === 'suspicious' || sinceSave >= cloudBatch) {
        sinceSave = 0
        save()
      }
    }
    let result: JudgeResult | null = null
    try {
      result = await ctx.judge.judge(inputs, rules, this.trust(), ctx.base.cancel, stopped, onHit)
    } catch (err) {
      rethrowCancel(err as Object)
      hilog.error(DOMAIN, TAG, 'exam app judge failed: %{public}s', reasonOf(err as Object))
    }
    step.snapshot = report.apps.slice()
    if (ctx.base.cancel.cancelled()) {
      return step
    }

    let counted = countLevels(step.snapshot)
    if (counted.risk !== summary.riskApps || counted.suspicious !== summary.suspiciousApps ||
      counted.unknown !== summary.unknownApps || counted.ok !== summary.okApps) {
      hilog.error(DOMAIN, TAG, 'exam app counts rewritten from judged rows')
      summary.riskApps = counted.risk
      summary.suspiciousApps = counted.suspicious
      summary.unknownApps = counted.unknown
      summary.okApps = counted.ok
    }
    let atLimit = result !== null && !result.complete
    let dropped = truncate(report)
    if (atLimit) {
      step.notes.push(AT_LIMIT)
    }
    if (dropped) {
      step.notes.push(TRUNCATED)
    }
    report.appsComplete = result !== null && !atLimit && !dropped

    let status = examAppsStatus(true, report.appsComplete, summary.riskApps, summary.unknownApps,
      examAnyOffline(step.snapshot))
    let item = appsItem(status, jobId)
    item.detail = appendExamAppsDetail(item.detail, step.snapshot)
    report.items.push(item)
    report.items.push(suspiciousItem(summary.suspiciousApps, jobId))
    return step
  }

  private async cleanable(ctx: ExamContext, report: Report, step: AppsStep): Promise<void> {
    let summary = report.summary
    let parts: CountedByte[] = []
    let notes: string[] = []
    let cacheMeasured = false
    let installersCounted = false
    try {
      let portUsable = step.bundlesReady
      if (portUsable) {
        for (let row of step.rows) {
          if (ctx.base.cancel.cancelled()) {
            break
          }
          try {
            let bytes = await ctx.cache.stats(row.bundleName)
            cacheMeasured = true
            if (bytes > 0) {
              parts.push(part(row.bundleName, bytes, 'cache'))
            }
          } catch (err) {
            let failure = err as Object
            rethrowCancel(failure)
            if (failure instanceof CenterError && failure.code === 'unsupported') {
              portUsable = false
              break
            }
            hilog.warn(DOMAIN, TAG, 'exam cache stats %{public}s: %{public}s', row.bundleName, reasonOf(failure))
          }
        }
      }
      if (!portUsable) {
        parts = []
        cacheMeasured = false
        try {
          let own = await this.sources.ownCache()
          cacheMeasured = true
          notes.push(OWN_CACHE_ONLY)
          if (own > 0) {
            parts.push(part(SELF, own, 'cache'))
          }
        } catch (err) {
          hilog.warn(DOMAIN, TAG, 'exam own cache unreadable: %{public}s', reasonOf(err as Object))
        }
      }

      let grants = ctx.files.persisted().filter((grant: FileGrant): boolean => grant.persisted === true)
      if (grants.length === 0) {
        notes.push(NO_FILE_GRANT)
      } else if (!ctx.base.cancel.cancelled()) {
        let installed = step.rows.map((row: BundleRow): string => row.bundleName)
        let scan: InstallerScanResult = listInstallers(ctx.files, ctx.open, installed,
          (): boolean => ctx.base.cancel.cancelled(), heavyMaxFiles, heavyMaxBytes, heavyBudgetMs)
        installersCounted = true
        for (let hit of scan.hits) {
          parts.push(part(hit.uri, hit.size, 'installer'))
        }
        if (scan.stoppedByLimit === true) {
          notes.push(INSTALLERS_PARTIAL)
        }
      }
    } catch (err) {
      rethrowCancel(err as Object)
      hilog.error(DOMAIN, TAG, 'exam cleanable failed: %{public}s', reasonOf(err as Object))
    }

    if (!cacheMeasured && !installersCounted && parts.length === 0) {
      summary.parts = []
      summary.cleanableBytes = 0
      summary.cleanableKnown = false
      summary.cleanableNote = ''
      return
    }
    summary.parts = parts
    summary.cleanableBytes = sumParts(parts)
    summary.cleanableKnown = true
    summary.cleanableNote = joinWith(notes, '、')
  }

  private permission(report: Report, step: AppsStep, rules: RuleLoad): void {
    let summary = report.summary
    let anomaly = adviceItem(ANOMALY_ID, '权限异常', 'permission', 'local-rule')
    anomaly.action.route = 'permission'
    anomaly.action.params = 'anomaly:' + report.jobId
    if (!step.bundlesReady || !step.grantsReady) {
      summary.sensitiveKnown = false
      summary.sensitiveApps = 0
      summary.anomalyApps = 0
      anomaly.status = 'unsupported'
      anomaly.detail = NO_GRANTS
      report.items.push(anomaly)
      return
    }
    let sensitive = 0
    let sideload = 0
    for (let row of step.rows) {
      let granted = step.granted.get(row.bundleName)
      if (row.bundleName === SELF || granted === undefined ||
        !granted.some((name: string): boolean => isSensitive(name))) {
        continue
      }
      sensitive++
      if (row.source === 'sideload') {
        sideload++
      }
    }
    summary.sensitiveApps = sensitive
    summary.sensitiveKnown = true
    summary.anomalyApps = Anomaly.count(step.snapshot, rules)
    anomaly.status = summary.anomalyApps > 0 ? 'attention' : 'ok'
    anomaly.detail = summary.anomalyApps > 0 ? '有 ' + summary.anomalyApps + ' 个应用同时允许了风险权限组合' : ''
    report.items.push(anomaly)
    if (sideload > 0) {
      let item = adviceItem(SIDELOAD_ID, '侧载应用', 'permission', 'system')
      item.status = 'attention'
      item.detail = '有 ' + sideload + ' 个侧载应用持有敏感权限'
      item.action.route = 'permission'
      item.action.params = 'sensitive'
      report.items.push(item)
    }
  }

  private trust(): TrustEntry[] {
    try {
      return this.sources.trust()
    } catch (err) {
      hilog.warn(DOMAIN, TAG, 'exam trust unreadable: %{public}s', reasonOf(err as Object))
      return []
    }
  }
}

/** 缓存端口不可用时，本应用 cacheDir 的文件字节之和。不跟随符号链接。 */
export function cacheDirBytes(dir: string): number {
  let total = 0
  let stat = fs.lstatSync(dir)
  if (stat.isSymbolicLink()) {
    return 0
  }
  if (!stat.isDirectory()) {
    return stat.size
  }
  let names = fs.listFileSync(dir)
  for (let name of names) {
    if (name === '.' || name === '..') {
      continue
    }
    total += cacheDirBytes(dir.replace(/\/$/, '') + '/' + name)
  }
  return total
}

async function readFact(read: () => Promise<ProtectFact>): Promise<ProtectFact | null> {
  try {
    return await read()
  } catch (err) {
    rethrowCancel(err as Object)
    hilog.warn(DOMAIN, TAG, 'exam posture unreadable: %{public}s', reasonOf(err as Object))
    return null
  }
}

function protectItem(id: string, title: string, fact: ProtectFact | null): Item {
  let item = new Item()
  item.id = id
  item.title = title
  item.group = 'protect'
  item.kind = 'state'
  item.source = 'system'
  item.action.route = 'protect'
  item.action.params = ''
  if (fact === null || (fact.status !== 'ok' && fact.status !== 'risk')) {
    item.status = 'unsupported'
    item.detail = fact === null || fact.detail.length === 0 ? UNREADABLE : fact.detail
    item.countsTowardState = false
    return item
  }
  item.status = fact.status
  item.detail = fact.detail
  item.countsTowardState = true
  return item
}

function appsItem(status: AppsItemStatus, jobId: string): Item {
  let item = new Item()
  item.id = APPS_ID
  item.title = '应用信誉'
  item.group = 'threat'
  item.kind = 'state'
  item.source = 'local-rule'
  item.status = status.status
  item.countsTowardState = status.countsTowardState
  item.detail = status.detail
  item.action.route = 'malware'
  item.action.params = jobId
  return item
}

function suspiciousItem(count: number, jobId: string): Item {
  let item = adviceItem(SUSPICIOUS_ID, '可疑应用', 'threat', 'local-rule')
  item.status = count > 0 ? 'attention' : 'ok'
  item.detail = count > 0 ? '发现 ' + count + ' 个可疑应用' : ''
  item.action.route = 'malware'
  item.action.params = jobId
  return item
}

function adviceItem(id: string, title: string, group: CheckGroup, source: VerdictSource): Item {
  let item = new Item()
  item.id = id
  item.title = title
  item.group = group
  item.kind = 'advice'
  item.source = source
  item.countsTowardState = false
  return item
}

/** 第 6、7 节：N、M 两句不改状态；损坏且仍有上一份时保持建议；没有任何一份时改成计入状态的 risk。 */
function rulesItem(rules: RuleLoad, judged: ScanHit[]): Item {
  let item = adviceItem(RULES_ID, '规则版本', 'rules', 'local-rule')
  item.action.route = 'protect'
  item.action.params = 'rules'
  let notes: string[] = []
  let ignored: string[] = []
  if (rules.unavailable > 0) {
    ignored.push('有 ' + rules.unavailable + ' 条规则暂不可用')
  }
  if (rules.disabled > 0) {
    ignored.push('有 ' + rules.disabled + ' 条规则未启用')
  }
  if (rules.rulesVersion === 'none') {
    item.kind = 'state'
    item.status = 'risk'
    item.countsTowardState = true
    notes.push(RULES_MISSING)
  } else {
    notes.push('本地规则 ' + rules.rulesVersion)
    if (rules.notice.length > 0) {
      item.status = 'attention'
      notes.push(rules.notice)
    } else if (cloudFailed(judged)) {
      item.status = 'unknown'
      notes.push(CLOUD_VERSION_OFFLINE)
    } else {
      item.status = 'ok'
    }
  }
  if (ignored.length > 0) {
    notes.push(joinWith(ignored, '、'))
  }
  item.detail = joinWith(notes, '，')
  return item
}

/** 没有公钥或服务地址时只写本地结论，不算云失败。 */
function cloudFailed(judged: ScanHit[]): boolean {
  for (let hit of judged) {
    if (hit.verdict.cloud === 'offline' && hit.verdict.reason.indexOf(CLOUD_UNCONFIGURED) < 0) {
      return true
    }
  }
  return false
}

function grantsReady(access: AccessFacts, facts: PermissionFact[]): boolean {
  let gate = access as Object as GrantsGate
  if (typeof gate.ready === 'function') {
    return gate.ready() === true
  }
  return facts.some((fact: PermissionFact): boolean => fact.grant !== 'unknown')
}

function fingerprintOf(row: BundleRow, label: string): Finger {
  let fp = new Finger()
  fp.kind = 'bundle'
  fp.id = row.bundleName
  fp.bundleName = row.bundleName
  fp.version = row.version
  fp.versionCode = row.versionCode
  fp.certSha256 = row.certSha256
  fp.certAlgo = row.certAlgo
  fp.sha256 = ''
  fp.size = 0
  fp.label = label
  return fp
}

function addLevel(summary: ExamSummary, level: RiskLevel): void {
  if (level === 'risk') {
    summary.riskApps++
  } else if (level === 'suspicious') {
    summary.suspiciousApps++
  } else if (level === 'unknown') {
    summary.unknownApps++
  } else {
    summary.okApps++
  }
}

function countLevels(hits: ScanHit[]): LevelCounts {
  let counts = new LevelCounts()
  for (let hit of hits) {
    if (hit.action !== 'none') {
      continue
    }
    if (hit.verdict.level === 'risk') {
      counts.risk++
    } else if (hit.verdict.level === 'suspicious') {
      counts.suspicious++
    } else if (hit.verdict.level === 'unknown') {
      counts.unknown++
    } else {
      counts.ok++
    }
  }
  return counts
}

/** 风险和可疑全部留下；unknown、ok 按 listMax 截断。返回是否丢掉了 unknown。 */
function truncate(report: Report): boolean {
  let byLevel = (level: RiskLevel): ScanHit[] =>
    report.apps.filter((hit: ScanHit): boolean => hit.verdict.level === level)
  let risk = byLevel('risk')
  let suspicious = byLevel('suspicious')
  let unknown = byLevel('unknown')
  let ok = byLevel('ok')
  let room = Math.max(0, listMax - risk.length - suspicious.length)
  let keptUnknown = unknown.slice(0, room)
  let keptOk = ok.slice(0, Math.max(0, room - keptUnknown.length))
  report.apps = risk.concat(suspicious, keptUnknown, keptOk)
  return keptUnknown.length < unknown.length
}

function part(id: string, bytes: number, kind: 'cache' | 'installer'): Part {
  let value = new Part()
  value.id = id
  value.bytes = bytes
  value.kind = kind
  return value
}

function refresh(report: Report): void {
  let skipped = 0
  let advice = 0
  let appsSeen = false
  for (let item of report.items) {
    if (item.status === 'unsupported' || item.status === 'unverified') {
      skipped++
    }
    if (item.kind === 'advice' && item.status !== 'ok') {
      advice++
    }
    if (item.id === APPS_ID) {
      appsSeen = true
    }
  }
  report.skipped = skipped
  report.advice = advice
  let state = stateOf(report.items)
  if (!appsSeen && state === 'clear') {
    state = 'incomplete'
  }
  if (report.apps.some((hit: ScanHit): boolean => hit.action === 'none' && hit.verdict.level === 'risk')) {
    state = 'risk'
  }
  report.state = state
}

function joinWith(parts: string[], separator: string): string {
  let text = ''
  for (let i = 0; i < parts.length; i++) {
    if (i > 0) {
      text += separator
    }
    text += parts[i]
  }
  return text
}

function rethrowCancel(err: Object): void {
  if (err instanceof CenterError && err.code === 'cancelled') {
    throw err
  }
}

function reasonOf(err: Object): string {
  if (err instanceof CenterError) {
    return err.code + ':' + err.raw
  }
  if (err instanceof Error) {
    return err.message
  }
  return 'error'
}
