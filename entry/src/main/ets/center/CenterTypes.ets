/**
 * 安全中心公共类型。字段名与《安全中心代码架构》第 3 节一致。
 * 不用可选字段：字符串用空串，数字用 0，布尔用 false。
 * JobBase 与七种窄上下文不在本文件。
 */

export type JobKind =
  | 'exam'
  | 'malware'
  | 'clean'
  | 'duplicate'
  | 'large-file'
  | 'permission'
  | 'apps'
  | 'protect'

export type Lane = 'light' | 'heavy'

export type JobState =
  | 'queued'
  | 'running'
  | 'done'
  | 'failed'
  | 'cancelled'
  | 'interrupted'

export type RiskLevel = 'ok' | 'unknown' | 'suspicious' | 'risk'

export type CheckStatus =
  | 'ok'
  | 'unknown'
  | 'risk'
  | 'attention'
  | 'unsupported'
  | 'unverified'

export type CheckKind = 'state' | 'advice'

export type ExamState = 'not-run' | 'risk' | 'incomplete' | 'clear'

export type VerdictSource =
  | 'local-black'
  | 'trust'
  | 'local-rule'
  | 'cloud'
  | 'probe'
  | 'system'

export type CloudState = 'unchecked' | 'offline' | 'reached'

export type ScanScope = 'quick' | 'full' | 'custom'

export type CleanClass = 'cache' | 'residue' | 'installer' | 'large' | 'duplicate'

export type GateStatus = 'ready' | 'unsupported'

export type CertAlgo = 'platform-fingerprint' | 'sha256-of-cert-bytes' | 'none'

export type TrustKind = 'bundle' | 'file-sha256'

export type HitAction = 'none' | 'quarantine' | 'uninstall' | 'cleared' | 'revoked'

export type InstallSource = 'system' | 'preinstalled' | 'store' | 'sideload' | 'unknown'

export interface Fingerprint {
  kind: 'bundle' | 'file'
  id: string
  bundleName: string
  version: string
  versionCode: number
  certSha256: string
  certAlgo: CertAlgo
  sha256: string
  size: number
  label: string
}

export interface QueryKey {
  bundleName: string
  versionCode: number
  certSha256: string
  sha256: string
}

export interface CloudView {
  state: CloudState
  level: 'ok' | 'unknown' | 'risk' | 'none'
  reason: string
  evidence: string
}

export interface Verdict {
  level: RiskLevel
  source: VerdictSource
  reason: string
  evidence: string
  cloud: CloudState
}

export interface ActionRef {
  route: string
  params: string
}

export type CheckGroup = 'threat' | 'clean' | 'permission' | 'protect' | 'rules'

export interface CheckItem {
  id: string
  title: string
  group: CheckGroup
  status: CheckStatus
  kind: CheckKind
  source: VerdictSource
  detail: string
  action: ActionRef
  countsTowardState: boolean
}

export interface AppsItemStatus {
  status: CheckStatus
  countsTowardState: boolean
  detail: string
}

export interface CountedByte {
  id: string
  bytes: number
  kind: 'cache' | 'installer'
}

export interface ExamSummary {
  riskApps: number
  suspiciousApps: number
  unknownApps: number
  okApps: number
  parts: CountedByte[]
  cleanableBytes: number
  cleanableKnown: boolean
  cleanableNote: string
  sensitiveApps: number
  sensitiveKnown: boolean
  anomalyApps: number
}

export interface ExamReport {
  jobId: string
  state: ExamState
  items: CheckItem[]
  apps: ScanHit[]
  appsComplete: boolean
  summary: ExamSummary
  skipped: number
  advice: number
  generatedAt: string
}

export interface JobRequest {
  kind: JobKind
  scope: ScanScope
  uris: string[]
  focus: string
}

export interface JobProgress {
  jobId: string
  kind: JobKind
  lane: Lane
  state: JobState
  done: number
  total: number
  message: string
}

export interface JobRecord {
  jobId: string
  seq: number
  kind: JobKind
  lane: Lane
  startedAt: string
  finishedAt: string
  state: JobState
  itemCount: number
  riskCount: number
  summary: string
  resultFile: string
}

export interface ScanHit {
  fingerprint: Fingerprint
  displayName: string
  verdict: Verdict
  quarantined: boolean
  action: HitAction
  granted: string[]
}

export interface HapMeta {
  bundleName: string
  version: string
  versionCode: number
  certSha256: string
  certAlgo: CertAlgo
  declaredPermissions: string[]
  sha256: string
  size: number
}

export interface FileHit {
  uri: string
  name: string
  size: number
  sha256: string
  clazz: CleanClass
  reason: string
  selected: boolean
  groupId: string
}

export interface DuplicateGroup {
  groupId: string
  sha256: string
  size: number
  fileUris: string[]
}

export interface ScanReport {
  hits: ScanHit[]
  complete: boolean
  note: string
  judged: number
  risk: number
  suspicious: number
  unknown: number
  ok: number
}

export interface PermissionFact {
  bundleName: string
  displayName: string
  permission: string
  label: string
  group: string
  sensitive: boolean
  declared: boolean
  grant: 'granted' | 'denied' | 'unknown'
  fixed: boolean
  tokenId: number
  source: InstallSource
}

export interface UseFact {
  bundleName: string
  displayName: string
  permission: string
  label: string
  at: string
}

export interface CacheRow {
  bundleName: string
  displayName: string
  cacheBytes: number
  selected: boolean
}

export interface CleanReport {
  caches: CacheRow[]
  hits: FileHit[]
  groups: DuplicateGroup[]
  complete: boolean
  note: string
}

export interface FileToolReport {
  hits: FileHit[]
  groups: DuplicateGroup[]
  complete: boolean
  note: string
}

export interface BundleRow {
  bundleName: string
  version: string
  versionCode: number
  certSha256: string
  certAlgo: CertAlgo
  declaredPermissions: string[]
  source: InstallSource
  verdict: Verdict
}

export interface ProtectFact {
  id: string
  status: CheckStatus
  expected: string
  actual: string
  detail: string
}

export interface Gate {
  id: string
  status: GateStatus
  reason: string
}

export interface QuarantineEntry {
  id: string
  from: string
  stored: string
  sha256: string
  size: number
  iv: string
  tag: string
  reason: string
  at: string
  committed: boolean
}

export interface TrustEntry {
  kind: TrustKind
  fingerprint: string
  id: string
  versionCode: number
  at: string
}

export interface FileGrant {
  uri: string
  displayName: string
  persisted: boolean
  at: string
}

export interface AuditLine {
  at: string
  kind: string
  action: string
  jobId: string
  target: string
  result: string
}

export interface FileSource {
  persisted(): FileGrant[]
  forget(uri: string): void
}

export interface PosturePort {
  pureMode(): Promise<ProtectFact>
  lockdown(): Promise<ProtectFact>
  el5(): Promise<ProtectFact>
}

export interface InstallerPort {
  uninstall(bundleName: string): Promise<void>
}

export interface CacheStats {
  stats(bundleName: string): Promise<number>
}

export interface CacheClear {
  clear(bundleName: string): Promise<void>
}

export interface AccessFacts {
  facts(bundles: BundleRow[]): Promise<PermissionFact[]>
  recentUses(): Promise<UseFact[]>
}

export interface AccessRevoke {
  revoke(tokenId: number, permission: string): Promise<void>
}

export interface GrantLookup {
  ready(): boolean
  grantedOf(bundleName: string): Promise<string[]>
}

/** CloudBatch 签名里的名字。缓冲区实现不在本文件。 */
export interface CancelFlag {
}

export interface CloudBatch {
  query(keys: QueryKey[], cancel: CancelFlag): Promise<CloudView[]>
}
