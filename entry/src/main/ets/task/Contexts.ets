import type {
  AccessFacts, CacheStats, FileSource, GrantLookup, JobRecord, JobRequest, PosturePort
} from '../center/CenterTypes'
import type { AppJudge } from '../engine/AppJudge'
import type { BundleCensus } from '../system/BundleCensus'
import type { FileOpen } from '../system/FileOpen'
import type { CancelFlag } from './CancelFlag'

/**
 * 七种窄上下文。每种只有自己的端口，不增不减。
 * 写盘不在上下文里：Runner 把结果对象交给 JobRunner，由 Writer 落盘。
 */

export interface Clock {
  nowIso(): string
}

export interface JobBase {
  job: JobRecord
  request: JobRequest
  cancel: CancelFlag
  clock: Clock
  report: (done: number, total: number, message: string) => void
}

export interface ExamContext {
  base: JobBase
  posture: PosturePort
  census: BundleCensus
  cache: CacheStats
  files: FileSource
  open: FileOpen
  access: AccessFacts
  judge: AppJudge
}

export interface MalwareContext {
  base: JobBase
  census: BundleCensus
  files: FileSource
  open: FileOpen
  grants: GrantLookup
  judge: AppJudge
}

export interface CleanContext {
  base: JobBase
  census: BundleCensus
  cache: CacheStats
  files: FileSource
  open: FileOpen
}

export interface PermissionContext {
  base: JobBase
  census: BundleCensus
  access: AccessFacts
}

export interface AppsContext {
  base: JobBase
  census: BundleCensus
  grants: GrantLookup
  judge: AppJudge
}

export interface ProtectContext {
  base: JobBase
  posture: PosturePort
}

/** duplicate 与 large-file 只用这一种。 */
export interface FileToolContext {
  base: JobBase
  files: FileSource
  open: FileOpen
}
