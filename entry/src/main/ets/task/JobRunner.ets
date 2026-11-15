import { hilog } from '@kit.PerformanceAnalysisKit'
import { CenterError, centerErrorMessage } from '../center/CenterError'
import type { CenterErrorCode } from '../center/CenterError'
import { nowIso } from '../center/Clock'
import type {
  AccessFacts, CacheStats, FileSource, GrantLookup, JobRecord, JobState, PosturePort
} from '../center/CenterTypes'
import type { AppJudge } from '../engine/AppJudge'
import { Writer } from '../record/Writer'
import type { BundleCensus } from '../system/BundleCensus'
import type { FileOpen } from '../system/FileOpen'
import type {
  AppsContext, CleanContext, Clock, ExamContext, FileToolContext, JobBase, MalwareContext, PermissionContext,
  ProtectContext
} from './Contexts'
import { RunnerRegistry } from './RunnerRegistry'
import type { ResultHand, RunEnd, RunnerTable } from './RunnerRegistry'

const DOMAIN: number = 0x4A59
const TAG: string = 'Center'
const NO_RUNNER: string = '暂不支持'
/** 条目级结果。Runner 把它们抛到作业层也不让整次作业 failed。 */
const ITEM_LEVEL: CenterErrorCode[] = ['unsupported', 'cloud', 'unsigned-cloud', 'rejected-system-path', 'quota']

/** 组合根持有全部端口。每个 Runner 只拿到自己的窄上下文。 */
export interface CenterPorts {
  posture: PosturePort
  census: BundleCensus
  cache: CacheStats
  files: FileSource
  open: FileOpen
  access: AccessFacts
  grants: GrantLookup
  judge: AppJudge
}

export class SystemClock implements Clock {
  nowIso(): string {
    return nowIso()
  }
}

export class JobEnd {
  state: JobState = 'done'
  itemCount: number = 0
  riskCount: number = 0
  summary: string = ''
}

class Hand implements ResultHand {
  private record: JobRecord

  constructor(record: JobRecord) {
    this.record = record
  }

  save(result: Object): void {
    Writer.commit(this.record, JSON.stringify(result))
  }
}

export class JobRunner {
  private ports: CenterPorts
  private table: () => RunnerTable

  constructor(ports: CenterPorts, table: () => RunnerTable = () => RunnerRegistry.table()) {
    this.ports = ports
    this.table = table
  }

  /**
   * live 是这条作业在内存里的记录，结果文件写下后回填 resultFile。
   * processed 是最近一次 report 的 done，Runner 抛错或取消时作为 itemCount。
   * 已写入的结果文件一律保留。本轮不调用 settleStoppedExam。
   */
  async run(base: JobBase, live: JobRecord, processed: () => number): Promise<JobEnd> {
    let out: RunEnd | null = null
    try {
      out = await this.dispatch(base, new Hand(live))
    } catch (err) {
      return thrown(err as Object, base, processed())
    }
    let end = new JobEnd()
    if (out === null) {
      hilog.error(DOMAIN, TAG, 'no runner for %{public}s', base.request.kind)
      end.state = 'failed'
      end.summary = NO_RUNNER
      return end
    }
    end.itemCount = out.itemCount
    end.riskCount = out.riskCount
    end.summary = out.summary
    if (base.cancel.cancelled()) {
      end.state = 'cancelled'
      end.summary = centerErrorMessage('cancelled')
    }
    return end
  }

  private async dispatch(base: JobBase, hand: ResultHand): Promise<RunEnd | null> {
    let table = this.table()
    let p = this.ports
    let kind = base.request.kind
    if (kind === 'exam' && table.exam !== null) {
      let ctx: ExamContext = {
        base: base, posture: p.posture, census: p.census, cache: p.cache, files: p.files, open: p.open,
        access: p.access, judge: p.judge
      }
      return await table.exam(ctx, hand)
    }
    if (kind === 'malware' && table.malware !== null) {
      let ctx: MalwareContext = {
        base: base, census: p.census, files: p.files, open: p.open, grants: p.grants, judge: p.judge
      }
      return await table.malware(ctx, hand)
    }
    if (kind === 'clean' && table.clean !== null) {
      let ctx: CleanContext = { base: base, census: p.census, cache: p.cache, files: p.files, open: p.open }
      return await table.clean(ctx, hand)
    }
    if (kind === 'duplicate' && table.duplicate !== null) {
      let ctx: FileToolContext = { base: base, files: p.files, open: p.open }
      return await table.duplicate(ctx, hand)
    }
    if (kind === 'large-file' && table.largeFile !== null) {
      let ctx: FileToolContext = { base: base, files: p.files, open: p.open }
      return await table.largeFile(ctx, hand)
    }
    if (kind === 'permission' && table.permission !== null) {
      let ctx: PermissionContext = { base: base, census: p.census, access: p.access }
      return await table.permission(ctx, hand)
    }
    if (kind === 'apps' && table.apps !== null) {
      let ctx: AppsContext = { base: base, census: p.census, grants: p.grants, judge: p.judge }
      return await table.apps(ctx, hand)
    }
    if (kind === 'protect' && table.protect !== null) {
      let ctx: ProtectContext = { base: base, posture: p.posture }
      return await table.protect(ctx, hand)
    }
    return null
  }
}

function thrown(err: Object, base: JobBase, processed: number): JobEnd {
  let end = new JobEnd()
  end.itemCount = processed
  if (base.cancel.cancelled() || (err instanceof CenterError && err.code === 'cancelled')) {
    end.state = 'cancelled'
    end.summary = centerErrorMessage('cancelled')
    return end
  }
  if (!(err instanceof CenterError)) {
    let detail = err instanceof Error ? err.message : 'error'
    hilog.error(DOMAIN, TAG, 'runner %{public}s threw: %{public}s', base.request.kind, detail)
    end.state = 'failed'
    end.summary = centerErrorMessage('io')
    return end
  }
  hilog.error(DOMAIN, TAG, 'runner %{public}s %{public}s: %{public}s', base.request.kind, err.code, err.raw)
  end.summary = err.message
  if (err.code === 'interrupted') {
    end.state = 'interrupted'
  } else if (ITEM_LEVEL.indexOf(err.code) >= 0) {
    end.state = 'done'
  } else {
    end.state = 'failed'
  }
  return end
}
