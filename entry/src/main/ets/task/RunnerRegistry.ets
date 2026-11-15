import type { JobKind } from '../center/CenterTypes'
import type {
  AppsContext, CleanContext, ExamContext, FileToolContext, MalwareContext, PermissionContext, ProtectContext
} from './Contexts'

/** Runner 正常返回即作业结束。到了自己的上限也是正常返回，作业记 done。 */
export class RunEnd {
  itemCount: number = 0
  riskCount: number = 0
  summary: string = ''
}

/** 结果对象交给 JobRunner，由 Writer 落盘。第一条结果出现时就调用，之后每次覆盖同一个文件。 */
export interface ResultHand {
  save(result: Object): void
}

export type ExamRun = (ctx: ExamContext, hand: ResultHand) => Promise<RunEnd>
export type MalwareRun = (ctx: MalwareContext, hand: ResultHand) => Promise<RunEnd>
export type CleanRun = (ctx: CleanContext, hand: ResultHand) => Promise<RunEnd>
export type PermissionRun = (ctx: PermissionContext, hand: ResultHand) => Promise<RunEnd>
export type AppsRun = (ctx: AppsContext, hand: ResultHand) => Promise<RunEnd>
export type ProtectRun = (ctx: ProtectContext, hand: ResultHand) => Promise<RunEnd>
export type FileToolRun = (ctx: FileToolContext, hand: ResultHand) => Promise<RunEnd>

/** 键是 JobKind。large-file 存在 largeFile 字段。 */
export class RunnerTable {
  exam: ExamRun | null = null
  malware: MalwareRun | null = null
  clean: CleanRun | null = null
  duplicate: FileToolRun | null = null
  largeFile: FileToolRun | null = null
  permission: PermissionRun | null = null
  apps: AppsRun | null = null
  protect: ProtectRun | null = null

  has(kind: JobKind): boolean {
    if (kind === 'exam') {
      return this.exam !== null
    }
    if (kind === 'malware') {
      return this.malware !== null
    }
    if (kind === 'clean') {
      return this.clean !== null
    }
    if (kind === 'duplicate') {
      return this.duplicate !== null
    }
    if (kind === 'large-file') {
      return this.largeFile !== null
    }
    if (kind === 'permission') {
      return this.permission !== null
    }
    if (kind === 'apps') {
      return this.apps !== null
    }
    return this.protect !== null
  }
}

/** task 不 import feature。EntryAbility 组装好 Runner 再交进来。 */
export class RunnerSet {
  exam: ExamRun | null = null
}

export class RunnerRegistry {
  private static current: RunnerTable = new RunnerTable()

  /** EntryAbility 调用一次。本轮只登记 exam，其余种类仍是空的。 */
  static registerAll(runners: RunnerSet = new RunnerSet()): void {
    let table = new RunnerTable()
    table.exam = runners.exam
    RunnerRegistry.current = table
  }

  static table(): RunnerTable {
    return RunnerRegistry.current
  }
}
