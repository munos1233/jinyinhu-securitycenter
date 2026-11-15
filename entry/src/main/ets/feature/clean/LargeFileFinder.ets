import { hilog } from '@kit.PerformanceAnalysisKit'
import { CenterError } from '../../center/CenterError'
import { heavyBudgetMs, heavyMaxBytes, heavyMaxFiles, largeTiers, listMax } from '../../center/CenterLimits'
import type { DuplicateGroup, FileGrant, FileHit, FileToolReport } from '../../center/CenterTypes'
import type { InstallerIo, OpenedInstaller } from '../../engine/InstallerScan'
import { FsInstallerIo } from '../../engine/InstallerScan'
import type { FileToolContext } from '../../task/Contexts'
import { RunEnd } from '../../task/RunnerRegistry'
import type { ResultHand } from '../../task/RunnerRegistry'

const DOMAIN: number = 0x4A59
const TAG: string = 'Center'

const AT_LIMIT: string = '已达本次扫描上限'
const TRUNCATED: string = '结果较多，仅显示部分'
const TIER_1G: string = '1GB+'
const TIER_500M: string = '500MB+'
const TIER_100M: string = '100MB+'

/** 授权目录遍历。测试替换成假实现。 */
export class LargeFileTools {
  io: InstallerIo = new FsInstallerIo()
}

class Report implements FileToolReport {
  hits: FileHit[] = []
  groups: DuplicateGroup[] = []
  complete: boolean = false
  note: string = ''
}

class Hit implements FileHit {
  uri: string = ''
  name: string = ''
  size: number = 0
  sha256: string = ''
  clazz: FileHit['clazz'] = 'large'
  reason: string = ''
  selected: boolean = false
  groupId: string = ''
}

class Budget {
  objects: number = 0
  bytes: number = 0
  started: number = 0
  hit: boolean = false

  constructor(started: number) {
    this.started = started
  }

  exhausted(now: number): boolean {
    if (this.objects >= heavyMaxFiles || this.bytes >= heavyMaxBytes || now - this.started >= heavyBudgetMs) {
      this.hit = true
    }
    return this.hit
  }
}

class Target {
  uri: string = ''
  root: string = ''
}

/**
 * 参数类型是 FileToolContext。size >= 100MB 列出，reason 取最高一档。
 * 不调用 Quarantine，不删除。各用各的三个上限。
 */
export class LargeFileFinder {
  private tools: LargeFileTools

  constructor(tools: LargeFileTools = new LargeFileTools()) {
    this.tools = tools
  }

  async run(ctx: FileToolContext, hand: ResultHand): Promise<RunEnd> {
    let report = new Report()
    let budget = new Budget(Date.now())
    ctx.base.report(0, 0, '正在查找大文件')

    let grants = persistedOf(ctx.files.persisted())
    let seen = new Set<string>()
    for (let grant of grants) {
      let item = new Target()
      item.uri = grant.uri
      item.root = rootOf(grant.uri)
      if (!(await this.visit(ctx, item, item.uri, grants, seen, report, budget))) {
        break
      }
    }

    let dropped = false
    if (report.hits.length > listMax) {
      report.hits = report.hits.slice(0, listMax)
      dropped = true
    }
    let atLimit = budget.hit && !ctx.base.cancel.cancelled()
    report.note = notesOf(atLimit, dropped)
    report.complete = !atLimit && !dropped && !ctx.base.cancel.cancelled()
    for (let hit of report.hits) {
      hit.selected = false
    }
    report.groups = []
    hand.save(report)

    let end = new RunEnd()
    end.itemCount = report.hits.length
    end.summary = atLimit ? AT_LIMIT : ''
    return end
  }

  private async visit(ctx: FileToolContext, item: Target, uri: string, grants: FileGrant[],
    seen: Set<string>, report: Report, budget: Budget): Promise<boolean> {
    if (ctx.base.cancel.cancelled() || budget.exhausted(Date.now())) {
      return false
    }
    let accepted = ctx.open.accept(uri, item.root)
    if (accepted instanceof CenterError) {
      return true
    }
    if (seen.has(accepted)) {
      return true
    }
    seen.add(accepted)
    let directory = false
    try {
      let stat = this.tools.io.stat(accepted)
      if (stat.symbolicLink) {
        return true
      }
      directory = stat.directory
    } catch (err) {
      hilog.warn(DOMAIN, TAG, 'large-file stat failed')
      return true
    }
    if (!directory) {
      return this.measure(ctx, uri, item, grants, report, budget)
    }
    let names: string[] = []
    try {
      names = this.tools.io.list(accepted).slice().sort(compareUtf8)
    } catch (err) {
      hilog.warn(DOMAIN, TAG, 'large-file list failed')
      return true
    }
    for (let name of names) {
      if (name === '.' || name === '..' || name.indexOf('/') >= 0) {
        continue
      }
      let child = uri.replace(/\/$/, '') + '/' + name
      if (!(await this.visit(ctx, item, child, grants, seen, report, budget))) {
        return false
      }
    }
    return true
  }

  private measure(ctx: FileToolContext, uri: string, item: Target, grants: FileGrant[],
    report: Report, budget: Budget): boolean {
    if (ctx.base.cancel.cancelled() || budget.exhausted(Date.now())) {
      return false
    }
    let opened = ctx.open.open(uri, item.root, false, grants)
    if (opened instanceof CenterError) {
      return true
    }
    try {
      let size = 0
      try {
        size = this.tools.io.size(opened.fd)
      } catch (err) {
        hilog.warn(DOMAIN, TAG, 'large-file size unreadable')
        return true
      }
      if (!Number.isSafeInteger(size) || size < 0) {
        return true
      }
      if (size > heavyMaxBytes - budget.bytes) {
        budget.hit = true
        return false
      }
      budget.objects++
      budget.bytes += size
      if (size >= largeTiers[0]) {
        report.hits.push(largeHit(uri, size))
        ctx.base.report(report.hits.length, 0, '正在查找大文件')
      }
    } finally {
      ctx.open.release(opened as OpenedInstaller)
    }
    return !ctx.base.cancel.cancelled() && !budget.exhausted(Date.now())
  }
}

/** size >= 1GB → 1GB+；否则 >= 500MB → 500MB+；否则 >= 100MB → 100MB+。1024 进位。 */
export function largeReason(size: number): string {
  if (size >= largeTiers[2]) {
    return TIER_1G
  }
  if (size >= largeTiers[1]) {
    return TIER_500M
  }
  return TIER_100M
}

function largeHit(uri: string, size: number): FileHit {
  let hit = new Hit()
  hit.uri = uri
  hit.name = nameOf(uri)
  hit.size = size
  hit.sha256 = ''
  hit.clazz = 'large'
  hit.reason = largeReason(size)
  hit.selected = false
  hit.groupId = ''
  return hit
}

function notesOf(atLimit: boolean, dropped: boolean): string {
  let notes: string[] = []
  if (atLimit) {
    notes.push(AT_LIMIT)
  }
  if (dropped) {
    notes.push(TRUNCATED)
  }
  return notes.join('、')
}

function persistedOf(grants: FileGrant[]): FileGrant[] {
  return grants.filter((grant: FileGrant): boolean => grant.persisted === true)
}

function rootOf(uri: string): string {
  return uri.startsWith('file:///') ? uri.substring('file://'.length) : uri
}

function nameOf(uri: string): string {
  let trimmed = uri.replace(/\/$/, '')
  return trimmed.substring(trimmed.lastIndexOf('/') + 1)
}

function compareUtf8(a: string, b: string): number {
  let left = Array.from(a)
  let right = Array.from(b)
  for (let i = 0; i < Math.min(left.length, right.length); i++) {
    let difference = (left[i].codePointAt(0) || 0) - (right[i].codePointAt(0) || 0)
    if (difference !== 0) {
      return difference
    }
  }
  return left.length - right.length
}
