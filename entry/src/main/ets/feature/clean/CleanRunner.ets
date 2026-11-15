import { hilog } from '@kit.PerformanceAnalysisKit'
import { CenterError } from '../../center/CenterError'
import { heavyBudgetMs, heavyMaxBytes, heavyMaxFiles, listMax } from '../../center/CenterLimits'
import type {
  BundleRow, CacheRow, CleanReport, DuplicateGroup, FileGrant, FileHit
} from '../../center/CenterTypes'
import type { CleanContext } from '../../task/Contexts'
import { RunEnd } from '../../task/RunnerRegistry'
import type { ResultHand } from '../../task/RunnerRegistry'
import { CorpseFinder, CorpseResult } from './CorpseFinder'

const DOMAIN: number = 0x4A59
const TAG: string = 'Center'
const SELF: string = 'com.jinyinhu.securitycenter'

const AT_LIMIT: string = '已达本次扫描上限'
const TRUNCATED: string = '结果较多，仅显示部分'
const OTHER_CACHE: string = '无法读取其他应用缓存'
const NO_DIR: string = '请先选择目录'

/**
 * CleanContext 里没有本应用 cacheDir 字节。缓存端口不可用时由组合根给出。
 * 不在 Runner 里清缓存，不调用 Quarantine.put。
 */
export interface CleanSources {
  ownCache(): Promise<number>
  selfBundle(): string
}

class Report implements CleanReport {
  caches: CacheRow[] = []
  hits: FileHit[] = []
  groups: DuplicateGroup[] = []
  complete: boolean = false
  note: string = ''
}

class Row implements CacheRow {
  bundleName: string = ''
  displayName: string = ''
  cacheBytes: number = 0
  selected: boolean = false
}

class Budget {
  started: number = 0
  hit: boolean = false

  constructor(started: number) {
    this.started = started
  }

  exhausted(now: number): boolean {
    if (now - this.started >= heavyBudgetMs) {
      this.hit = true
    }
    return this.hit
  }
}

export class CleanRunner {
  private sources: CleanSources
  private corpses: CorpseFinder

  constructor(sources: CleanSources, corpses: CorpseFinder = new CorpseFinder()) {
    this.sources = sources
    this.corpses = corpses
  }

  /** 主列表是应用缓存和安装包。写回 selected=false。不清除、不隔离。 */
  async run(ctx: CleanContext, hand: ResultHand): Promise<RunEnd> {
    let report = new Report()
    let budget = new Budget(Date.now())
    let cacheNote = ''
    ctx.base.report(0, 0, '正在扫描缓存')

    let caches = await this.caches(ctx, budget)
    report.caches = caches.rows
    cacheNote = caches.note
    hand.save(snapshot(report, false, notesOf(false, false, cacheNote, '')))

    let grantNote = ''
    let corpse = new CorpseResult()
    if (!ctx.base.cancel.cancelled() && !budget.hit) {
      ctx.base.report(report.caches.length, 0, '正在查找安装包')
      let grants = persistedOf(ctx.files.persisted())
      if (grants.length === 0) {
        grantNote = NO_DIR
      } else {
        let installed = caches.installed
        corpse = this.corpses.find(ctx.files, ctx.open, installed,
          (): boolean => ctx.base.cancel.cancelled() || budget.exhausted(Date.now()),
          heavyMaxFiles, heavyMaxBytes, heavyBudgetMs)
        if (corpse.stoppedByLimit) {
          budget.hit = true
        }
      }
    }

    report.hits = corpse.hits.map((hit: FileHit): FileHit => copyHit(hit))
    let dropped = false
    if (report.caches.length > listMax) {
      report.caches = report.caches.slice(0, listMax)
      dropped = true
    }
    if (report.hits.length > listMax) {
      report.hits = report.hits.slice(0, listMax)
      dropped = true
    }
    for (let row of report.caches) {
      row.selected = false
    }
    for (let hit of report.hits) {
      hit.selected = false
    }
    report.groups = []
    let atLimit = budget.hit && !ctx.base.cancel.cancelled()
    report.note = notesOf(atLimit, dropped, cacheNote, grantNote)
    report.complete = !atLimit && !dropped && !ctx.base.cancel.cancelled()
    hand.save(report)

    let end = new RunEnd()
    end.itemCount = report.caches.length + report.hits.length
    end.summary = atLimit ? AT_LIMIT : ''
    return end
  }

  private async caches(ctx: CleanContext, budget: Budget): Promise<CachePass> {
    let out = new CachePass()
    let rows: BundleRow[] = []
    try {
      rows = await ctx.census.list()
      out.installed = rows.map((row: BundleRow): string => row.bundleName)
    } catch (err) {
      rethrowCancel(err as Object)
      hilog.warn(DOMAIN, TAG, 'clean census unavailable: %{public}s', reasonOf(err as Object))
      rows = []
    }

    let portUsable = rows.length > 0
    if (portUsable) {
      for (let row of rows) {
        if (ctx.base.cancel.cancelled() || budget.exhausted(Date.now())) {
          break
        }
        try {
          let bytes = await ctx.cache.stats(row.bundleName)
          if (bytes > 0) {
            out.rows.push(cacheRow(row.bundleName, row.bundleName, bytes))
          }
        } catch (err) {
          let failure = err as Object
          rethrowCancel(failure)
          if (failure instanceof CenterError && failure.code === 'unsupported') {
            portUsable = false
            out.rows = []
            break
          }
          hilog.warn(DOMAIN, TAG, 'clean cache stats %{public}s: %{public}s', row.bundleName,
            reasonOf(failure))
        }
      }
    }

    if (!portUsable) {
      out.note = OTHER_CACHE
      out.rows = []
      let self = this.selfName()
      let bytes = 0
      try {
        bytes = await this.sources.ownCache()
      } catch (err) {
        hilog.warn(DOMAIN, TAG, 'clean own cache unreadable: %{public}s', reasonOf(err as Object))
        bytes = 0
      }
      out.rows.push(cacheRow(self, self, bytes))
    }
    return out
  }

  private selfName(): string {
    try {
      let name = this.sources.selfBundle()
      return name.length > 0 ? name : SELF
    } catch (err) {
      return SELF
    }
  }
}

class CachePass {
  rows: CacheRow[] = []
  installed: string[] = []
  note: string = ''
}

function cacheRow(bundleName: string, displayName: string, cacheBytes: number): CacheRow {
  let row = new Row()
  row.bundleName = bundleName
  row.displayName = displayName
  row.cacheBytes = cacheBytes
  row.selected = false
  return row
}

function copyHit(hit: FileHit): FileHit {
  let out = new Hit()
  out.uri = hit.uri
  out.name = hit.name
  out.size = hit.size
  out.sha256 = hit.sha256
  out.clazz = hit.clazz
  out.reason = hit.reason
  out.selected = false
  out.groupId = ''
  return out
}

class Hit implements FileHit {
  uri: string = ''
  name: string = ''
  size: number = 0
  sha256: string = ''
  clazz: FileHit['clazz'] = 'residue'
  reason: string = ''
  selected: boolean = false
  groupId: string = ''
}

function snapshot(report: Report, complete: boolean, note: string): CleanReport {
  let copy = new Report()
  copy.caches = report.caches.map((row: CacheRow): CacheRow =>
    cacheRow(row.bundleName, row.displayName, row.cacheBytes))
  copy.hits = report.hits.map((hit: FileHit): FileHit => copyHit(hit))
  copy.groups = []
  copy.complete = complete
  copy.note = note
  return copy
}

function notesOf(atLimit: boolean, dropped: boolean, cacheNote: string, grantNote: string): string {
  let notes: string[] = []
  if (atLimit) {
    notes.push(AT_LIMIT)
  }
  if (dropped) {
    notes.push(TRUNCATED)
  }
  if (cacheNote.length > 0) {
    notes.push(cacheNote)
  }
  if (grantNote.length > 0) {
    notes.push(grantNote)
  }
  return notes.join('、')
}

function persistedOf(grants: FileGrant[]): FileGrant[] {
  return grants.filter((grant: FileGrant): boolean => grant.persisted === true)
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
