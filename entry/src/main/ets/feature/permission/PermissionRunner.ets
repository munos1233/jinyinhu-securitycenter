import { hilog } from '@kit.PerformanceAnalysisKit'
import { CenterError } from '../../center/CenterError'
import type { BundleRow, PermissionFact, UseFact } from '../../center/CenterTypes'
import { limitFacts, limitRows } from '../../record/Writer'
import type { PermissionContext } from '../../task/Contexts'
import { RunEnd } from '../../task/RunnerRegistry'
import type { ResultHand } from '../../task/RunnerRegistry'

const DOMAIN: number = 0x4A59
const TAG: string = 'Center'
const NO_BUNDLES: string = '无法获取应用列表'
const GROUPS: string[] = ['位置', '相机', '麦克风', '通讯录', '日历', '短信', '电话', '媒体']

export class PermissionGroupCount {
  group: string = ''
  count: number = 0
  known: boolean = true
}

/** A permission result keeps the complete census counts alongside bounded rows. */
export class PermissionReport {
  facts: PermissionFact[] = []
  uses: UseFact[] = []
  counts: PermissionGroupCount[] = []
  bundlesAvailable: boolean = false
  usesAvailable: boolean = false
}

export class PermissionRunner {
  async run(ctx: PermissionContext, hand: ResultHand): Promise<RunEnd> {
    let result = new PermissionReport()
    let end = new RunEnd()
    ctx.base.report(0, 0, '正在检查应用权限')
    let bundles: BundleRow[]
    try {
      bundles = await ctx.census.list()
    } catch (err) {
      if (!(err instanceof CenterError) || err.code !== 'unsupported') {
        throw err as Error
      }
      hilog.warn(DOMAIN, TAG, 'permission bundle census unavailable')
      end.summary = NO_BUNDLES
      hand.save(result)
      return end
    }
    result.bundlesAvailable = true
    if (ctx.base.cancel.cancelled()) {
      hand.save(result)
      return end
    }
    let facts = await ctx.access.facts(bundles)
    result.counts = groupCounts(facts)
    result.facts = limitFacts(facts)
    end.itemCount = bundles.length
    ctx.base.report(bundles.length, bundles.length, '正在检查应用权限')
    if (!ctx.base.cancel.cancelled()) {
      try {
        result.uses = limitRows(await ctx.access.recentUses())
        result.usesAvailable = true
      } catch (err) {
        hilog.warn(DOMAIN, TAG, 'permission usage unavailable')
      }
    }
    hand.save(result)
    return end
  }
}

export function groupCounts(facts: PermissionFact[]): PermissionGroupCount[] {
  let counts: PermissionGroupCount[] = []
  for (let group of GROUPS) {
    let row = new PermissionGroupCount()
    row.group = group
    let bundles = new Set<string>()
    for (let fact of facts) {
      if (fact.group === group) {
        if (fact.grant === 'unknown') {
          row.known = false
        } else if (fact.grant === 'granted') {
          bundles.add(fact.bundleName)
        }
      }
    }
    row.count = bundles.size
    counts.push(row)
  }
  return counts
}
