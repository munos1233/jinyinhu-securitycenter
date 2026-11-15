import { hilog } from '@kit.PerformanceAnalysisKit'
import type { BundleRow, Fingerprint, RiskLevel, ScanHit, TrustEntry } from '../../center/CenterTypes'
import type { JudgeInput } from '../../engine/AppJudge'
import { RulePack } from '../../engine/RulePack'
import { limitRows } from '../../record/Writer'
import type { AppsContext } from '../../task/Contexts'
import { RunEnd } from '../../task/RunnerRegistry'
import type { ResultHand } from '../../task/RunnerRegistry'

const DOMAIN: number = 0x4A59
const TAG: string = 'Center'

export interface AppSources {
  trust(): TrustEntry[]
}

export class AppRunner {
  private sources: AppSources

  constructor(sources: AppSources) {
    this.sources = sources
  }

  async run(ctx: AppsContext, hand: ResultHand): Promise<RunEnd> {
    let end = new RunEnd()
    let rows: BundleRow[]
    try {
      rows = await ctx.census.list()
    } catch (err) {
      hilog.warn(DOMAIN, TAG, 'apps census unavailable')
      end.summary = '无法获取应用列表'
      return end
    }
    let inputs: JudgeInput[] = []
    let rowsByName = new Map<string, BundleRow>()
    for (let row of rows) {
      if (ctx.base.cancel.cancelled()) {
        break
      }
      let ready = ctx.grants.ready()
      let granted: string[] = []
      if (ready) {
        try {
          granted = await ctx.grants.grantedOf(row.bundleName)
          ready = ctx.grants.ready()
        } catch (err) {
          ready = false
        }
      }
      let fingerprint: Fingerprint = {
        kind: 'bundle', id: row.bundleName, bundleName: row.bundleName, version: row.version,
        versionCode: row.versionCode, certSha256: row.certSha256, certAlgo: row.certAlgo,
        sha256: '', size: 0, label: row.bundleName
      }
      inputs.push({ fingerprint: fingerprint, declared: row.declaredPermissions.slice(),
        granted: granted, grantsReady: ready })
      rowsByName.set(row.bundleName, row)
    }
    if (!ctx.grants.ready()) {
      for (let input of inputs) {
        input.grantsReady = false
        input.granted = []
      }
    }
    let result = await ctx.judge.judge(inputs, RulePack.active(), this.sources.trust(), ctx.base.cancel,
      (): boolean => ctx.base.cancel.cancelled(), (_hit: ScanHit): void => {})
    let output: BundleRow[] = []
    for (let hit of result.hits) {
      let row = rowsByName.get(hit.fingerprint.id)
      if (row !== undefined) {
        row.verdict = hit.verdict
        output.push(row)
      }
    }
    output.sort((a: BundleRow, b: BundleRow): number => {
      let order = rank(a.verdict.level) - rank(b.verdict.level)
      return order !== 0 ? order : (a.bundleName < b.bundleName ? -1 : (a.bundleName > b.bundleName ? 1 : 0))
    })
    hand.save(limitRows(output))
    end.itemCount = output.length
    end.riskCount = output.filter((row: BundleRow): boolean => row.verdict.level === 'risk').length
    if (!result.complete) {
      end.summary = '本次扫描未完成'
    } else if (output.length > limitRows(output).length) {
      end.summary = '结果较多，仅显示部分'
    }
    return end
  }
}

function rank(level: RiskLevel): number {
  if (level === 'risk') return 0
  if (level === 'suspicious') return 1
  if (level === 'unknown') return 2
  return 3
}
