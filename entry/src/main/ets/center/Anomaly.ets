import type { ScanHit } from './CenterTypes'
import type { RuleLoad } from '../engine/RulePack'
import { Heuristic } from '../engine/Heuristic'

const SELF: string = 'com.jinyinhu.securitycenter'

export class Anomaly {
  static count(hits: ScanHit[], rules: RuleLoad): number {
    let count = 0
    for (let i = 0; i < hits.length; i++) {
      let hit = hits[i]
      if (hit.fingerprint.kind !== 'bundle' || hit.fingerprint.bundleName === SELF ||
        hit.action !== 'none' || hit.verdict.evidence === 'official') {
        continue
      }
      if (Heuristic.matches(hit.fingerprint, [], hit.granted, true, rules).matched) {
        count++
      }
    }
    return count
  }
}
