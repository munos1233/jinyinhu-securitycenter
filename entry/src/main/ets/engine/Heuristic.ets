import type { Fingerprint } from '../center/CenterTypes'
import { reasonMax } from '../center/CenterLimits'
import type { RuleLoad } from './RulePack'

export interface HeuristicMatch {
  matched: boolean
  reason: string
}

class MatchResult implements HeuristicMatch {
  matched: boolean = false
  reason: string = ''
}

export class Heuristic {
  static matches(fp: Fingerprint, declared: string[], granted: string[],
    grantsReady: boolean, rules: RuleLoad): HeuristicMatch {
    let result = new MatchResult()
    if (fp.kind === 'bundle' && !grantsReady) {
      return result
    }
    let permissions = fp.kind === 'file' ? declared : granted
    let reasons: string[] = []
    for (let i = 0; i < rules.heuristics.length; i++) {
      let row = rules.heuristics[i]
      if (row.permissions.length < 2 ||
        !row.permissions.every((permission: string) => permissions.indexOf(permission) >= 0)) {
        continue
      }
      result.matched = true
      reasons.push(row.reason)
    }
    if (result.matched) {
      let prefix = fp.kind === 'file' ? '安装包中声明：' : '已允许：'
      result.reason = (prefix + reasons.join('、')).substring(0, reasonMax)
    }
    return result
  }
}
