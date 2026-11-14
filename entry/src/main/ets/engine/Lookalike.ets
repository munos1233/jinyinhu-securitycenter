import type { Fingerprint } from '../center/CenterTypes'
import { lookalikeDistance, lookalikeMinLength } from '../center/CenterLimits'
import type { RuleLoad } from './RulePack'
import { canonicalCert } from './Decide'

export interface LookalikePick {
  bundleName: string
  certAlgo: string
  certSha256: string[]
}

class EmptyPick implements LookalikePick {
  bundleName: string = ''
  certAlgo: string = ''
  certSha256: string[] = []
}

export class Lookalike {
  static select(fp: Fingerprint, rules: RuleLoad): LookalikePick {
    let pick = new EmptyPick()
    if (fp.bundleName.length === 0) {
      return pick
    }
    for (let i = 0; i < rules.officials.length; i++) {
      let row = rules.officials[i]
      if (row.certSha256.length > 0 && row.bundleName === fp.bundleName) {
        return pick
      }
    }
    let bestDistance = lookalikeDistance + 1
    for (let i = 0; i < rules.officials.length; i++) {
      let row = rules.officials[i]
      if (row.certSha256.length === 0 || fp.bundleName.length < lookalikeMinLength ||
        row.bundleName.length < lookalikeMinLength ||
        Math.abs(fp.bundleName.length - row.bundleName.length) > lookalikeDistance) {
        continue
      }
      let distance = editDistance(fp.bundleName, row.bundleName)
      if (distance > lookalikeDistance || distance > bestDistance) {
        continue
      }
      if (distance === bestDistance && row.bundleName >= pick.bundleName) {
        continue
      }
      bestDistance = distance
      pick.bundleName = row.bundleName
      pick.certAlgo = row.certAlgo
      pick.certSha256 = row.certSha256.slice()
    }
    return pick
  }

  static matches(pick: LookalikePick, fp: Fingerprint): boolean {
    if (pick.bundleName.length === 0 || pick.certAlgo !== fp.certAlgo) {
      return false
    }
    let cert = canonicalCert(fp.certSha256)
    for (let i = 0; i < pick.certSha256.length; i++) {
      if (canonicalCert(pick.certSha256[i]) === cert) {
        return false
      }
    }
    return true
  }
}

function editDistance(left: string, right: string): number {
  let previous: number[] = []
  for (let j = 0; j <= right.length; j++) {
    previous.push(j)
  }
  for (let i = 1; i <= left.length; i++) {
    let current: number[] = [i]
    for (let j = 1; j <= right.length; j++) {
      let substitution = previous[j - 1]
      if (left.charAt(i - 1) !== right.charAt(j - 1)) {
        substitution++
      }
      current.push(Math.min(previous[j] + 1, current[j - 1] + 1, substitution))
    }
    previous = current
  }
  return previous[right.length]
}
