import type { Fingerprint } from '../center/CenterTypes'
import type { BundleRule, FileRule, OfficialRule, RuleLoad } from './RulePack'
import type { LookalikePick } from './Lookalike'
import { canonicalCert } from './Decide'

export interface LocalMatch {
  reason: string
  evidence: string
}

/** 仅提供匹配材料。判定顺序统一由 Decide 控制。 */
export class LocalRuleEngine {
  static black(fp: Fingerprint, rules: RuleLoad): LocalMatch | null {
    if (fp.kind === 'file') {
      let file = LocalRuleEngine.file(fp, rules, 'risk')
      if (file !== null) {
        return { reason: file.reason, evidence: 'match=sha256' }
      }
    }
    let cert = canonicalCert(fp.certSha256)
    if (fp.bundleName.length === 0 || cert.length === 0 || fp.certAlgo === 'none') {
      return null
    }
    for (let row of rules.bundles) {
      if (row.level === 'risk' && row.bundleName === fp.bundleName &&
        row.certAlgo === fp.certAlgo && canonicalCert(row.certSha256) === cert) {
        return { reason: row.reason, evidence: 'match=bundle-cert' }
      }
    }
    return null
  }

  static file(fp: Fingerprint, rules: RuleLoad, level: string): FileRule | null {
    if (fp.kind !== 'file' || fp.sha256.length === 0) {
      return null
    }
    for (let row of rules.files) {
      if (row.level === level && row.sha256 === fp.sha256) {
        return row
      }
    }
    return null
  }

  static official(fp: Fingerprint, rules: RuleLoad): OfficialRule | null {
    let cert = canonicalCert(fp.certSha256)
    if (fp.bundleName.length === 0 || cert.length === 0 || fp.certAlgo === 'none') {
      return null
    }
    for (let row of rules.officials) {
      if (row.bundleName === fp.bundleName && row.certAlgo === fp.certAlgo &&
        row.certSha256.some((allowed: string): boolean => canonicalCert(allowed) === cert)) {
        return row
      }
    }
    return null
  }

  static impersonation(fp: Fingerprint, rules: RuleLoad): OfficialRule | null {
    let cert = canonicalCert(fp.certSha256)
    if (fp.bundleName.length === 0 || cert.length === 0 || fp.certAlgo === 'none' ||
      LocalRuleEngine.official(fp, rules) !== null) {
      return null
    }
    for (let row of rules.officials) {
      if (row.bundleName === fp.bundleName && row.certAlgo === fp.certAlgo &&
        row.certSha256.length > 0) {
        return row
      }
    }
    return null
  }

  static certUncompared(fp: Fingerprint, rules: RuleLoad, pick: LookalikePick): boolean {
    if (fp.bundleName.length === 0) {
      return false
    }
    let exact = rules.officials.filter((row: OfficialRule): boolean =>
      row.bundleName === fp.bundleName && row.certSha256.length > 0)
    if (exact.length > 0) {
      if (exact.every((row: OfficialRule): boolean => row.certAlgo !== fp.certAlgo)) {
        return true
      }
    } else if (pick.bundleName.length > 0 && pick.certAlgo !== fp.certAlgo) {
      return true
    }
    return rules.bundles.some((row: BundleRule): boolean =>
      row.bundleName === fp.bundleName && canonicalCert(row.certSha256).length > 0 &&
      row.certAlgo !== fp.certAlgo)
  }

  static bundleCertMismatch(fp: Fingerprint, rules: RuleLoad): boolean {
    let cert = canonicalCert(fp.certSha256)
    if (fp.bundleName.length === 0 || cert.length === 0 || fp.certAlgo === 'none') {
      return false
    }
    return rules.bundles.some((row: BundleRule): boolean =>
      row.bundleName === fp.bundleName && row.certAlgo === fp.certAlgo &&
      canonicalCert(row.certSha256).length > 0 && canonicalCert(row.certSha256) !== cert)
  }

  static nameOnly(fp: Fingerprint, rules: RuleLoad): BundleRule | null {
    if (fp.bundleName.length === 0) {
      return null
    }
    for (let row of rules.bundles) {
      if (row.bundleName === fp.bundleName && row.step === 12) {
        return row
      }
    }
    return null
  }
}
