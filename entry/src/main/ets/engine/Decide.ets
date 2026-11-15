import { hilog } from '@kit.PerformanceAnalysisKit';
import type { CloudView, Fingerprint, RiskLevel, TrustEntry, Verdict, VerdictSource } from '../center/CenterTypes'
import { reasonMax } from '../center/CenterLimits'
import type { RuleLoad } from './RulePack'
import { LocalRuleEngine } from './LocalRuleEngine'
import { Lookalike } from './Lookalike'
import type { LookalikePick } from './Lookalike'
import { Heuristic } from './Heuristic'

export function canonicalCert(value: string): string {
  let original = value.trim()
  let compact = stripSeparators(original)
  let body = stripKnownPrefix(compact)
  if (body.length > 0 && body.length % 2 === 0 && isHex(body)) {
    return toLowerAscii(body)
  }
  return original
}

function stripSeparators(value: string): string {
  let compact = ''
  for (let i = 0; i < value.length; i++) {
    let ch = value.charAt(i)
    if (ch !== ' ' && ch !== ':' && ch !== '-') {
      compact += ch
    }
  }
  return compact
}

function stripKnownPrefix(compact: string): string {
  let lower = toLowerAscii(compact)
  if (prefixed(lower, 'sha256', 64)) {
    return compact.substring(6)
  }
  if (prefixed(lower, 'sha1', 40)) {
    return compact.substring(4)
  }
  if (prefixed(lower, 'md5', 32)) {
    return compact.substring(3)
  }
  return compact
}

function prefixed(lower: string, prefix: string, remain: number): boolean {
  if (lower.length !== prefix.length + remain) {
    return false
  }
  for (let i = 0; i < prefix.length; i++) {
    if (lower.charAt(i) !== prefix.charAt(i)) {
      return false
    }
  }
  return isHex(lower.substring(prefix.length))
}

function isHex(value: string): boolean {
  if (value.length === 0) {
    return false
  }
  for (let i = 0; i < value.length; i++) {
    let code = value.charCodeAt(i)
    let digit = code >= 48 && code <= 57
    let lower = code >= 97 && code <= 102
    let upper = code >= 65 && code <= 70
    if (!digit && !lower && !upper) {
      return false
    }
  }
  return true
}

function toLowerAscii(value: string): string {
  let out = ''
  for (let i = 0; i < value.length; i++) {
    let code = value.charCodeAt(i)
    if (code >= 65 && code <= 90) {
      out += String.fromCharCode(code + 32)
    } else {
      out += value.charAt(i)
    }
  }
  return out
}

export function terminalBeforeCloud(fp: Fingerprint, rules: RuleLoad): Verdict | null {
  if ((fp.kind === 'bundle' && fp.id.length === 0) ||
    (fp.kind === 'file' && fp.sha256.length === 0)) {
    return verdict('unknown', 'local-rule', '', 'empty-fingerprint', 'unchecked')
  }
  let black = LocalRuleEngine.black(fp, rules)
  if (black !== null) {
    return verdict('risk', 'local-black', black.reason, black.evidence, 'unchecked')
  }
  let impersonation = LocalRuleEngine.impersonation(fp, rules)
  if (impersonation !== null) {
    let reason = impersonation.reason.length > 0 ? impersonation.reason : '签名与官方记录不符'
    return verdict('risk', 'local-rule', reason, 'impersonation', 'unchecked')
  }
  return null
}

export function decide(
  fp: Fingerprint,
  declared: string[],
  granted: string[],
  grantsReady: boolean,
  rules: RuleLoad,
  trust: TrustEntry[],
  cloud: CloudView
): Verdict {
  if (cloud.state === 'unchecked') {
    hilog.error(0x4A59, 'Center', 'decide called before cloud batch settled')
    return verdict('unknown', 'local-rule', '', 'unchecked-cloud', 'unchecked')
  }
  let terminal = terminalBeforeCloud(fp, rules)
  if (terminal !== null) {
    return terminal
  }
  let view = checkedCloud(cloud)
  if (view.state === 'reached' && view.level === 'risk') {
    return verdict('risk', 'cloud', view.reason, view.evidence, 'reached')
  }
  let white = LocalRuleEngine.file(fp, rules, 'ok')
  if (white !== null) {
    return localVerdict('ok', 'local-rule', white.reason, 'match=sha256', view, false)
  }
  if (LocalRuleEngine.official(fp, rules) !== null) {
    return localVerdict('ok', 'local-rule', '签名与官方记录一致', 'official', view, true)
  }
  let pick: LookalikePick = { bundleName: '', certAlgo: '', certSha256: [] }
  if (fp.bundleName.length > 0) {
    pick = Lookalike.select(fp, rules)
  }
  let uncompared = LocalRuleEngine.certUncompared(fp, rules, pick)
  let mismatch = LocalRuleEngine.bundleCertMismatch(fp, rules)
  if (!uncompared && !mismatch && trusted(fp, trust)) {
    return localVerdict('ok', 'trust', '已加入信任', 'trust', view, true)
  }
  if (uncompared) {
    return localVerdict('unknown', 'local-rule', '证书无法比对', 'cert-uncompared', view, false)
  }
  if (mismatch) {
    return localVerdict('unknown', 'local-rule', '同名应用签名与风险名单不符',
      'bundle-cert-mismatch', view, false)
  }
  let heuristic = Heuristic.matches(fp, declared, granted, grantsReady, rules)
  let lookalike = Lookalike.matches(pick, fp)
  if (heuristic.matched || lookalike) {
    let suffix = ''
    if (lookalike) {
      suffix = '包名与 ' + pick.bundleName + ' 相似'
    }
    let evidence = heuristic.matched ? 'heuristic' : 'lookalike'
    if (heuristic.matched && lookalike) {
      evidence = 'heuristic+lookalike'
    }
    if (view.state === 'reached' && view.level === 'ok') {
      suffix = appendReason(suffix, '云端查询正常')
    } else if (view.state === 'offline') {
      suffix = appendReason(suffix, view.reason)
    }
    let reason = appendReason(heuristic.reason, suffix)
    return verdict('suspicious', 'local-rule', reason, evidence, view.state)
  }
  let hasCertificate = canonicalCert(fp.certSha256).length > 0 && fp.certAlgo !== 'none'
  let hashOnlyFile = fp.kind === 'file' && fp.bundleName.length === 0
  if (view.state === 'reached' && view.level === 'ok' && (hasCertificate || hashOnlyFile)) {
    let reason = view.reason.length > 0 ? view.reason : '云端查询正常'
    return verdict('ok', 'cloud', reason, view.evidence, 'reached')
  }
  let nameOnly = LocalRuleEngine.nameOnly(fp, rules)
  if (nameOnly !== null) {
    return localVerdict('unknown', 'local-rule', nameOnly.reason, 'match=name-only', view, true)
  }
  let reason = view.state === 'offline' ? '' : '暂无匹配结果'
  return localVerdict('unknown', 'local-rule', reason, '', view, true)
}

function checkedCloud(cloud: CloudView): CloudView {
  if (cloud.state === 'reached' && cloud.level !== 'ok' &&
    cloud.level !== 'unknown' && cloud.level !== 'risk') {
    return { state: 'offline', level: 'none', reason: '未联网，云端结果无效', evidence: '' }
  }
  if (cloud.state === 'offline') {
    let reason = '未联网'
    if (cloud.reason === '未联网，云服务未配置' || cloud.reason === '未联网，云端结果无效') {
      reason = cloud.reason
    }
    return { state: 'offline', level: 'none', reason: reason, evidence: '' }
  }
  return cloud
}

function trusted(fp: Fingerprint, entries: TrustEntry[]): boolean {
  if (fp.kind === 'file') {
    return entries.some((entry: TrustEntry): boolean =>
      entry.kind === 'file-sha256' && entry.fingerprint.length > 0 && entry.fingerprint === fp.sha256)
  }
  let cert = canonicalCert(fp.certSha256)
  if (cert.length === 0 || fp.certAlgo === 'none') {
    return false
  }
  return entries.some((entry: TrustEntry): boolean =>
    entry.kind === 'bundle' && canonicalCert(entry.fingerprint).length > 0 &&
    canonicalCert(entry.fingerprint) === cert && entry.id === fp.bundleName &&
    entry.versionCode === fp.versionCode)
}

function verdict(
  level: RiskLevel,
  source: VerdictSource,
  reason: string,
  evidence: string,
  cloud: 'unchecked' | 'offline' | 'reached'
): Verdict {
  return { level: level, source: source, reason: reason.substring(0, reasonMax),
    evidence: evidence, cloud: cloud }
}

function localVerdict(
  level: RiskLevel,
  source: VerdictSource,
  reason: string,
  evidence: string,
  cloud: CloudView,
  appendNoResult: boolean
): Verdict {
  if (cloud.state === 'offline') {
    reason = appendReason(reason, cloud.reason)
  } else if (appendNoResult && cloud.level === 'unknown') {
    reason = appendReason(reason, '云端暂无结果')
  }
  return verdict(level, source, reason, evidence, cloud.state)
}

function appendReason(local: string, suffix: string): string {
  if (suffix.length === 0) {
    return local.substring(0, reasonMax)
  }
  if (local.length === 0) {
    return suffix.substring(0, reasonMax)
  }
  let available = reasonMax - suffix.length - 1
  if (available <= 0) {
    return suffix.substring(0, reasonMax)
  }
  return local.substring(0, available) + '、' + suffix
}
