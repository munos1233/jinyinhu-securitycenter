import { hilog } from '@kit.PerformanceAnalysisKit';
import { canonicalCert } from './Decide';

const DOMAIN: number = 0x4A59
const TAG: string = 'Center'
const DAMAGE: string = '规则文件损坏，仍使用上一份'
const NONE: string = 'none'

export class BundleRule {
  bundleName: string = ''
  certAlgo: string = ''
  certSha256: string = ''
  level: string = ''
  reason: string = ''
  step: number = 2
}

export class OfficialRule {
  bundleName: string = ''
  certAlgo: string = ''
  certSha256: string[] = []
  reason: string = ''
}

export class FileRule {
  sha256: string = ''
  level: string = ''
  reason: string = ''
}

export class HeuristicRule {
  id: string = ''
  permissions: string[] = []
  reason: string = ''
  level: string = 'suspicious'
}

export class RuleVersionOrder {
  compared: boolean = false
  order: number = 0
}

export class RuleLoad {
  rulesVersion: string = NONE
  versionComparable: boolean = false
  unavailable: number = 0
  disabled: number = 0
  notice: string = ''
  bundles: BundleRule[] = []
  officials: OfficialRule[] = []
  files: FileRule[] = []
  heuristics: HeuristicRule[] = []
}

class RawPack {
  version: string = ''
  bundles: Object[] = []
  officials: Object[] = []
  files: Object[] = []
  heuristics: Object[] = []
}

export class RulePack {
  private static current: RuleLoad | null = null

  static active(): RuleLoad {
    if (RulePack.current === null) {
      let empty = new RuleLoad()
      empty.rulesVersion = NONE
      return empty
    }
    return RulePack.current
  }

  static load(text: string | null): RuleLoad {
    let parsed = RulePack.parse(text)
    if (parsed === null) {
      if (RulePack.current !== null) {
        RulePack.current.notice = DAMAGE
        return RulePack.current
      }
      let empty = new RuleLoad()
      empty.rulesVersion = NONE
      return empty
    }
    parsed.notice = ''
    RulePack.current = parsed
    return parsed
  }

  static compareVersions(local: string, cloud: string): RuleVersionOrder {
    let result = new RuleVersionOrder()
    if (!versionOk(local) || !versionOk(cloud)) {
      return result
    }
    result.compared = true
    result.order = compareUtf8(local, cloud)
    return result
  }

  private static parse(text: string | null): RuleLoad | null {
    if (text === null) {
      return null
    }
    let raw: RawPack
    try {
      raw = JSON.parse(text) as RawPack
    } catch (err) {
      return null
    }
    if (raw === null || typeof raw !== 'object' || raw instanceof Array) {
      return null
    }
    let pack = new RuleLoad()
    pack.rulesVersion = typeof raw.version === 'string' ? raw.version : ''
    pack.versionComparable = versionOk(pack.rulesVersion)
    pack.bundles = readBundles(arrayOf(raw.bundles), pack)
    pack.officials = readOfficials(arrayOf(raw.officials), pack)
    pack.files = readFiles(arrayOf(raw.files))
    pack.heuristics = readHeuristics(arrayOf(raw.heuristics), pack)
    return pack
  }
}

function arrayOf(value: Object[] | undefined): Object[] {
  if (value instanceof Array) {
    return value
  }
  return []
}

function compareUtf8(left: string, right: string): number {
  let a = utf8(left)
  let b = utf8(right)
  let count = a.length < b.length ? a.length : b.length
  for (let i = 0; i < count; i++) {
    if (a[i] !== b[i]) {
      return a[i] < b[i] ? -1 : 1
    }
  }
  if (a.length === b.length) {
    return 0
  }
  return a.length < b.length ? -1 : 1
}

function utf8(value: string): number[] {
  let bytes: number[] = []
  for (let i = 0; i < value.length; i++) {
    let code = value.charCodeAt(i)
    if (code < 0x80) {
      bytes.push(code)
    } else if (code < 0x800) {
      bytes.push(0xc0 | (code >> 6))
      bytes.push(0x80 | (code & 0x3f))
    } else {
      bytes.push(0xe0 | (code >> 12))
      bytes.push(0x80 | ((code >> 6) & 0x3f))
      bytes.push(0x80 | (code & 0x3f))
    }
  }
  return bytes
}

function algoOk(value: string): boolean {
  return value === 'platform-fingerprint' || value === 'sha256-of-cert-bytes'
}

function versionOk(value: string): boolean {
  if (value.length !== 10) {
    return false
  }
  for (let i = 0; i < value.length; i++) {
    let ch = value.charAt(i)
    if (i === 4 || i === 7) {
      if (ch !== '.') {
        return false
      }
    } else if (ch < '0' || ch > '9') {
      return false
    }
  }
  return true
}

function readBundles(rows: Object[], pack: RuleLoad): BundleRule[] {
  let kept: BundleRule[] = []
  for (let i = 0; i < rows.length; i++) {
    let peek = rows[i] as BundleRule
    let name = typeof peek.bundleName === 'string' ? peek.bundleName : ''
    let algo = typeof peek.certAlgo === 'string' ? peek.certAlgo : ''
    let level = typeof peek.level === 'string' ? peek.level : ''
    let reason = typeof peek.reason === 'string' ? peek.reason : ''
    if (!algoOk(algo)) {
      hilog.error(DOMAIN, TAG, 'certAlgo ignored')
      pack.unavailable++
      continue
    }
    let cert = canonicalCert(typeof peek.certSha256 === 'string' ? peek.certSha256 : '')
    if (cert.length === 0) {
      if (level === 'risk') {
        hilog.error(DOMAIN, TAG, 'bundle downgraded to step 12')
        let row = new BundleRule()
        row.bundleName = name
        row.certAlgo = algo
        row.certSha256 = ''
        row.level = 'unknown'
        row.reason = reason
        row.step = 12
        kept.push(row)
      }
      continue
    }
    let row = new BundleRule()
    row.bundleName = name
    row.certAlgo = algo
    row.certSha256 = cert
    row.level = level
    row.reason = reason
    row.step = 2
    kept.push(row)
  }
  return kept
}

function readOfficials(rows: Object[], pack: RuleLoad): OfficialRule[] {
  let kept: OfficialRule[] = []
  for (let i = 0; i < rows.length; i++) {
    let peek = rows[i] as OfficialRule
    let name = typeof peek.bundleName === 'string' ? peek.bundleName : ''
    let algo = typeof peek.certAlgo === 'string' ? peek.certAlgo : ''
    let reason = typeof peek.reason === 'string' ? peek.reason : ''
    if (!algoOk(algo)) {
      hilog.error(DOMAIN, TAG, 'certAlgo ignored')
      pack.unavailable++
      continue
    }
    let certs = readCerts(peek.certSha256)
    if (certs.length === 0) {
      hilog.error(DOMAIN, TAG, 'officials certSha256 empty')
      pack.disabled++
      continue
    }
    let row = new OfficialRule()
    row.bundleName = name
    row.certAlgo = algo
    row.certSha256 = certs
    row.reason = reason
    kept.push(row)
  }
  return kept
}

function readCerts(value: string[] | string | undefined): string[] {
  let kept: string[] = []
  if (typeof value === 'string') {
    let cert = canonicalCert(value)
    if (cert.length > 0) {
      kept.push(cert)
    }
    return kept
  }
  if (!(value instanceof Array)) {
    return kept
  }
  for (let i = 0; i < value.length; i++) {
    if (typeof value[i] !== 'string') {
      continue
    }
    let cert = canonicalCert(value[i])
    if (cert.length > 0) {
      kept.push(cert)
    }
  }
  return kept
}

function readFiles(rows: Object[]): FileRule[] {
  let kept: FileRule[] = []
  for (let i = 0; i < rows.length; i++) {
    let peek = rows[i] as FileRule
    let sha = typeof peek.sha256 === 'string' ? peek.sha256.trim() : ''
    if (sha.length === 0) {
      continue
    }
    let row = new FileRule()
    row.sha256 = sha
    row.level = typeof peek.level === 'string' ? peek.level : ''
    row.reason = typeof peek.reason === 'string' ? peek.reason : ''
    kept.push(row)
  }
  return kept
}

function readHeuristics(rows: Object[], pack: RuleLoad): HeuristicRule[] {
  let kept: HeuristicRule[] = []
  for (let i = 0; i < rows.length; i++) {
    let peek = rows[i] as HeuristicRule
    let permissions = readPermissions(peek.permissions)
    if (permissions.length < 2) {
      pack.disabled++
      continue
    }
    let level = typeof peek.level === 'string' ? peek.level : 'suspicious'
    if (level === 'risk') {
      hilog.error(DOMAIN, TAG, 'heuristic level downgraded')
      level = 'suspicious'
    }
    let row = new HeuristicRule()
    row.id = typeof peek.id === 'string' ? peek.id : ''
    row.permissions = permissions
    row.reason = typeof peek.reason === 'string' ? peek.reason : ''
    row.level = level
    kept.push(row)
  }
  return kept
}

function readPermissions(value: string[] | undefined): string[] {
  let kept: string[] = []
  if (!(value instanceof Array)) {
    return kept
  }
  for (let i = 0; i < value.length; i++) {
    if (typeof value[i] === 'string' && value[i].length > 0) {
      kept.push(value[i])
    }
  }
  return kept
}
