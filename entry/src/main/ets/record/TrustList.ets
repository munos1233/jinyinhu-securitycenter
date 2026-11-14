import { hilog } from '@kit.PerformanceAnalysisKit';
import { nowIso } from '../center/Clock';
import type { CertAlgo, TrustEntry, TrustKind } from '../center/CenterTypes';
import { canonicalCert } from '../engine/Decide';
import { Writer } from './Writer';

const DOMAIN: number = 0x4A59
const TAG: string = 'Center'
/** filesDir 内相对路径，对应 filesDir/center/trust.json。 */
const TRUST_PATH: string = 'center/trust.json'

class TrustRow implements TrustEntry {
  kind: TrustKind = 'bundle'
  fingerprint: string = ''
  id: string = ''
  versionCode: number = 0
  at: string = ''
}

export class TrustList {
  static trustBundle(certSha256: string, certAlgo: CertAlgo, bundleName: string, versionCode: number): boolean {
    if (certAlgo === 'none') {
      return false
    }
    let fingerprint = canonicalCert(certSha256)
    if (fingerprint.length === 0) {
      return false
    }
    let rows = TrustList.readRows()
    if (rows === null) {
      return false
    }
    if (TrustList.findBundle(rows, fingerprint, bundleName, versionCode) >= 0) {
      return true
    }
    let row = new TrustRow()
    row.kind = 'bundle'
    row.fingerprint = fingerprint
    row.id = bundleName
    row.versionCode = versionCode
    row.at = nowIso()
    rows.push(row)
    Writer.replaceText(TRUST_PATH, JSON.stringify(rows))
    return true
  }

  static trustFile(sha256: string, uri: string): boolean {
    let fingerprint = canonicalCert(sha256)
    if (fingerprint.length === 0) {
      return false
    }
    let rows = TrustList.readRows()
    if (rows === null) {
      return false
    }
    if (TrustList.findFile(rows, fingerprint) >= 0) {
      return true
    }
    let row = new TrustRow()
    row.kind = 'file-sha256'
    row.fingerprint = fingerprint
    row.id = uri
    row.versionCode = 0
    row.at = nowIso()
    rows.push(row)
    Writer.replaceText(TRUST_PATH, JSON.stringify(rows))
    return true
  }

  static matchesBundle(certSha256: string, bundleName: string, versionCode: number): boolean {
    let fingerprint = canonicalCert(certSha256)
    if (fingerprint.length === 0) {
      return false
    }
    let rows = TrustList.readRows()
    if (rows === null) {
      return false
    }
    return TrustList.findBundle(rows, fingerprint, bundleName, versionCode) >= 0
  }

  static matchesFile(sha256: string): boolean {
    let fingerprint = canonicalCert(sha256)
    if (fingerprint.length === 0) {
      return false
    }
    let rows = TrustList.readRows()
    if (rows === null) {
      return false
    }
    return TrustList.findFile(rows, fingerprint) >= 0
  }

  private static findBundle(rows: TrustRow[], fingerprint: string, bundleName: string, versionCode: number): number {
    for (let i = 0; i < rows.length; i++) {
      let row = rows[i]
      if (row.kind === 'bundle' && row.fingerprint === fingerprint && row.id === bundleName &&
        row.versionCode === versionCode) {
        return i
      }
    }
    return -1
  }

  private static findFile(rows: TrustRow[], sha256: string): number {
    for (let i = 0; i < rows.length; i++) {
      let row = rows[i]
      if (row.kind === 'file-sha256' && row.fingerprint === sha256) {
        return i
      }
    }
    return -1
  }

  private static readRows(): TrustRow[] | null {
    let text = Writer.readText(TRUST_PATH)
    if (text === null || text.length === 0) {
      return []
    }
    try {
      let parsed = JSON.parse(text) as Object[]
      if (!(parsed instanceof Array)) {
        hilog.error(DOMAIN, TAG, 'trust.json parse failed')
        return null
      }
      let rows: TrustRow[] = []
      for (let i = 0; i < parsed.length; i++) {
        rows.push(TrustList.rowFrom(parsed[i]))
      }
      return rows
    } catch (err) {
      hilog.error(DOMAIN, TAG, 'trust.json parse failed')
      return null
    }
  }

  private static rowFrom(raw: Object): TrustRow {
    let peek = raw as TrustRow
    let row = new TrustRow()
    row.kind = peek.kind === 'file-sha256' ? 'file-sha256' : 'bundle'
    row.fingerprint = typeof peek.fingerprint === 'string' ? peek.fingerprint : ''
    row.id = typeof peek.id === 'string' ? peek.id : ''
    row.versionCode = typeof peek.versionCode === 'number' ? peek.versionCode : 0
    row.at = typeof peek.at === 'string' ? peek.at : ''
    return row
  }
}
