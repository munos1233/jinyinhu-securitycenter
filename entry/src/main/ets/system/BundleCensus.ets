import type { BusinessError } from '@ohos.base';
import bundleManager from '@ohos.bundle.bundleManager';
import util from '@ohos.util';
import { hilog } from '@kit.PerformanceAnalysisKit';
import { CenterError } from '../center/CenterError';
import type { BundleRow, CertAlgo, CloudState, InstallSource, RiskLevel, Verdict, VerdictSource } from '../center/CenterTypes';
import { BundleFinger } from '../engine/BundleFinger';
import type { SystemGate } from './SystemGate';

const DOMAIN: number = 0x4A59
const TAG: string = 'Center'

export interface BundleCensus {
  list(): Promise<BundleRow[]>
}

export class RawBundle {
  bundleName: string = ''
  versionName: string = ''
  versionCode: number = 0
  fingerprint: string = ''
  certificate: Uint8Array = new Uint8Array(0)
  permissions: string[] = []
  installSource: string = ''
  hasInstallSource: boolean = false
}

export class RawSignature {
  fingerprint: string = ''
  certificate: Uint8Array = new Uint8Array(0)
}

export interface BundleSource {
  listAll(): Promise<RawBundle[]>
  signatureOf(bundleName: string): Promise<RawSignature>
}

class PendingVerdict implements Verdict {
  level: RiskLevel = 'unknown'
  source: VerdictSource = 'system'
  reason: string = ''
  evidence: string = ''
  cloud: CloudState = 'unchecked'
}

class Row implements BundleRow {
  bundleName: string = ''
  version: string = ''
  versionCode: number = 0
  certSha256: string = ''
  certAlgo: CertAlgo = 'none'
  declaredPermissions: string[] = []
  source: InstallSource = 'unknown'
  verdict: Verdict = new PendingVerdict()
}

export class GatedBundleCensus implements BundleCensus {
  private gate: SystemGate
  private source: BundleSource

  constructor(gate: SystemGate, source: BundleSource) {
    this.gate = gate
    this.source = source
  }

  async list(): Promise<BundleRow[]> {
    let gate = this.gate.bundles()
    if (gate.status !== 'ready') {
      throw new CenterError('unsupported', gate.reason)
    }
    let raws: RawBundle[]
    try {
      raws = await this.source.listAll()
    } catch (err) {
      let raw = 'getAllBundleInfo:' + codeOf(err as Object)
      hilog.error(DOMAIN, TAG, 'census list failed: %{public}s', raw)
      throw new CenterError('unsupported', raw)
    }
    let rows: Row[] = []
    let sourceKnown = false
    for (let i = 0; i < raws.length; i++) {
      if (raws[i].hasInstallSource) {
        sourceKnown = true
      }
      rows.push(await this.row(raws[i]))
    }
    if (!sourceKnown && rows.length > 0) {
      hilog.info(DOMAIN, TAG, 'census install source field absent, all unknown')
    }
    rows.sort((a: Row, b: Row): number => a.bundleName < b.bundleName ? -1 : (a.bundleName > b.bundleName ? 1 : 0))
    return rows
  }

  private async row(raw: RawBundle): Promise<Row> {
    let row = new Row()
    row.bundleName = raw.bundleName
    row.version = raw.versionName
    row.versionCode = raw.versionCode
    row.declaredPermissions = raw.permissions.slice()
    row.source = raw.hasInstallSource ? installSourceOf(raw.installSource) : 'unknown'
    let cert = BundleFinger.read(raw.fingerprint, raw.certificate)
    if (cert.certAlgo === 'none') {
      try {
        let signature = await this.source.signatureOf(raw.bundleName)
        cert = BundleFinger.read(signature.fingerprint, signature.certificate)
      } catch (err) {
        hilog.warn(DOMAIN, TAG, 'census signature unreadable %{public}s: %{public}s', raw.bundleName,
          codeOf(err as Object))
      }
    }
    row.certSha256 = cert.certSha256
    row.certAlgo = cert.certAlgo
    return row
  }
}

/**
 * pre-installed / ota / recovery 是预置应用。其余值是安装方的包名或 unknown，
 * 分不出商店与侧载，只能是 unknown。
 */
export function installSourceOf(value: string): InstallSource {
  let text = value.trim()
  if (text === 'pre-installed' || text === 'ota' || text === 'recovery') {
    return 'preinstalled'
  }
  return 'unknown'
}

function codeOf(err: Object): string {
  try {
    let code = (err as BusinessError).code
    if (code !== undefined && code !== null) {
      return String(code)
    }
  } catch (e) {
  }
  return 'error'
}

const LIST_FLAGS: number = bundleManager.BundleFlag.GET_BUNDLE_INFO_WITH_APPLICATION |
  bundleManager.BundleFlag.GET_BUNDLE_INFO_WITH_REQUESTED_PERMISSION |
  bundleManager.BundleFlag.GET_BUNDLE_INFO_WITH_SIGNATURE_INFO

export class SdkBundleSource implements BundleSource {
  async listAll(): Promise<RawBundle[]> {
    let infos = await bundleManager.getAllBundleInfo(LIST_FLAGS)
    let out: RawBundle[] = []
    for (let i = 0; i < infos.length; i++) {
      out.push(rawOf(infos[i]))
    }
    return out
  }

  async signatureOf(bundleName: string): Promise<RawSignature> {
    let info = await bundleManager.getBundleInfo(bundleName,
      bundleManager.BundleFlag.GET_BUNDLE_INFO_WITH_SIGNATURE_INFO)
    let signature = new RawSignature()
    signature.fingerprint = fingerprintOf(info)
    signature.certificate = certificateOf(info)
    return signature
  }
}

function rawOf(info: bundleManager.BundleInfo): RawBundle {
  let raw = new RawBundle()
  raw.bundleName = info.name
  raw.versionName = info.versionName
  raw.versionCode = info.versionCode
  raw.fingerprint = fingerprintOf(info)
  raw.certificate = certificateOf(info)
  let details = info.reqPermissionDetails
  if (details !== undefined && details !== null) {
    for (let i = 0; i < details.length; i++) {
      raw.permissions.push(details[i].name)
    }
  }
  let app = info.appInfo
  if (app !== undefined && app !== null && typeof app.installSource === 'string') {
    raw.installSource = app.installSource
    raw.hasInstallSource = true
  }
  return raw
}

function fingerprintOf(info: bundleManager.BundleInfo): string {
  let signature = info.signatureInfo
  if (signature === undefined || signature === null || typeof signature.fingerprint !== 'string') {
    return ''
  }
  return signature.fingerprint
}

function certificateOf(info: bundleManager.BundleInfo): Uint8Array {
  let signature = info.signatureInfo
  if (signature === undefined || signature === null || typeof signature.certificate !== 'string') {
    return new Uint8Array(0)
  }
  return pemBytes(signature.certificate)
}

export function pemBody(text: string): string {
  let body = ''
  let lines = text.split('\n')
  for (let i = 0; i < lines.length; i++) {
    let line = lines[i].trim()
    if (line.length === 0 || line.indexOf('-----') === 0) {
      continue
    }
    body += line
  }
  return body
}

function pemBytes(text: string): Uint8Array {
  let body = pemBody(text)
  if (body.length === 0) {
    return new Uint8Array(0)
  }
  try {
    return new util.Base64Helper().decodeSync(body)
  } catch (err) {
    hilog.warn(DOMAIN, TAG, 'census certificate not base64')
    return new Uint8Array(0)
  }
}
