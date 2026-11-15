import type { CloudView, QueryKey } from '../center/CenterTypes'
import { cloudAlg, cloudKid } from '../center/CenterLimits'

const INVALID: string = '未联网，云端结果无效'

export interface ReputationItem extends QueryKey {
  level: string
  reason: string
  evidence: string
}

export interface ReputationResponse {
  alg: string
  kid: string
  nonce: string
  version: string
  items: ReputationItem[]
  signature: string
}

export type SignatureVerifier = (message: Uint8Array, signature: string) => boolean

export class CheckedResponse {
  views: CloudView[] = []
  version: string = ''
  accepted: boolean = false
}

class CloudResult implements CloudView {
  state: 'unchecked' | 'offline' | 'reached' = 'offline'
  level: 'ok' | 'unknown' | 'risk' | 'none' = 'none'
  reason: string = INVALID
  evidence: string = ''
}

export class ResponseCheck {
  static accept(keys: QueryKey[], nonce: string, response: ReputationResponse | null,
    verify: SignatureVerifier): CheckedResponse {
    let rejected = rejectBatch(keys.length)
    if (!validResponse(keys, nonce, response) || response === null) {
      return rejected
    }
    let result = new CheckedResponse()
    result.version = response.version
    let signature = response.signature
    let text = nonce + '\n' + result.version + '\n'
    let lines: string[] = []
    for (let i = 0; i < response.items.length; i++) {
      let item = response.items[i]
      lines.push([item.bundleName, String(item.versionCode), item.certSha256, item.sha256,
        item.level, item.reason, item.evidence].join('|'))
      let view = new CloudResult()
      if (item.level === 'ok' || item.level === 'unknown' || item.level === 'risk') {
        view.state = 'reached'
        view.level = item.level
        view.reason = item.reason
        view.evidence = item.evidence
      }
      result.views.push(view)
    }
    let verified = false
    try {
      verified = verify(encodeUtf8(text + lines.join('\n')), signature)
    } catch (err) {
      return rejected
    }
    if (verified !== true) {
      return rejected
    }
    result.accepted = true
    return result
  }
}

function rejectBatch(count: number): CheckedResponse {
  let result = new CheckedResponse()
  for (let i = 0; i < count; i++) {
    result.views.push(new CloudResult())
  }
  return result
}

function validResponse(keys: QueryKey[], nonce: string, response: ReputationResponse | null): boolean {
  if (response === null || typeof response !== 'object' || response instanceof Array ||
    !cleanField(nonce) || !cleanField(response.alg) || !cleanField(response.kid) ||
    !cleanField(response.nonce) || !cleanField(response.version) ||
    !cleanField(response.signature) || response.signature.length === 0 ||
    response.alg !== cloudAlg || response.kid !== cloudKid || response.nonce !== nonce ||
    !(response.items instanceof Array) || response.items.length !== keys.length) {
    return false
  }
  for (let i = 0; i < keys.length; i++) {
    let key = keys[i]
    let item = response.items[i]
    if (!validKey(key) || !validKey(item) || !cleanField(item.level) ||
      !cleanField(item.reason) || !cleanField(item.evidence) ||
      item.bundleName !== key.bundleName || item.versionCode !== key.versionCode ||
      item.certSha256 !== key.certSha256 || item.sha256 !== key.sha256) {
      return false
    }
  }
  return true
}

function validKey(key: QueryKey): boolean {
  return key !== null && typeof key === 'object' && !(key instanceof Array) &&
    cleanField(key.bundleName) && cleanField(key.certSha256) && cleanField(key.sha256) &&
    typeof key.versionCode === 'number' && Number.isSafeInteger(key.versionCode) && key.versionCode >= 0
}

function cleanField(value: string): boolean {
  return typeof value === 'string' && value.indexOf('|') < 0 && value.indexOf('\n') < 0 &&
    value.indexOf('\r') < 0
}

function encodeUtf8(value: string): Uint8Array {
  let bytes: number[] = []
  for (let i = 0; i < value.length; i++) {
    let code = value.charCodeAt(i)
    if (code >= 0xd800 && code <= 0xdbff) {
      let low = value.charCodeAt(i + 1)
      if (low >= 0xdc00 && low <= 0xdfff) {
        code = 0x10000 + (code - 0xd800) * 0x400 + low - 0xdc00
        i++
      } else {
        code = 0xfffd
      }
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      code = 0xfffd
    }
    if (code < 0x80) {
      bytes.push(code)
    } else if (code < 0x800) {
      bytes.push(0xc0 | (code >> 6), 0x80 | (code & 0x3f))
    } else if (code < 0x10000) {
      bytes.push(0xe0 | (code >> 12), 0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f))
    } else {
      bytes.push(0xf0 | (code >> 18), 0x80 | ((code >> 12) & 0x3f),
        0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f))
    }
  }
  return new Uint8Array(bytes)
}
