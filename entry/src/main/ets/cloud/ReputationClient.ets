import cryptoFramework from '@ohos.security.cryptoFramework';
import http from '@ohos.net.http';
import util from '@ohos.util';
import { hilog } from '@kit.PerformanceAnalysisKit';
import type { CancelFlag, CloudBatch, CloudView, QueryKey } from '../center/CenterTypes';
import { cloudBatch, cloudTimeoutMs } from '../center/CenterLimits';
import { ResponseCheck } from './ResponseCheck';
import type { ReputationResponse, SignatureVerifier } from './ResponseCheck';

const DOMAIN: number = 0x4A59
const TAG: string = 'Center'

export const OFFLINE: string = '未联网'
export const UNCONFIGURED: string = '未联网，云服务未配置'
export const INVALID: string = '未联网，云端结果无效'

const QUERY_PATH: string = '/reputation/query'
const HINT_PATH: string = '/reputation/hint'
const NONCE_BYTES: number = 16
const CANCEL_POLL_MS: number = 100

/** 服务地址只接受 https。公钥是 rules/reputation_pub.pem 的文本，缺失为空串。 */
export interface CloudConfig {
  endpoint(): string
  publicKey(): string
}

export class CloudReply {
  status: number = 0
  body: string = ''
}

export interface CloudCall {
  reply: Promise<CloudReply>
  abort(): void
}

export interface CloudTransport {
  post(url: string, body: string, timeoutMs: number): CloudCall
}

export interface CloudTimer {
  start(ms: number, fire: () => void): number
  stop(handle: number): void
}

/** 读本次作业的取消标志。缓冲区实现在 task/CancelFlag。 */
export type CancelRead = (flag: CancelFlag) => boolean

export type RandomBytes = (count: number) => Uint8Array

export type VerifierFactory = (publicKeyPem: string) => SignatureVerifier

export type HintResult = 'sent' | 'offline' | 'unconfigured'

class View implements CloudView {
  state: 'unchecked' | 'offline' | 'reached' = 'offline'
  level: 'ok' | 'unknown' | 'risk' | 'none' = 'none'
  reason: string = OFFLINE
  evidence: string = ''
}

class WireKey implements QueryKey {
  bundleName: string = ''
  versionCode: number = 0
  certSha256: string = ''
  sha256: string = ''
}

class WireQuery {
  nonce: string = ''
  items: WireKey[] = []
}

type Ending = 'reply' | 'timeout' | 'cancelled' | 'failed'

class Outcome {
  ending: Ending = 'failed'
  reply: CloudReply = new CloudReply()
}

class Service {
  base: string = ''
  publicKey: string = ''
}

export class ReputationClient implements CloudBatch {
  private config: CloudConfig
  private transport: CloudTransport
  private cancelled: CancelRead
  private random: RandomBytes
  private verifierOf: VerifierFactory
  private timer: CloudTimer

  constructor(config: CloudConfig, transport: CloudTransport, cancelled: CancelRead,
    random: RandomBytes = secureRandom, verifierOf: VerifierFactory = ecdsaVerifier,
    timer: CloudTimer = new SystemTimer()) {
    this.config = config
    this.transport = transport
    this.cancelled = cancelled
    this.random = random
    this.verifierOf = verifierOf
    this.timer = timer
  }

  async query(keys: QueryKey[], cancel: CancelFlag): Promise<CloudView[]> {
    let service = this.service()
    if (service === null) {
      return offlineAll(keys.length, UNCONFIGURED)
    }
    let out: CloudView[] = []
    for (let start = 0; start < keys.length; start += cloudBatch) {
      let batch = keys.slice(start, start + cloudBatch)
      let views = await this.batch(service, batch, cancel)
      for (let i = 0; i < views.length; i++) {
        out.push(views[i])
      }
    }
    return out
  }

  /** 仅当用户在该行点「提交检测」。正文只有一个 QueryKey。 */
  async hint(key: QueryKey, cancel: CancelFlag): Promise<HintResult> {
    let service = this.service()
    if (service === null) {
      return 'unconfigured'
    }
    let outcome = await this.send(service.base + HINT_PATH, JSON.stringify(wireKey(key)), cancel)
    if (outcome.ending !== 'reply' || outcome.reply.status !== 200) {
      hilog.warn(DOMAIN, TAG, 'cloud hint %{public}s status %{public}d', outcome.ending, outcome.reply.status)
      return 'offline'
    }
    return 'sent'
  }

  private service(): Service | null {
    let base = ''
    let publicKey = ''
    try {
      base = normalBase(this.config.endpoint())
      publicKey = this.config.publicKey()
    } catch (err) {
      hilog.warn(DOMAIN, TAG, 'cloud config unreadable')
      return null
    }
    if (base.length === 0 || typeof publicKey !== 'string' || publicKey.trim().length === 0) {
      return null
    }
    let service = new Service()
    service.base = base
    service.publicKey = publicKey
    return service
  }

  private async batch(service: Service, keys: QueryKey[], cancel: CancelFlag): Promise<CloudView[]> {
    if (keys.length === 0) {
      return []
    }
    let nonce = ''
    try {
      nonce = hexOf(this.random(NONCE_BYTES))
    } catch (err) {
      hilog.error(DOMAIN, TAG, 'cloud nonce unavailable')
    }
    if (!/^[0-9a-f]{32}$/.test(nonce)) {
      return offlineAll(keys.length, OFFLINE)
    }
    let request = new WireQuery()
    request.nonce = nonce
    request.items = keys.map((key: QueryKey): WireKey => wireKey(key))
    let outcome = await this.send(service.base + QUERY_PATH, JSON.stringify(request), cancel)
    if (outcome.ending !== 'reply') {
      hilog.warn(DOMAIN, TAG, 'cloud query %{public}s', outcome.ending)
      return offlineAll(keys.length, OFFLINE)
    }
    if (outcome.reply.status !== 200) {
      hilog.warn(DOMAIN, TAG, 'cloud query status %{public}d', outcome.reply.status)
      return offlineAll(keys.length, OFFLINE)
    }
    let response = parseResponse(outcome.reply.body)
    if (response === null) {
      hilog.warn(DOMAIN, TAG, 'cloud query body not json object')
      return offlineAll(keys.length, OFFLINE)
    }
    let verify: SignatureVerifier
    try {
      verify = this.verifierOf(service.publicKey)
    } catch (err) {
      hilog.error(DOMAIN, TAG, 'cloud public key unusable')
      return offlineAll(keys.length, INVALID)
    }
    let checked = ResponseCheck.accept(request.items, nonce, response, verify)
    if (!checked.accepted) {
      hilog.warn(DOMAIN, TAG, 'cloud batch rejected')
    }
    return checked.views
  }

  private send(url: string, body: string, cancel: CancelFlag): Promise<Outcome> {
    return new Promise<Outcome>((resolve: (outcome: Outcome) => void): void => {
      if (this.isCancelled(cancel)) {
        resolve(ended('cancelled'))
        return
      }
      let call: CloudCall
      try {
        call = this.transport.post(url, body, cloudTimeoutMs)
      } catch (err) {
        resolve(ended('failed'))
        return
      }
      let settled = false
      let deadline = -1
      let poll = -1
      let finish = (outcome: Outcome): void => {
        if (settled) {
          return
        }
        settled = true
        this.timer.stop(deadline)
        this.timer.stop(poll)
        if (outcome.ending !== 'reply') {
          try {
            call.abort()
          } catch (err) {
          }
        }
        resolve(outcome)
      }
      let watch = (): void => {
        if (settled) {
          return
        }
        if (this.isCancelled(cancel)) {
          finish(ended('cancelled'))
          return
        }
        poll = this.timer.start(CANCEL_POLL_MS, watch)
      }
      deadline = this.timer.start(cloudTimeoutMs, (): void => finish(ended('timeout')))
      watch()
      call.reply.then((reply: CloudReply): void => {
        let outcome = ended('reply')
        outcome.reply = reply
        finish(outcome)
      }, (): void => finish(ended('failed')))
    })
  }

  private isCancelled(cancel: CancelFlag): boolean {
    try {
      return this.cancelled(cancel) === true
    } catch (err) {
      return false
    }
  }
}

/** 只复制四个查询键。uri、路径、标签、声明权限不出本机。 */
function wireKey(key: QueryKey): WireKey {
  let wire = new WireKey()
  wire.bundleName = typeof key.bundleName === 'string' ? key.bundleName : ''
  wire.versionCode = typeof key.versionCode === 'number' ? key.versionCode : 0
  wire.certSha256 = typeof key.certSha256 === 'string' ? key.certSha256 : ''
  wire.sha256 = typeof key.sha256 === 'string' ? key.sha256 : ''
  return wire
}

function normalBase(endpoint: string): string {
  if (typeof endpoint !== 'string') {
    return ''
  }
  let base = endpoint.trim()
  if (base.indexOf('https://') !== 0 || base.length <= 'https://'.length) {
    return ''
  }
  while (base.charAt(base.length - 1) === '/') {
    base = base.substring(0, base.length - 1)
  }
  return base
}

function parseResponse(body: string): ReputationResponse | null {
  if (typeof body !== 'string' || body.length === 0) {
    return null
  }
  let parsed: Object
  try {
    parsed = JSON.parse(body) as Object
  } catch (err) {
    return null
  }
  if (parsed === null || typeof parsed !== 'object' || parsed instanceof Array) {
    return null
  }
  return parsed as ReputationResponse
}

function ended(ending: Ending): Outcome {
  let outcome = new Outcome()
  outcome.ending = ending
  return outcome
}

function offlineAll(count: number, reason: string): CloudView[] {
  let out: CloudView[] = []
  for (let i = 0; i < count; i++) {
    let view = new View()
    view.reason = reason
    out.push(view)
  }
  return out
}

function hexOf(bytes: Uint8Array): string {
  if (!(bytes instanceof Uint8Array) || bytes.length !== NONCE_BYTES) {
    return ''
  }
  let out = ''
  for (let i = 0; i < bytes.length; i++) {
    out += (bytes[i] < 16 ? '0' : '') + bytes[i].toString(16)
  }
  return out
}

export function secureRandom(count: number): Uint8Array {
  return cryptoFramework.createRandom().generateRandomSync(count).data
}

function pemDer(pem: string): Uint8Array {
  let body = ''
  let lines = pem.split('\n')
  for (let i = 0; i < lines.length; i++) {
    let line = lines[i].trim()
    if (line.length === 0 || line.indexOf('-----') === 0) {
      continue
    }
    body += line
  }
  return new util.Base64Helper().decodeSync(body)
}

/** 公钥是 P-256 的 SubjectPublicKeyInfo，签名是 DER 编码的 ECDSA。 */
export function ecdsaVerifier(publicKeyPem: string): SignatureVerifier {
  let generator = cryptoFramework.createAsyKeyGenerator('ECC256')
  let pair = generator.convertKeySync({ data: pemDer(publicKeyPem) }, null)
  return (message: Uint8Array, signature: string): boolean => {
    let verifier = cryptoFramework.createVerify('ECC256|SHA256')
    verifier.initSync(pair.pubKey)
    let raw = new util.Base64Helper().decodeSync(signature)
    return verifier.verifySync({ data: message }, { data: raw })
  }
}

export class SystemTimer implements CloudTimer {
  start(ms: number, fire: () => void): number {
    return setTimeout(fire, ms)
  }

  stop(handle: number): void {
    clearTimeout(handle)
  }
}

class HttpCall implements CloudCall {
  reply: Promise<CloudReply>
  private client: http.HttpRequest
  private closed: boolean = false

  constructor(client: http.HttpRequest, reply: Promise<CloudReply>) {
    this.client = client
    this.reply = reply
  }

  abort(): void {
    this.close()
  }

  close(): void {
    if (this.closed) {
      return
    }
    this.closed = true
    this.client.destroy()
  }
}

export class HttpCloudTransport implements CloudTransport {
  post(url: string, body: string, timeoutMs: number): CloudCall {
    let client = http.createHttp()
    let options: http.HttpRequestOptions = {
      method: http.RequestMethod.POST,
      header: { 'Content-Type': 'application/json' },
      extraData: body,
      expectDataType: http.HttpDataType.STRING,
      usingCache: false,
      connectTimeout: timeoutMs,
      readTimeout: timeoutMs
    }
    let call: HttpCall | null = null
    let reply = client.request(url, options).then((response: http.HttpResponse): CloudReply => {
      let out = new CloudReply()
      out.status = response.responseCode
      out.body = typeof response.result === 'string' ? response.result : ''
      return out
    }).finally((): void => {
      if (call !== null) {
        call.close()
      }
    })
    call = new HttpCall(client, reply)
    return call
  }
}
