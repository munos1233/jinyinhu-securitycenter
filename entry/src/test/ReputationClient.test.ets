import type { CancelFlag, CloudView, QueryKey } from '../main/ets/center/CenterTypes'
import { cloudBatch, cloudTimeoutMs } from '../main/ets/center/CenterLimits'
import { CloudReply, INVALID, OFFLINE, ReputationClient, UNCONFIGURED } from '../main/ets/cloud/ReputationClient'
import type { CloudCall, CloudConfig, CloudTimer, CloudTransport } from '../main/ets/cloud/ReputationClient'
import type { SignatureVerifier } from '../main/ets/cloud/ResponseCheck'

const BASE: string = 'https://reputation.example'
const PEM: string = '-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n'
const URI: string = 'file:///storage/Users/currentUser/Download/secret-report.hap'
const PATH: string = '/storage/Users/currentUser/Download/secret-report.hap'
const LABEL: string = '机密报表'
const DECLARED: string = 'ohos.permission.READ_CONTACTS'

function fail(message: string): void {
  throw new Error(message)
}

function require(ok: boolean, message: string): void {
  if (!ok) {
    fail(message)
  }
}

class Config implements CloudConfig {
  base: string = BASE
  key: string = PEM

  endpoint(): string {
    return this.base
  }

  publicKey(): string {
    return this.key
  }
}

class ManualCall implements CloudCall {
  reply: Promise<CloudReply>
  aborted: boolean = false
  url: string = ''
  body: string = ''
  timeoutMs: number = 0
  private done: (reply: CloudReply) => void = (): void => {}
  private broken: (err: Error) => void = (): void => {}

  constructor() {
    this.reply = new Promise<CloudReply>((resolve: (reply: CloudReply) => void, reject: (err: Error) => void): void => {
      this.done = resolve
      this.broken = reject
    })
  }

  answer(status: number, body: string): void {
    let reply = new CloudReply()
    reply.status = status
    reply.body = body
    this.done(reply)
  }

  error(): void {
    this.broken(new Error('network'))
  }

  abort(): void {
    this.aborted = true
  }
}

class Transport implements CloudTransport {
  calls: ManualCall[] = []

  post(url: string, body: string, timeoutMs: number): CloudCall {
    let call = new ManualCall()
    call.url = url
    call.body = body
    call.timeoutMs = timeoutMs
    this.calls.push(call)
    return call
  }
}

class PendingTimer {
  ms: number = 0
  fire: () => void = (): void => {}
}

class ManualTimer implements CloudTimer {
  next: number = 1
  pending: Map<number, PendingTimer> = new Map()
  started: number[] = []

  start(ms: number, fire: () => void): number {
    let handle = this.next++
    let timer = new PendingTimer()
    timer.ms = ms
    timer.fire = fire
    this.pending.set(handle, timer)
    this.started.push(ms)
    return handle
  }

  stop(handle: number): void {
    this.pending.delete(handle)
  }

  fireAll(ms: number): void {
    let due: PendingTimer[] = []
    this.pending.forEach((timer: PendingTimer, handle: number): void => {
      if (timer.ms === ms) {
        due.push(timer)
        this.pending.delete(handle)
      }
    })
    for (let timer of due) {
      timer.fire()
    }
  }
}

class Flag implements CancelFlag {
  stopped: boolean = false
}

function readFlag(flag: CancelFlag): boolean {
  return (flag as Flag).stopped
}

class Counter {
  value: number = 0
}

function randomFrom(counter: Counter): (count: number) => Uint8Array {
  return (count: number): Uint8Array => {
    counter.value++
    let bytes = new Uint8Array(count)
    for (let i = 0; i < count; i++) {
      bytes[i] = (counter.value * 37 + i * 11) & 0xff
    }
    return bytes
  }
}

function asciiOf(bytes: Uint8Array): string {
  let out = ''
  for (let i = 0; i < bytes.length; i++) {
    out += String.fromCharCode(bytes[i])
  }
  return out
}

function sign(text: string): string {
  let sum = 0
  for (let i = 0; i < text.length; i++) {
    sum = (sum * 31 + text.charCodeAt(i)) % 1000000007
  }
  return 'sig' + sum.toString()
}

class Verifiers {
  keys: string[] = []

  factory(): (pem: string) => SignatureVerifier {
    return (pem: string): SignatureVerifier => {
      this.keys.push(pem)
      return (message: Uint8Array, signature: string): boolean => signature === sign(asciiOf(message))
    }
  }
}

class Rig {
  config: Config = new Config()
  transport: Transport = new Transport()
  timer: ManualTimer = new ManualTimer()
  counter: Counter = new Counter()
  verifiers: Verifiers = new Verifiers()
  client: ReputationClient

  constructor() {
    this.client = new ReputationClient(this.config, this.transport, readFlag, randomFrom(this.counter),
      this.verifiers.factory(), this.timer)
  }
}

class Leaky implements QueryKey {
  bundleName: string = ''
  versionCode: number = 0
  certSha256: string = ''
  sha256: string = ''
  id: string = URI
  uri: string = URI
  path: string = PATH
  label: string = LABEL
  version: string = '1.0.0'
  declaredPermissions: string[] = [DECLARED]
}

function key(bundleName: string, versionCode: number, sha256: string): QueryKey {
  let k = new Leaky()
  k.bundleName = bundleName
  k.versionCode = versionCode
  k.certSha256 = bundleName.length > 0 ? 'ab'.repeat(32) : ''
  k.sha256 = sha256
  return k
}

class SentItem {
  bundleName: string = ''
  versionCode: number = 0
  certSha256: string = ''
  sha256: string = ''
}

class Sent {
  nonce: string = ''
  items: SentItem[] = []
}

function signedBody(call: ManualCall, levels: string[], nonce: string = ''): string {
  let sent = JSON.parse(call.body) as Sent
  let echo = nonce.length > 0 ? nonce : sent.nonce
  let lines: string[] = []
  let items: Object[] = []
  for (let i = 0; i < sent.items.length; i++) {
    let item = sent.items[i]
    let level = levels[i % levels.length]
    lines.push([item.bundleName, item.versionCode.toString(), item.certSha256, item.sha256, level, 'r' + i, 'e' + i].join('|'))
    items.push({ bundleName: item.bundleName, versionCode: item.versionCode, certSha256: item.certSha256,
      sha256: item.sha256, level: level, reason: 'r' + i, evidence: 'e' + i } as Object)
  }
  let text = echo + '\n2026.11.15\n' + lines.join('\n')
  return JSON.stringify({ alg: 'SHA256withECDSA', kid: 'primary', nonce: echo, version: '2026.11.15',
    items: items, signature: sign(text) } as Object)
}

function tick(): Promise<void> {
  return new Promise<void>((resolve: () => void): void => {
    setTimeout(resolve, 0)
  })
}

function allOffline(views: CloudView[], count: number, reason: string): boolean {
  return views.length === count && views.every((view: CloudView): boolean =>
    view.state === 'offline' && view.level === 'none' && view.reason === reason)
}

async function checkUnconfigured(): Promise<void> {
  for (let variant of ['no-endpoint', 'no-key', 'blank-key', 'http']) {
    let rig = new Rig()
    if (variant === 'no-endpoint') {
      rig.config.base = ''
    } else if (variant === 'no-key') {
      rig.config.key = ''
    } else if (variant === 'blank-key') {
      rig.config.key = '  \n'
    } else {
      rig.config.base = 'http://reputation.example'
    }
    let views = await rig.client.query([key('com.example.a', 1, ''), key('', 0, 'cd'.repeat(32))], new Flag())
    require(rig.transport.calls.length === 0, variant + '：没有公钥或服务地址时不发请求')
    require(allOffline(views, 2, UNCONFIGURED), variant + '：state=offline，level=none，原因「未联网，云服务未配置」')
    require(await rig.client.hint(key('com.example.a', 1, ''), new Flag()) === 'unconfigured' &&
      rig.transport.calls.length === 0, variant + '：提交检测同样不发请求')
  }
}

async function checkBody(): Promise<void> {
  let rig = new Rig()
  let pending = rig.client.query([key('com.example.a', 7, ''), key('', 0, 'cd'.repeat(32))], new Flag())
  require(rig.transport.calls.length === 1, '发出一次请求')
  let call = rig.transport.calls[0]
  require(call.url === BASE + '/reputation/query', '请求 POST /reputation/query')
  require(call.timeoutMs === cloudTimeoutMs && rig.timer.started.indexOf(cloudTimeoutMs) >= 0, '超时用 cloudTimeoutMs')
  for (let leak of [URI, PATH, LABEL, DECLARED, 'secret-report', '1.0.0', '"id"', '"uri"', '"label"', '"version"']) {
    require(call.body.indexOf(leak) < 0, '请求正文不得包含 ' + leak)
  }
  let sent = JSON.parse(call.body) as Record<string, Object>
  require(Object.keys(sent).join(',') === 'nonce,items', '请求体只有 nonce 和 items')
  let items = sent['items'] as Record<string, Object>[]
  for (let item of items) {
    require(Object.keys(item).join(',') === 'bundleName,versionCode,certSha256,sha256', '每项只有四个查询键')
  }
  require(/^[0-9a-f]{32}$/.test(sent['nonce'] as string), 'nonce 是 32 位十六进制')
  call.answer(200, signedBody(call, ['risk', 'ok']))
  let views = await pending
  require(views.length === 2 && views[0].state === 'reached' && views[0].level === 'risk' &&
    views[1].state === 'reached' && views[1].level === 'ok', '验签通过的结果按下标返回')
  require(rig.verifiers.keys.length === 1 && rig.verifiers.keys[0] === PEM, '用配置的公钥验签')
  require(rig.timer.pending.size === 0, '收到回复后停掉计时器')
}

async function checkNonceIsolation(): Promise<void> {
  let rig = new Rig()
  let light = rig.client.query([key('com.example.light', 1, '')], new Flag())
  let heavy = rig.client.query([key('com.example.heavy', 2, '')], new Flag())
  let a = rig.transport.calls[0]
  let b = rig.transport.calls[1]
  let nonceA = (JSON.parse(a.body) as Sent).nonce
  let nonceB = (JSON.parse(b.body) as Sent).nonce
  require(nonceA !== nonceB, '两次并发的 query 使用不同 nonce')
  b.answer(200, signedBody(b, ['ok']))
  a.answer(200, signedBody(a, ['risk']))
  let viewsA = await light
  let viewsB = await heavy
  require(viewsA[0].state === 'reached' && viewsA[0].level === 'risk', '轻车道收到自己的结果')
  require(viewsB[0].state === 'reached' && viewsB[0].level === 'ok', '重车道收到自己的结果，不因另一次变成未联网')

  let replay = new Rig()
  let first = replay.client.query([key('com.example.a', 1, '')], new Flag())
  let firstCall = replay.transport.calls[0]
  let oldNonce = (JSON.parse(firstCall.body) as Sent).nonce
  firstCall.answer(200, signedBody(firstCall, ['ok']))
  await first
  let second = replay.client.query([key('com.example.a', 1, '')], new Flag())
  let secondCall = replay.transport.calls[1]
  require((JSON.parse(secondCall.body) as Sent).nonce !== oldNonce, '每次 query 重新生成 nonce')
  secondCall.answer(200, signedBody(secondCall, ['ok'], oldNonce))
  require(allOffline(await second, 1, INVALID), '旧的合法响应因 nonce 对不上整批拒绝')
}

async function checkFailures(): Promise<void> {
  let timeout = new Rig()
  let pending = timeout.client.query([key('com.example.a', 1, ''), key('com.example.b', 1, '')], new Flag())
  timeout.timer.fireAll(cloudTimeoutMs)
  require(allOffline(await pending, 2, OFFLINE), '超时是 offline，行内原因「未联网」')
  require(timeout.transport.calls[0].aborted, '超时后中止这次请求')

  for (let variant of ['500', '204', 'bad-json', 'array', 'network']) {
    let rig = new Rig()
    let views = rig.client.query([key('com.example.a', 1, '')], new Flag())
    let call = rig.transport.calls[0]
    if (variant === 'bad-json') {
      call.answer(200, '{"alg":')
    } else if (variant === 'array') {
      call.answer(200, '[]')
    } else if (variant === 'network') {
      call.error()
    } else {
      call.answer(Number(variant), signedBody(call, ['ok']))
    }
    require(allOffline(await views, 1, OFFLINE), variant + '：offline，行内原因「未联网」')
  }

  let forged = new Rig()
  let forgedViews = forged.client.query([key('com.example.a', 1, ''), key('com.example.b', 1, '')], new Flag())
  let forgedCall = forged.transport.calls[0]
  forgedCall.answer(200, signedBody(forgedCall, ['ok']).replace(/"signature":"sig\d+"/, '"signature":"sig1"'))
  require(allOffline(await forgedViews, 2, INVALID), '验签失败整批拒绝，原因「未联网，云端结果无效」')

  let badLevel = new Rig()
  let badViews = badLevel.client.query([key('com.example.a', 1, ''), key('com.example.b', 1, '')], new Flag())
  let badCall = badLevel.transport.calls[0]
  badCall.answer(200, signedBody(badCall, ['malware', 'risk']))
  let views = await badViews
  require(views[0].state === 'offline' && views[0].reason === INVALID && views[1].state === 'reached',
    '单条 level 非法只收这一条')

  let broken = new Rig()
  broken.client = new ReputationClient(broken.config, broken.transport, readFlag, (count: number): Uint8Array => {
    throw new Error('no entropy ' + count)
  }, broken.verifiers.factory(), broken.timer)
  require(allOffline(await broken.client.query([key('com.example.a', 1, '')], new Flag()), 1, OFFLINE) &&
    broken.transport.calls.length === 0, '拿不到安全随机数时不发请求')
}

async function checkCancel(): Promise<void> {
  let rig = new Rig()
  let flagA = new Flag()
  let flagB = new Flag()
  let a = rig.client.query([key('com.example.a', 1, '')], flagA)
  let b = rig.client.query([key('com.example.b', 1, '')], flagB)
  let callA = rig.transport.calls[0]
  let callB = rig.transport.calls[1]
  flagA.stopped = true
  for (let i = 0; i < 3; i++) {
    let polls: number[] = []
    rig.timer.pending.forEach((timer: PendingTimer): void => {
      if (timer.ms !== cloudTimeoutMs) {
        polls.push(timer.ms)
      }
    })
    if (polls.length > 0) {
      rig.timer.fireAll(polls[0])
    }
  }
  require(allOffline(await a, 1, OFFLINE) && callA.aborted, '取消只结束本次请求')
  require(!callB.aborted, '取消不得中止另一次正在飞的请求')
  callB.answer(200, signedBody(callB, ['risk']))
  let viewsB = await b
  require(viewsB[0].state === 'reached' && viewsB[0].level === 'risk', '另一次请求不被整批标成 offline')

  let early = new Rig()
  let stopped = new Flag()
  stopped.stopped = true
  require(allOffline(await early.client.query([key('com.example.a', 1, '')], stopped), 1, OFFLINE) &&
    early.transport.calls.length === 0, '已取消时不发请求')
}

async function checkBatches(): Promise<void> {
  let rig = new Rig()
  let keys: QueryKey[] = []
  for (let i = 0; i < cloudBatch + 3; i++) {
    keys.push(key('com.example.app' + i, i, ''))
  }
  let pending = rig.client.query(keys, new Flag())
  require(rig.transport.calls.length === 1 && (JSON.parse(rig.transport.calls[0].body) as Sent).items.length === cloudBatch,
    '一批最多 cloudBatch 个查询键')
  rig.transport.calls[0].answer(200, signedBody(rig.transport.calls[0], ['ok']))
  await tick()
  require(rig.transport.calls.length === 2, '第二批在第一批之后发出')
  let second = rig.transport.calls[1]
  require((JSON.parse(second.body) as Sent).items.length === 3, '剩余查询键在第二批')
  require((JSON.parse(second.body) as Sent).nonce !== (JSON.parse(rig.transport.calls[0].body) as Sent).nonce,
    '每批用自己的 nonce')
  second.answer(200, signedBody(second, ['risk']))
  let views = await pending
  require(views.length === keys.length && views[0].level === 'ok' && views[cloudBatch].level === 'risk',
    '结果按查询键顺序拼接')
}

async function checkHint(): Promise<void> {
  let rig = new Rig()
  let pending = rig.client.hint(key('', 0, 'cd'.repeat(32)), new Flag())
  let call = rig.transport.calls[0]
  require(call.url === BASE + '/reputation/hint', '提交检测 POST /reputation/hint')
  let sent = JSON.parse(call.body) as Record<string, Object>
  require(Object.keys(sent).join(',') === 'bundleName,versionCode,certSha256,sha256', '正文只有一个 QueryKey')
  require(call.body.indexOf(URI) < 0 && call.body.indexOf(LABEL) < 0, '提交检测不上传 uri 和标签')
  call.answer(200, '')
  require(await pending === 'sent', '200 即已提交')

  let down = new Rig()
  let failed = down.client.hint(key('com.example.a', 1, ''), new Flag())
  down.transport.calls[0].answer(503, '')
  require(await failed === 'offline', '非 200 是未联网')
}

export async function runReputationClientChecks(): Promise<void> {
  await checkUnconfigured()
  await checkBody()
  await checkNonceIsolation()
  await checkFailures()
  await checkCancel()
  await checkBatches()
  await checkHint()
}
