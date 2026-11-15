import { CenterError } from '../main/ets/center/CenterError'
import { gateCacheMs } from '../main/ets/center/CenterLimits'
import type { BundleRow, Gate, GateStatus, ProtectFact } from '../main/ets/center/CenterTypes'
import { canonicalCert } from '../main/ets/engine/Decide'
import { GatedBundleCensus, installSourceOf, pemBody, RawBundle, RawSignature } from '../main/ets/system/BundleCensus'
import type { BundleSource } from '../main/ets/system/BundleCensus'
import {
  El5Read,
  EL5_UNREADABLE,
  LOCKDOWN_UNREADABLE,
  ParamPosturePort,
  ParamRead,
  PURE_MODE_UNREADABLE
} from '../main/ets/system/PosturePort'
import type { El5Outcome, El5Query, ParamReader } from '../main/ets/system/PosturePort'
import { gateOf, ProbedGate } from '../main/ets/system/SystemGate'
import type { GateProbes, SystemGate } from '../main/ets/system/SystemGate'

function fail(message: string): void {
  throw new Error(message)
}

class Clock {
  value: number = 1000

  now(): number {
    return this.value
  }
}

class Hold {
  release: () => void = (): void => {
  }
  promise: Promise<void>

  constructor() {
    this.promise = new Promise<void>((resolve: () => void): void => {
      this.release = resolve
    })
  }
}

class FakeProbes implements GateProbes {
  status: Map<string, GateStatus> = new Map()
  reasons: Map<string, string> = new Map()
  throwing: string[] = []
  calls: number = 0
  hold: Hold | null = null

  private async answer(id: string): Promise<Gate> {
    let status = this.status.get(id)
    let reason = this.reasons.get(id)
    if (id === 'bundles') {
      this.calls++
      if (this.hold !== null) {
        await this.hold.promise
      }
    }
    if (this.throwing.indexOf(id) >= 0) {
      throw new Error('boom')
    }
    return gateOf('wrong-id', status === undefined ? 'unsupported' : status, reason === undefined ? 'fake' : reason)
  }

  bundles(): Promise<Gate> {
    return this.answer('bundles')
  }

  grants(): Promise<Gate> {
    return this.answer('grants')
  }

  revoke(): Promise<Gate> {
    return this.answer('revoke')
  }

  usedStats(): Promise<Gate> {
    return this.answer('usedStats')
  }

  cacheStats(): Promise<Gate> {
    return this.answer('cacheStats')
  }

  clearCache(): Promise<Gate> {
    return this.answer('clearCache')
  }

  uninstall(): Promise<Gate> {
    return this.answer('uninstall')
  }

  persistFileGrant(): Promise<Gate> {
    return this.answer('persistFileGrant')
  }

  posture(): Promise<Gate> {
    return this.answer('posture')
  }

  huks(): Promise<Gate> {
    return this.answer('huks')
  }
}

function newGate(probes: FakeProbes, clock: Clock): ProbedGate {
  return new ProbedGate(probes, (): number => clock.now())
}

async function checkGate(): Promise<void> {
  let clock = new Clock()
  let probes = new FakeProbes()
  let gate = newGate(probes, clock)
  if (gate.bundles().status !== 'unsupported' || !gate.stale()) {
    fail('探测之前 Gate 应为 unsupported 且需要探测')
  }
  if (gate.userPickedFiles().status !== 'ready' || gate.ownCache().status !== 'ready') {
    fail('userPickedFiles 与 ownCache 恒为 ready')
  }

  probes.status.set('bundles', 'ready')
  probes.status.set('uninstall', 'ready')
  probes.reasons.set('grants', 'not-granted:ohos.permission.GET_SENSITIVE_PERMISSIONS')
  probes.throwing.push('huks')
  await gate.probe()
  if (gate.bundles().status !== 'ready' || gate.bundles().id !== 'bundles' || gate.bundles().reason !== '') {
    fail('探测结果应写回 bundles，id 以门面为准')
  }
  if (gate.grants().status !== 'unsupported' ||
    gate.grants().reason !== 'not-granted:ohos.permission.GET_SENSITIVE_PERMISSIONS') {
    fail('unsupported 的原因要原样保留，供 CenterError.raw 使用')
  }
  if (gate.huks().status !== 'unsupported' || gate.huks().reason.indexOf('probe-failed') !== 0) {
    fail('某一项探测抛错时只把这一项写成 unsupported')
  }
  if (gate.uninstall().status !== 'ready') {
    fail('一项抛错不能拖累其它项')
  }
  if (gate.stale()) {
    fail('刚探测完不应过期')
  }

  gate.invalidate()
  if (!gate.stale()) {
    fail('invalidate 之后必须重新探测')
  }
  if (gate.bundles().status !== 'ready' || gate.grants().reason.length === 0) {
    fail('invalidate 只清缓存，不改当前 Gate 值')
  }

  await gate.probe()
  clock.value += gateCacheMs - 1
  if (gate.stale()) {
    fail('未超过 gateCacheMs 不应过期')
  }
  clock.value += 1
  if (!gate.stale()) {
    fail('超过 gateCacheMs 必须过期，不能把 unsupported 缓存到进程结束')
  }

  probes.status.set('grants', 'ready')
  await gate.probe()
  if (gate.grants().status !== 'ready') {
    fail('再次探测要能把 unsupported 改成 ready')
  }
}

async function checkGateConcurrency(): Promise<void> {
  let clock = new Clock()
  let probes = new FakeProbes()
  probes.status.set('bundles', 'ready')
  let gate = newGate(probes, clock)

  let hold = new Hold()
  probes.hold = hold
  let first = gate.probe()
  let second = gate.probe()
  hold.release()
  await Promise.all([first, second])
  if (probes.calls !== 1) {
    fail('同时两次 probe 应合并为一次探测')
  }

  let early = new Hold()
  probes.hold = early
  probes.status.set('bundles', 'unsupported')
  let before = gate.probe()
  gate.invalidate()
  probes.hold = null
  probes.status.set('bundles', 'ready')
  let after = gate.probe()
  await after
  if (probes.calls !== 3) {
    fail('invalidate 之后的 probe 不得沿用失效前那一次')
  }
  early.release()
  await before
  if (gate.bundles().status !== 'ready') {
    fail('失效前那一次晚到，不得覆盖较新的结果')
  }
  if (gate.stale()) {
    fail('失效之后的那一次已经完成，应视为新鲜')
  }

  let late = new Hold()
  probes.hold = late
  let pending = gate.probe()
  probes.hold = null
  gate.invalidate()
  late.release()
  await pending
  if (!gate.stale()) {
    fail('失效前开始的探测完成后，不能把缓存标成新鲜')
  }
}

class GateStub implements SystemGate {
  bundleGate: Gate = gateOf('bundles', 'ready', '')

  bundles(): Gate {
    return this.bundleGate
  }

  grants(): Gate {
    return gateOf('grants', 'unsupported', '')
  }

  revoke(): Gate {
    return gateOf('revoke', 'unsupported', '')
  }

  usedStats(): Gate {
    return gateOf('usedStats', 'unsupported', '')
  }

  cacheStats(): Gate {
    return gateOf('cacheStats', 'unsupported', '')
  }

  clearCache(): Gate {
    return gateOf('clearCache', 'unsupported', '')
  }

  uninstall(): Gate {
    return gateOf('uninstall', 'unsupported', '')
  }

  persistFileGrant(): Gate {
    return gateOf('persistFileGrant', 'unsupported', '')
  }

  userPickedFiles(): Gate {
    return gateOf('userPickedFiles', 'ready', '')
  }

  ownCache(): Gate {
    return gateOf('ownCache', 'ready', '')
  }

  posture(): Gate {
    return gateOf('posture', 'unsupported', '')
  }

  huks(): Gate {
    return gateOf('huks', 'unsupported', '')
  }

  async probe(): Promise<void> {
  }

  invalidate(): void {
  }

  stale(): boolean {
    return false
  }
}

class FakeSource implements BundleSource {
  bundles: RawBundle[] = []
  signatures: Map<string, RawSignature> = new Map()
  listError: boolean = false
  listCalls: number = 0
  asked: string[] = []

  async listAll(): Promise<RawBundle[]> {
    this.listCalls++
    if (this.listError) {
      throw new Error('denied')
    }
    return this.bundles
  }

  async signatureOf(bundleName: string): Promise<RawSignature> {
    this.asked.push(bundleName)
    let signature = this.signatures.get(bundleName)
    if (signature === undefined) {
      throw new Error('no bundle')
    }
    return signature
  }
}

function raw(name: string, fingerprint: string, source: string, hasSource: boolean): RawBundle {
  let bundle = new RawBundle()
  bundle.bundleName = name
  bundle.versionName = '1.0'
  bundle.versionCode = 3
  bundle.fingerprint = fingerprint
  bundle.permissions = ['ohos.permission.CAMERA']
  bundle.installSource = source
  bundle.hasInstallSource = hasSource
  return bundle
}

function signature(fingerprint: string): RawSignature {
  let value = new RawSignature()
  value.fingerprint = fingerprint
  return value
}

function rowOf(rows: BundleRow[], name: string): BundleRow {
  for (let i = 0; i < rows.length; i++) {
    if (rows[i].bundleName === name) {
      return rows[i]
    }
  }
  throw new Error('缺少 ' + name)
}

async function expectUnsupported(census: GatedBundleCensus, raw: string, message: string): Promise<void> {
  try {
    let rows = await census.list()
    fail(message + '，实际返回了 ' + rows.length + ' 行')
  } catch (err) {
    if (!(err instanceof CenterError) || err.code !== 'unsupported') {
      throw err as Error
    }
    if (raw.length > 0 && err.raw !== raw) {
      fail(message + '：raw 应为 ' + raw + '，实际 ' + err.raw)
    }
  }
}

const FP_A: string = 'AA:BB:CC:DD'
const FP_B: string = '0011223344'

async function checkCensus(): Promise<void> {
  let gate = new GateStub()
  let source = new FakeSource()
  source.bundles = [raw('com.example.b', '', 'pre-installed', true), raw('com.example.a', FP_A, 'ota', true)]
  let census = new GatedBundleCensus(gate, source)

  gate.bundleGate = gateOf('bundles', 'unsupported', 'getAllBundleInfo:201')
  await expectUnsupported(census, 'getAllBundleInfo:201', 'bundles() 不是 ready 时必须抛 unsupported')
  if (source.listCalls !== 0) {
    fail('Gate 不是 ready 时不应再调用列表')
  }

  gate.bundleGate = gateOf('bundles', 'ready', '')
  source.listError = true
  await expectUnsupported(census, '', '列表调用失败时不能返回空数组冒充没有应用')
  source.listError = false

  source.signatures.set('com.example.b', signature(FP_B))
  source.bundles.push(raw('com.example.c', '', 'com.example.market', true))
  source.bundles.push(raw('com.example.d', '', 'unknown', true))
  source.signatures.set('com.example.d', signature(''))
  let rows = await census.list()
  if (rows.length !== 4 || rows[0].bundleName !== 'com.example.a' || rows[3].bundleName !== 'com.example.d') {
    fail('Gate 为 ready 时应列出全部包，并按包名排序')
  }
  let a = rowOf(rows, 'com.example.a')
  if (a.certAlgo !== 'platform-fingerprint' || a.certSha256 !== canonicalCert(FP_A)) {
    fail('列表自带 fingerprint 时应按 BundleFinger 写 platform-fingerprint')
  }
  if (source.asked.indexOf('com.example.a') >= 0) {
    fail('已有证书的包不应再按包名补证书')
  }
  let b = rowOf(rows, 'com.example.b')
  if (b.certAlgo !== 'platform-fingerprint' || b.certSha256 !== canonicalCert(FP_B)) {
    fail('列表没有证书时应按包名补证书')
  }
  let c = rowOf(rows, 'com.example.c')
  let d = rowOf(rows, 'com.example.d')
  if (c.certAlgo !== 'none' || c.certSha256 !== '' || d.certAlgo !== 'none' || d.certSha256 !== '') {
    fail('补不到证书的包只把该包写成 certAlgo=none')
  }
  if (a.version !== '1.0' || a.versionCode !== 3 || a.declaredPermissions.length !== 1 ||
    a.declaredPermissions[0] !== 'ohos.permission.CAMERA') {
    fail('版本与声明权限要原样带出')
  }
  if (a.verdict.level !== 'unknown' || a.verdict.cloud !== 'unchecked') {
    fail('普查不做判定，verdict 只是未判定的占位')
  }
  if (a.source !== 'preinstalled' || b.source !== 'preinstalled') {
    fail('pre-installed 与 ota 都是预置应用')
  }
  if (c.source !== 'unknown' || d.source !== 'unknown') {
    fail('安装方包名或 unknown 分不出商店与侧载，只能是 unknown')
  }

  source.bundles = [raw('com.example.x', FP_A, '', false), raw('com.example.y', FP_A, '', false)]
  rows = await census.list()
  for (let i = 0; i < rows.length; i++) {
    if (rows[i].source !== 'unknown') {
      fail('SDK 没有安装来源字段时全部填 unknown')
    }
  }

  source.bundles = []
  rows = await census.list()
  if (rows.length !== 0) {
    fail('Gate 为 ready 且系统确实没有包时才返回空数组')
  }

  let values = ['', 'sideload', 'com.ohos.hdc', 'unknown', ' pre-installed ', 'recovery']
  for (let i = 0; i < values.length; i++) {
    if (installSourceOf(values[i]) === 'sideload' || installSourceOf(values[i]) === 'store') {
      fail('不得把来源猜成 sideload 或 store：' + values[i])
    }
  }
  if (installSourceOf(' pre-installed ') !== 'preinstalled' || installSourceOf('recovery') !== 'preinstalled') {
    fail('预置来源应写 preinstalled')
  }
  if (pemBody('-----BEGIN CERTIFICATE-----\r\nQUJD\r\nREVG\r\n-----END CERTIFICATE-----\r\n') !== 'QUJDREVG') {
    fail('PEM 证书只取正文')
  }
}

class Params implements ParamReader {
  values: Map<string, string> = new Map()
  failing: string[] = []
  throwing: boolean = false
  keys: string[] = []

  read(key: string): ParamRead {
    this.keys.push(key)
    if (this.throwing) {
      throw new Error('crash')
    }
    let read = new ParamRead()
    let value = this.values.get(key)
    if (value !== undefined) {
      read.outcome = 'value'
      read.value = value
    } else if (this.failing.indexOf(key) >= 0) {
      read.outcome = 'failed'
      read.reason = '14700103'
    } else {
      read.outcome = 'missing'
      read.reason = '14700101'
    }
    return read
  }
}

class Keys implements El5Query {
  outcome: El5Outcome = 'present'

  query(): El5Read {
    let read = new El5Read()
    read.outcome = this.outcome
    return read
  }
}

function expectFact(fact: ProtectFact, id: string, status: string, detail: string, message: string): void {
  if (fact.id !== id || fact.status !== status || (detail.length > 0 && fact.detail !== detail)) {
    fail(message + '：' + fact.id + ' ' + fact.status + ' ' + fact.detail)
  }
}

async function checkPosture(): Promise<void> {
  let params = new Params()
  let keys = new Keys()
  let port = new ParamPosturePort(params, keys)

  keys.outcome = 'no-interface'
  let pure = await port.pureMode()
  let lock = await port.lockdown()
  let el5 = await port.el5()
  expectFact(pure, 'pure-mode', 'unsupported', PURE_MODE_UNREADABLE, '纯净模式读不到')
  expectFact(lock, 'lockdown', 'unsupported', LOCKDOWN_UNREADABLE, '锁定状态读不到')
  expectFact(el5, 'el5', 'unsupported', EL5_UNREADABLE, 'el5 没有查询接口')
  if (pure.detail === lock.detail || lock.detail === el5.detail || pure.detail === el5.detail) {
    fail('三项读不到时不得共用一句')
  }
  if (params.keys.indexOf('persist.jyh.pure_mode') < 0) {
    fail('纯净模式读 persist.jyh.pure_mode')
  }
  if (params.keys.indexOf('const.jyh.lockdown') < 0 || params.keys.indexOf('persist.jyh.lockdown') < 0) {
    fail('lockdown 两个键都没有时两个都要读过')
  }

  params.values.set('persist.jyh.pure_mode', '1')
  keys.outcome = 'present'
  expectFact(await port.pureMode(), 'pure-mode', 'ok', '', '纯净模式为 1')
  expectFact(await port.lockdown(), 'lockdown', 'unsupported', LOCKDOWN_UNREADABLE, 'lockdown 两个键都没有')
  expectFact(await port.el5(), 'el5', 'ok', '', 'lockdown 读不到时不得拖累 el5')

  params.values.set('persist.jyh.pure_mode', '0')
  expectFact(await port.pureMode(), 'pure-mode', 'risk', '', '纯净模式不是 1')

  params.keys = []
  params.values.set('const.jyh.lockdown', ' confidentiality ')
  params.values.set('persist.jyh.lockdown', 'none')
  expectFact(await port.lockdown(), 'lockdown', 'ok', '', 'const 键优先，去掉首尾空白后比较')
  if (params.keys.indexOf('persist.jyh.lockdown') >= 0) {
    fail('const.jyh.lockdown 读到时不再读 persist 键')
  }

  params.values.delete('const.jyh.lockdown')
  params.values.set('persist.jyh.lockdown', 'integrity')
  let fallback = await port.lockdown()
  expectFact(fallback, 'lockdown', 'risk', '', 'const 没有时读 persist')
  if (fallback.actual !== 'integrity' || fallback.expected !== 'confidentiality') {
    fail('lockdown 要带出读到的值与期望值')
  }

  params.failing.push('const.jyh.lockdown')
  params.values.set('persist.jyh.lockdown', 'confidentiality')
  expectFact(await port.lockdown(), 'lockdown', 'ok', '', 'const 被拒时仍读 persist')

  keys.outcome = 'absent'
  expectFact(await port.el5(), 'el5', 'risk', '', '读到且服务不在是 risk')
  keys.outcome = 'failed'
  expectFact(await port.el5(), 'el5', 'unsupported', EL5_UNREADABLE, '查询出错')

  params.throwing = true
  keys.outcome = 'present'
  expectFact(await port.pureMode(), 'pure-mode', 'unsupported', PURE_MODE_UNREADABLE, '读参数抛错只影响本项')
  expectFact(await port.lockdown(), 'lockdown', 'unsupported', LOCKDOWN_UNREADABLE, '读参数抛错只影响本项')
  expectFact(await port.el5(), 'el5', 'ok', '', '参数读取抛错不影响 el5')
}

export async function runSystemGateChecks(): Promise<void> {
  await checkGate()
  await checkGateConcurrency()
  await checkCensus()
  await checkPosture()
}
