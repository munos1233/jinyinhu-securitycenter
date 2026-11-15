import { CenterError } from '../main/ets/center/CenterError'
import { useListMax, useLookbackMs } from '../main/ets/center/CenterLimits'
import type {
  BundleRow,
  CertAlgo,
  CloudState,
  Gate,
  GateStatus,
  InstallSource,
  PermissionFact,
  RiskLevel,
  Verdict,
  VerdictSource
} from '../main/ets/center/CenterTypes'
import {
  AccessPort,
  isFixed,
  PERMISSION_FIXED_BY_ADMIN_POLICY,
  PERMISSION_FIXED_FOR_SECURITY_POLICY,
  PERMISSION_PRE_AUTHORIZED_CANCELABLE,
  PERMISSION_SYSTEM_FIXED,
  PERMISSION_USER_FIXED,
  RawAccess,
  RawUse
} from '../main/ets/system/AccessPort'
import type { AccessSource } from '../main/ets/system/AccessPort'
import { gateOf, ProbedGate } from '../main/ets/system/SystemGate'
import type { GateProbes, GateRefusal, SystemGate } from '../main/ets/system/SystemGate'

const CAMERA: string = 'ohos.permission.CAMERA'
const MICROPHONE: string = 'ohos.permission.MICROPHONE'
const LOCATION: string = 'ohos.permission.LOCATION'
const INTERNET: string = 'ohos.permission.INTERNET'
const PERMISSION_USER_SET: number = 1 << 0

function fail(message: string): void {
  throw new Error(message)
}

class Clock {
  value: number = 1800000000000

  now(): number {
    return this.value
  }
}

class Coded extends Error {
  code: number

  constructor(code: number) {
    super('sdk ' + code)
    this.code = code
  }
}

class StubGate implements SystemGate, GateRefusal {
  status: Map<string, GateStatus> = new Map()
  refused: string[] = []

  private of(id: string): Gate {
    let status = this.status.get(id)
    return gateOf(id, status === undefined ? 'ready' : status, status === 'unsupported' ? 'stub:' + id : '')
  }

  bundles(): Gate {
    return this.of('bundles')
  }

  grants(): Gate {
    return this.of('grants')
  }

  revoke(): Gate {
    return this.of('revoke')
  }

  usedStats(): Gate {
    return this.of('usedStats')
  }

  cacheStats(): Gate {
    return this.of('cacheStats')
  }

  clearCache(): Gate {
    return this.of('clearCache')
  }

  uninstall(): Gate {
    return this.of('uninstall')
  }

  persistFileGrant(): Gate {
    return this.of('persistFileGrant')
  }

  userPickedFiles(): Gate {
    return this.of('userPickedFiles')
  }

  ownCache(): Gate {
    return this.of('ownCache')
  }

  posture(): Gate {
    return this.of('posture')
  }

  huks(): Gate {
    return this.of('huks')
  }

  async probe(): Promise<void> {
  }

  invalidate(): void {
  }

  stale(): boolean {
    return false
  }

  refuse(id: 'grants' | 'revoke', reason: string): void {
    this.refused.push(id + '=' + reason)
    this.status.set(id, 'unsupported')
  }
}

class FakeSource implements AccessSource {
  tokens: Map<string, number> = new Map()
  labels: Map<string, string> = new Map()
  declared: Map<string, string[]> = new Map()
  unreadable: string[] = []
  status: Map<string, number> = new Map()
  flags: Map<string, number> = new Map()
  statusError: number = 0
  flagsError: number = 0
  revokeError: number = 0
  usesError: number = 0
  uses: RawUse[] = []
  statusCalls: number[] = []
  flagsCalls: number[] = []
  revokeCalls: string[] = []
  useCalls: number[] = []

  async bundleOf(bundleName: string): Promise<RawAccess> {
    if (this.unreadable.indexOf(bundleName) >= 0) {
      throw new Coded(17700001)
    }
    let raw = new RawAccess()
    let token = this.tokens.get(bundleName)
    raw.tokenId = token === undefined ? 0 : token
    let label = this.labels.get(bundleName)
    raw.label = label === undefined ? '' : label
    let declared = this.declared.get(bundleName)
    raw.permissions = declared === undefined ? [] : declared.slice()
    return raw
  }

  async statusOf(tokenId: number, permissions: string[]): Promise<number[]> {
    this.statusCalls.push(tokenId)
    if (this.statusError !== 0) {
      throw new Coded(this.statusError)
    }
    let out: number[] = []
    for (let i = 0; i < permissions.length; i++) {
      let status = this.status.get(tokenId + '/' + permissions[i])
      out.push(status === undefined ? -1 : status)
    }
    return out
  }

  async flagsOf(tokenId: number, permission: string): Promise<number> {
    this.flagsCalls.push(tokenId)
    if (this.flagsError !== 0) {
      throw new Coded(this.flagsError)
    }
    let flags = this.flags.get(tokenId + '/' + permission)
    return flags === undefined ? 0 : flags
  }

  async revoke(tokenId: number, permission: string): Promise<void> {
    this.revokeCalls.push(tokenId + '/' + permission)
    if (this.revokeError !== 0) {
      throw new Coded(this.revokeError)
    }
  }

  async usedSince(begin: number, end: number): Promise<RawUse[]> {
    this.useCalls.push(begin)
    this.useCalls.push(end)
    if (this.usesError !== 0) {
      throw new Coded(this.usesError)
    }
    return this.uses.slice()
  }
}

class RowVerdict implements Verdict {
  level: RiskLevel = 'unknown'
  source: VerdictSource = 'system'
  reason: string = ''
  evidence: string = ''
  cloud: CloudState = 'unchecked'
}

class Row implements BundleRow {
  bundleName: string = ''
  version: string = '1'
  versionCode: number = 1
  certSha256: string = ''
  certAlgo: CertAlgo = 'none'
  declaredPermissions: string[] = []
  source: InstallSource = 'unknown'
  verdict: Verdict = new RowVerdict()
}

function row(bundleName: string, declared: string[]): Row {
  let value = new Row()
  value.bundleName = bundleName
  value.declaredPermissions = declared
  return value
}

function setup(source: FakeSource, bundleName: string, token: number, declared: string[]): Row {
  source.tokens.set(bundleName, token)
  source.declared.set(bundleName, declared)
  return row(bundleName, declared)
}

function factOf(facts: PermissionFact[], bundleName: string, permission: string): PermissionFact {
  for (let i = 0; i < facts.length; i++) {
    if (facts[i].bundleName === bundleName && facts[i].permission === permission) {
      return facts[i]
    }
  }
  throw new Error('缺少 ' + bundleName + ' ' + permission)
}

function grantedIn(facts: PermissionFact[], bundleName: string): string {
  let names: string[] = []
  for (let i = 0; i < facts.length; i++) {
    if (facts[i].bundleName === bundleName && facts[i].grant === 'granted') {
      names.push(facts[i].permission)
    }
  }
  return names.sort().join(',')
}

async function expectCenterError(run: () => Promise<void>, code: string, message: string): Promise<CenterError> {
  try {
    await run()
  } catch (err) {
    if (err instanceof CenterError && err.code === code) {
      return err
    }
    fail(message + '：错误类型不对')
  }
  throw new Error(message + '：没有抛错')
}

function checkFlags(): void {
  if (PERMISSION_USER_FIXED !== 2) {
    fail('PERMISSION_USER_FIXED 必须是 1 << 1')
  }
  if (!isFixed(PERMISSION_SYSTEM_FIXED) || !isFixed(PERMISSION_FIXED_FOR_SECURITY_POLICY) ||
    !isFixed(PERMISSION_FIXED_BY_ADMIN_POLICY)) {
    fail('三种系统固定位任一出现都是 fixed')
  }
  if (!isFixed(PERMISSION_USER_FIXED | PERMISSION_FIXED_BY_ADMIN_POLICY)) {
    fail('组合标志里含固定位仍是 fixed')
  }
  if (isFixed(PERMISSION_PRE_AUTHORIZED_CANCELABLE)) {
    fail('PERMISSION_PRE_AUTHORIZED_CANCELABLE 不算固定')
  }
  if (isFixed(0) || isFixed(PERMISSION_USER_SET) || isFixed(PERMISSION_USER_FIXED)) {
    fail('用户设置或用户固定不是系统固定')
  }
}

async function checkFacts(): Promise<void> {
  let gate = new StubGate()
  let source = new FakeSource()
  let port = new AccessPort(gate, gate, source, (): number => 0)
  let a = setup(source, 'com.example.a', 11, [CAMERA, MICROPHONE, LOCATION, INTERNET, CAMERA])
  a.source = 'preinstalled'
  source.labels.set('com.example.a', '示例')
  source.status.set('11/' + CAMERA, 0)
  source.status.set('11/' + MICROPHONE, 0)
  source.status.set('11/' + LOCATION, 0)
  source.status.set('11/' + INTERNET, 2)
  source.flags.set('11/' + CAMERA, PERMISSION_USER_SET)
  source.flags.set('11/' + MICROPHONE, PERMISSION_SYSTEM_FIXED)
  source.flags.set('11/' + LOCATION, PERMISSION_PRE_AUTHORIZED_CANCELABLE)

  if (!port.ready()) {
    fail('GrantLookup.ready() 与 SystemGate.grants() 一致')
  }
  let facts = await port.facts([a])
  if (facts.length !== 4) {
    fail('每个声明的权限一行，重复声明只算一次')
  }
  let camera = factOf(facts, 'com.example.a', CAMERA)
  if (camera.grant !== 'granted' || camera.fixed || camera.tokenId !== 11 || !camera.declared) {
    fail('已授予且非固定的权限要带当场读到的 tokenId')
  }
  if (camera.group !== '相机' || !camera.sensitive || camera.displayName !== '示例' ||
    camera.source !== 'preinstalled' || camera.label !== 'CAMERA') {
    fail('分组、敏感、应用名和安装来源要随事实写入')
  }
  if (!factOf(facts, 'com.example.a', MICROPHONE).fixed) {
    fail('PERMISSION_SYSTEM_FIXED 是 fixed')
  }
  if (factOf(facts, 'com.example.a', LOCATION).fixed) {
    fail('PERMISSION_PRE_AUTHORIZED_CANCELABLE 不是 fixed')
  }
  let internet = factOf(facts, 'com.example.a', INTERNET)
  if (internet.grant !== 'unknown' || internet.fixed || internet.sensitive) {
    fail('授权状态无效时写 unknown')
  }
  let granted = await port.grantedOf('com.example.a')
  if (granted.slice().sort().join(',') !== grantedIn(facts, 'com.example.a')) {
    fail('grantedOf 的名字集合与 facts() 里该包已授予的权限名一致')
  }

  source.status.set('11/' + CAMERA, -1)
  facts = await port.facts([a])
  if (factOf(facts, 'com.example.a', CAMERA).grant !== 'denied') {
    fail('被拒绝的权限写 denied')
  }
  if ((await port.grantedOf('com.example.a')).indexOf(CAMERA) >= 0) {
    fail('grantedOf 不含已关闭的权限')
  }
}

async function checkToken(): Promise<void> {
  let gate = new StubGate()
  let source = new FakeSource()
  let port = new AccessPort(gate, gate, source, (): number => 0)
  let zero = setup(source, 'com.example.zero', 0, [CAMERA])
  let negative = setup(source, 'com.example.negative', -3, [CAMERA])
  let gone = row('com.example.gone', [CAMERA])
  source.unreadable.push('com.example.gone')
  let facts = await port.facts([zero, negative, gone])
  if (source.statusCalls.length !== 0 || source.flagsCalls.length !== 0) {
    fail('tokenId 为 0、无效或读取失败时不调用 getPermissionsStatus / getPermissionFlags')
  }
  for (let i = 0; i < facts.length; i++) {
    if (facts[i].tokenId !== 0 || facts[i].grant !== 'unknown' || facts[i].fixed) {
      fail('读不到 tokenId 时 tokenId=0，grant=unknown，fixed=false')
    }
  }
  if (factOf(facts, 'com.example.gone', CAMERA).displayName !== 'com.example.gone') {
    fail('读不到应用名时用包名')
  }
  if ((await port.grantedOf('com.example.zero')).length !== 0 || source.statusCalls.length !== 0) {
    fail('grantedOf 在 tokenId 为 0 时不读授权')
  }
  await expectCenterError((): Promise<void> => port.revoke(0, CAMERA), 'unsupported', 'tokenId 为 0 时不撤权')
  await expectCenterError((): Promise<void> => port.revoke(-1, CAMERA), 'unsupported', 'tokenId 无效时不撤权')
  if (source.revokeCalls.length !== 0) {
    fail('tokenId 为 0 时不调用 revokeUserGrantedPermission')
  }
}

async function checkGrantsNotReady(): Promise<void> {
  let gate = new StubGate()
  gate.status.set('grants', 'unsupported')
  let source = new FakeSource()
  let port = new AccessPort(gate, gate, source, (): number => 0)
  let a = setup(source, 'com.example.a', 11, [CAMERA])
  source.status.set('11/' + CAMERA, 0)
  if (port.ready()) {
    fail('grants() 不是 ready 时 ready() 为 false')
  }
  let facts = await port.facts([a])
  if (facts[0].grant !== 'unknown' || facts[0].fixed || facts[0].tokenId !== 11) {
    fail('grants() 不是 ready 时只填声明和 tokenId，grant 写 unknown')
  }
  if ((await port.grantedOf('com.example.a')).length !== 0) {
    fail('ready() 为 false 时 grantedOf 不给已授予名单')
  }
  if (source.statusCalls.length !== 0 || source.flagsCalls.length !== 0) {
    fail('ready() 为 false 时不读授权')
  }
}

async function checkGrantsRefused(): Promise<void> {
  let gate = new StubGate()
  let source = new FakeSource()
  let port = new AccessPort(gate, gate, source, (): number => 0)
  let a = setup(source, 'com.example.a', 11, [CAMERA])
  let b = setup(source, 'com.example.b', 12, [CAMERA])
  source.status.set('11/' + CAMERA, 0)
  source.status.set('12/' + CAMERA, 0)
  source.statusError = 201
  let facts = await port.facts([a, b])
  if (gate.grants().status !== 'unsupported' || port.ready()) {
    fail('读授权被拒时 grants() 为 unsupported，ready() 随之为 false')
  }
  if (gate.refused.join(';') !== 'grants=getPermissionsStatus:201') {
    fail('被拒原因要带接口名和返回码')
  }
  for (let i = 0; i < facts.length; i++) {
    if (facts[i].grant !== 'unknown' || facts[i].fixed) {
      fail('被拒之后整份结果 grant 都是 unknown')
    }
  }

  gate = new StubGate()
  source.statusError = 0
  source.flagsError = 202
  port = new AccessPort(gate, gate, source, (): number => 0)
  facts = await port.facts([a, b])
  if (gate.grants().status !== 'unsupported' || facts[0].grant !== 'unknown' || facts[1].grant !== 'unknown') {
    fail('读 flag 被拒同样把 grants() 记成 unsupported')
  }

  gate = new StubGate()
  source.flagsError = 12100001
  port = new AccessPort(gate, gate, source, (): number => 0)
  facts = await port.facts([a])
  if (gate.grants().status !== 'ready' || facts[0].grant !== 'granted' || facts[0].fixed) {
    fail('单个权限读 flag 出错不是被拒，不动 Gate')
  }

  source.flagsError = 0
  source.statusError = 12100002
  facts = await port.facts([a])
  if (gate.grants().status !== 'ready' || facts[0].grant !== 'unknown') {
    fail('单个包读状态出错时该包 unknown，不动 Gate')
  }
}

async function checkRevoke(): Promise<void> {
  let gate = new StubGate()
  let source = new FakeSource()
  let port = new AccessPort(gate, gate, source, (): number => 0)
  await port.revoke(11, CAMERA)
  if (source.revokeCalls.join(',') !== '11/' + CAMERA) {
    fail('撤权用传入的 tokenId 与权限名')
  }

  source.revokeError = 12100003
  let thrown = false
  try {
    await port.revoke(11, CAMERA)
  } catch (err) {
    thrown = !(err instanceof CenterError) && (err as Coded).code === 12100003
  }
  if (!thrown || gate.revoke().status !== 'ready') {
    fail('非被拒的失败把返回码原样抛出，不动 Gate')
  }

  source.revokeError = 201
  let refused = await expectCenterError((): Promise<void> => port.revoke(11, CAMERA), 'unsupported', '撤权被拒')
  if (refused.raw !== 'revokeUserGrantedPermission:201' || gate.revoke().status !== 'unsupported') {
    fail('撤权被拒时 revoke() 为 unsupported')
  }
  if (gate.grants().status !== 'ready') {
    fail('撤权被拒不动 grants()')
  }
  let calls = source.revokeCalls.length
  await expectCenterError((): Promise<void> => port.revoke(11, CAMERA), 'unsupported', 'revoke() 不是 ready')
  if (source.revokeCalls.length !== calls) {
    fail('revoke() 不是 ready 时不调用撤权')
  }
}

async function checkRecentUses(): Promise<void> {
  let clock = new Clock()
  let gate = new StubGate()
  gate.status.set('usedStats', 'unsupported')
  let source = new FakeSource()
  let port = new AccessPort(gate, gate, source, (): number => clock.now())
  await expectCenterError(async (): Promise<void> => {
    await port.recentUses()
  }, 'unsupported', 'usedStats() 不是 ready')
  if (source.useCalls.length !== 0) {
    fail('usedStats() 不是 ready 时不读最近使用')
  }

  gate.status.set('usedStats', 'ready')
  let now = clock.now()
  let old = new RawUse()
  old.bundleName = 'com.example.old'
  old.permission = CAMERA
  old.at = now - useLookbackMs - 1
  source.uses.push(old)
  for (let i = 0; i < useListMax + 5; i++) {
    let use = new RawUse()
    use.bundleName = 'com.example.n' + i
    use.permission = MICROPHONE
    use.at = now - useLookbackMs + i * 1000
    source.uses.push(use)
  }
  let uses = await port.recentUses()
  if (source.useCalls[0] !== now - useLookbackMs || source.useCalls[1] !== now) {
    fail('只查最近 useLookbackMs')
  }
  if (uses.length !== useListMax) {
    fail('最多 useListMax 条')
  }
  if (uses[0].bundleName !== 'com.example.n' + (useListMax + 4) || uses[0].at !== new Date(now - useLookbackMs +
    (useListMax + 4) * 1000).toISOString()) {
    fail('新的在前')
  }
  for (let i = 0; i < uses.length; i++) {
    if (uses[i].bundleName === 'com.example.old') {
      fail('超出时间窗的记录不留')
    }
    if (i > 0 && uses[i - 1].at < uses[i].at) {
      fail('按时间倒序')
    }
  }
  if (uses[0].label !== 'MICROPHONE' || uses[0].permission !== MICROPHONE) {
    fail('最近使用带权限名')
  }

  source.usesError = 201
  await expectCenterError(async (): Promise<void> => {
    await port.recentUses()
  }, 'unsupported', '读最近使用失败时不返回空数组冒充没有记录')
}

class ReadyProbes implements GateProbes {
  private ready(id: string): Promise<Gate> {
    return Promise.resolve(gateOf(id, 'ready', ''))
  }

  bundles(): Promise<Gate> {
    return this.ready('bundles')
  }

  grants(): Promise<Gate> {
    return this.ready('grants')
  }

  revoke(): Promise<Gate> {
    return this.ready('revoke')
  }

  usedStats(): Promise<Gate> {
    return this.ready('usedStats')
  }

  cacheStats(): Promise<Gate> {
    return this.ready('cacheStats')
  }

  clearCache(): Promise<Gate> {
    return this.ready('clearCache')
  }

  uninstall(): Promise<Gate> {
    return this.ready('uninstall')
  }

  persistFileGrant(): Promise<Gate> {
    return this.ready('persistFileGrant')
  }

  posture(): Promise<Gate> {
    return this.ready('posture')
  }

  huks(): Promise<Gate> {
    return this.ready('huks')
  }
}

async function checkProbedGateRefusal(): Promise<void> {
  let gate = new ProbedGate(new ReadyProbes(), (): number => 0)
  await gate.probe()
  let source = new FakeSource()
  let port = new AccessPort(gate, gate, source, (): number => 0)
  let a = setup(source, 'com.example.a', 11, [CAMERA])
  source.statusError = 201
  await port.facts([a])
  if (gate.grants().status !== 'unsupported' || gate.grants().reason !== 'getPermissionsStatus:201' || port.ready()) {
    fail('SystemGate.grants() 要记下被拒，GrantLookup.ready() 随之变化')
  }
  source.revokeError = 202
  await expectCenterError((): Promise<void> => port.revoke(11, CAMERA), 'unsupported', 'SystemGate 撤权被拒')
  if (gate.revoke().status !== 'unsupported' || gate.bundles().status !== 'ready') {
    fail('只把被拒的那一项记成 unsupported')
  }
  await gate.probe()
  if (gate.grants().status !== 'ready' || gate.revoke().status !== 'ready') {
    fail('被拒不缓存到进程结束，下一次 probe() 重新探测')
  }
}

export async function runAccessPortChecks(): Promise<void> {
  checkFlags()
  await checkFacts()
  await checkToken()
  await checkGrantsNotReady()
  await checkGrantsRefused()
  await checkRevoke()
  await checkRecentUses()
  await checkProbedGateRefusal()
}
