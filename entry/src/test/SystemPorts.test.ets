import { CenterError } from '../main/ets/center/CenterError'
import type { FileGrant, Gate, GateStatus } from '../main/ets/center/CenterTypes'
import type { InstallerOpen, OpenedInstaller } from '../main/ets/engine/InstallerScan'
import { CachePort } from '../main/ets/system/CachePort'
import type { CacheSource } from '../main/ets/system/CachePort'
import { FileGrants } from '../main/ets/system/FileGrant'
import type { GrantPersist, GrantStore } from '../main/ets/system/FileGrant'
import { GatedInstallerPort } from '../main/ets/system/InstallerPort'
import type { UninstallTool } from '../main/ets/system/InstallerPort'
import { gateOf, ProbedGate } from '../main/ets/system/SystemGate'
import type { GateProbes, GateRefusal, RefusableGate, SystemGate } from '../main/ets/system/SystemGate'

const DIR_A: string = 'file:///storage/Users/currentUser/Download'
const DIR_B: string = 'file:///storage/Users/currentUser/Documents'

function fail(message: string): void {
  throw new Error(message)
}

function require(ok: boolean, message: string): void {
  if (!ok) {
    fail(message)
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
  invalidations: number = 0

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
    this.invalidations++
  }

  stale(): boolean {
    return false
  }

  refuse(id: RefusableGate, reason: string): void {
    this.refused.push(id + '=' + reason)
    this.status.set(id, 'unsupported')
  }
}

class MemoryStore implements GrantStore {
  text: string = ''
  saves: number = 0

  load(): string {
    return this.text
  }

  save(text: string): void {
    this.saves++
    this.text = text
  }
}

class FakePersist implements GrantPersist {
  calls: string[] = []
  persistError: number = 0
  activateError: Map<string, number> = new Map()

  async persist(uri: string): Promise<void> {
    this.calls.push('persist ' + uri)
    if (this.persistError !== 0) {
      throw new Coded(this.persistError)
    }
  }

  async activate(uri: string): Promise<void> {
    this.calls.push('activate ' + uri)
    let code = this.activateError.get(uri)
    if (code !== undefined) {
      throw new Coded(code)
    }
  }

  async release(uri: string): Promise<void> {
    this.calls.push('release ' + uri)
  }
}

class Opened implements OpenedInstaller {
  fd: number = 3
  path: string = ''
}

class FakeOpen implements InstallerOpen {
  broken: string[] = []
  opened: string[] = []
  released: number = 0

  accept(uri: string, root: string): CenterError | string {
    return root
  }

  open(uri: string, root: string, fromPicker: boolean, grants: FileGrant[]): CenterError | OpenedInstaller {
    require(!fromPicker, '已记住的目录不是当次选择器给的')
    require(grants.some((grant: FileGrant): boolean => grant.uri === uri), '打开时要带上这条授权')
    require(root.indexOf('/storage/') === 0, '授权根按路径给出')
    this.opened.push(uri)
    if (this.broken.indexOf(uri) >= 0) {
      return new CenterError('io', uri)
    }
    return new Opened()
  }

  release(opened: OpenedInstaller): void {
    this.released++
  }
}

class Grants {
  gate: StubGate = new StubGate()
  store: MemoryStore = new MemoryStore()
  system: FakePersist = new FakePersist()
  port: FileGrants

  constructor() {
    this.port = new FileGrants(this.gate, this.gate, this.store, this.system, (): string => '2026-11-15T13:00:00+08:00')
  }
}

async function rejects(run: () => Promise<Object | void>, code: string, message: string): Promise<CenterError> {
  try {
    await run()
  } catch (err) {
    if (err instanceof CenterError && err.code === code) {
      return err
    }
    fail(message + '：错误不对 ' + JSON.stringify(err))
  }
  fail(message + '：没有抛错')
  return new CenterError('io', '')
}

async function checkPicked(): Promise<void> {
  let t = new Grants()
  let grant = t.port.picked(DIR_A, 'Download')
  require(grant.persisted === false && grant.uri === DIR_A, '选择器返回的 uri 不是持久授权')
  require(t.store.saves === 0 && t.gate.invalidations === 0 && t.system.calls.length === 0,
    '选择器返回的 uri 只给当前作业，不写入 grant，不调用持久化')
  require(t.port.persisted().length === 0, '没有点「记住此目录」时下次没有授权目录')
}

async function checkUnsupported(): Promise<void> {
  let t = new Grants()
  t.store.text = JSON.stringify([{ uri: DIR_A, displayName: 'Download', persisted: true, at: '' }])
  t.gate.status.set('persistFileGrant', 'unsupported')
  await rejects(() => t.port.remember(DIR_B, 'Documents'), 'unsupported', '持久化不可用时「记住此目录」')
  require(t.system.calls.length === 0, '持久化不可用时不调用 persistPermission')
  require(t.store.saves === 0 && t.gate.invalidations === 0, '持久化不可用时不写 center.grants')
  require(t.port.persisted().length === 0, '持久化不可用时全盘不读旧目录')
}

async function checkRemember(): Promise<void> {
  let t = new Grants()
  let grant = await t.port.remember(DIR_A, 'Download')
  require(grant.persisted === true && grant.at.length > 0, '记住之后 persisted=true')
  require(t.system.calls.join(',') === 'persist ' + DIR_A, '先调用系统持久化，再写入')
  require(t.store.saves === 1 && t.gate.invalidations === 1, '写入一条 grant 之后调用 SystemGate.invalidate()')
  await t.port.remember(DIR_B, 'Documents')
  await t.port.remember(DIR_A, 'Download')
  let rows = t.port.persisted()
  require(rows.length === 2 && rows.every((row: FileGrant): boolean => row.persisted), '同一目录不重复记住')
  require(t.gate.invalidations === 3, '每次写入都要失效 Gate 缓存')

  t.port.forget(DIR_A)
  await Promise.resolve()
  require(t.port.persisted().map((row: FileGrant): string => row.uri).join(',') === DIR_B, 'forget 删除该条')
  require(t.gate.invalidations === 4, '删除一条 grant 之后调用 SystemGate.invalidate()')
  require(t.system.calls.indexOf('release ' + DIR_A) >= 0, '删除时一并撤销系统持久授权')
  t.port.forget('file:///storage/absent')
  require(t.gate.invalidations === 4 && t.store.saves === 4, '删除不存在的条目不写入、不失效')
}

async function checkPersistRefused(): Promise<void> {
  let t = new Grants()
  t.system.persistError = 201
  let err = await rejects(() => t.port.remember(DIR_A, 'Download'), 'unsupported', '持久化被拒')
  require(err.raw === 'persistPermission:201', '原因写返回码')
  require(t.gate.refused.join(',') === 'persistFileGrant=persistPermission:201', '被拒时 persistFileGrant() 记为 unsupported')
  require(t.store.saves === 0 && t.gate.invalidations === 0, '持久化失败不写入')

  let other = new Grants()
  other.system.persistError = 13900001
  await rejects(() => other.port.remember(DIR_A, 'Download'), 'io', '持久化的其它错误')
  require(other.gate.refused.length === 0 && other.store.saves === 0, '其它错误不动 Gate，也不写入')
}

async function checkOpenFailure(): Promise<void> {
  let t = new Grants()
  await t.port.remember(DIR_A, 'Download')
  await t.port.remember(DIR_B, 'Documents')
  let open = new FakeOpen()
  open.broken.push(DIR_A)
  let before = t.gate.invalidations
  let gone = await t.port.check(open)
  require(gone.join(',') === DIR_A, '持久化之后 FileOpen 失败的那条要删除')
  require(t.port.persisted().map((row: FileGrant): string => row.uri).join(',') === DIR_B, '打得开的目录保留')
  require(t.gate.invalidations === before + 1, '删除之后调用 SystemGate.invalidate()')
  require(open.released === 1, '打开成功的描述符要释放')
  require(t.system.calls.indexOf('activate ' + DIR_B) >= 0, '读之前先激活持久授权')

  let lost = new Grants()
  await lost.port.remember(DIR_A, 'Download')
  lost.system.activateError.set(DIR_A, 13900042)
  require((await lost.port.check(new FakeOpen())).join(',') === DIR_A, '激活失败等同授权已失效')
  require(lost.port.persisted().length === 0, '激活失败的条目被删除')

  let refused = new Grants()
  await refused.port.remember(DIR_A, 'Download')
  refused.system.activateError.set(DIR_A, 201)
  require((await refused.port.check(new FakeOpen())).length === 0, '激活被拒不是授权失效')
  require(refused.gate.refused.join(',') === 'persistFileGrant=activatePermission:201', '激活被拒时 Gate 记为 unsupported')
  require(refused.store.text.indexOf(DIR_A) >= 0, '激活被拒时不删除已记住的目录')
}

async function checkStoreDamage(): Promise<void> {
  let t = new Grants()
  t.store.text = '{not json'
  require(t.port.persisted().length === 0, '坏的 center.grants 不崩溃')
  t.store.text = JSON.stringify([{ uri: DIR_A, persisted: false }, { uri: '', persisted: true },
    { uri: DIR_B, displayName: 'Documents', persisted: true, at: 'x' }])
  let rows = t.port.persisted()
  require(rows.length === 1 && rows[0].uri === DIR_B, '只读出 persisted=true 且有 uri 的条目')
}

class FakeCache implements CacheSource {
  bytes: number = 4096
  statsError: number = 0
  clearError: number = 0
  calls: string[] = []

  async cacheBytes(bundleName: string): Promise<number> {
    this.calls.push('stats ' + bundleName)
    if (this.statsError !== 0) {
      throw new Coded(this.statsError)
    }
    return this.bytes
  }

  async clear(bundleName: string): Promise<void> {
    this.calls.push('clear ' + bundleName)
    if (this.clearError !== 0) {
      throw new Coded(this.clearError)
    }
  }
}

async function checkCache(): Promise<void> {
  let gate = new StubGate()
  let source = new FakeCache()
  let port = new CachePort(gate, gate, source)
  require(await port.stats('com.example.a') === 4096, '统计返回缓存字节')
  await port.clear('com.example.a')
  require(source.calls.join(',') === 'stats com.example.a,clear com.example.a', '统计与清除各调一次')

  gate.status.set('cacheStats', 'unsupported')
  gate.status.set('clearCache', 'unsupported')
  source.calls = []
  await rejects(() => port.stats('com.example.a'), 'unsupported', 'cacheStats 不是 ready')
  await rejects(() => port.clear('com.example.a'), 'unsupported', 'clearCache 不是 ready')
  require(source.calls.length === 0, 'Gate 不是 ready 时不调用系统接口')

  for (let code of [201, 202, 801]) {
    let g = new StubGate()
    let s = new FakeCache()
    s.statsError = code
    s.clearError = code
    let p = new CachePort(g, g, s)
    let a = await rejects(() => p.stats('com.example.a'), 'unsupported', '统计被拒 ' + code)
    let b = await rejects(() => p.clear('com.example.a'), 'unsupported', '清除被拒 ' + code)
    require(a.raw === 'getBundleStats:' + code && b.raw === 'cleanBundleCacheFiles:' + code, '原因写返回码')
    require(g.refused.join(',') === 'cacheStats=getBundleStats:' + code + ',clearCache=cleanBundleCacheFiles:' + code,
      '被拒时对应 Gate 为 unsupported')
  }

  let g = new StubGate()
  let s = new FakeCache()
  s.statsError = 17700001
  s.clearError = 17700001
  let p = new CachePort(g, g, s)
  await rejects(() => p.stats('com.example.gone'), 'io', '单个包统计失败')
  let failed = await rejects(() => p.clear('com.example.gone'), 'io', '单个包清除失败')
  require(failed.raw === 'cleanBundleCacheFiles:17700001', '清除失败时该行写返回码')
  require(g.refused.length === 0, '包不存在之类的错误不把 Gate 打成 unsupported')

  for (let bad of [-1, NaN, Infinity]) {
    let src = new FakeCache()
    src.bytes = bad
    await rejects(() => new CachePort(new StubGate(), new StubGate(), src).stats('com.example.a'), 'io', '坏的缓存字节 ' + bad)
  }
}

class AllReady implements GateProbes {
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
  let gate = new ProbedGate(new AllReady(), (): number => 1000)
  await gate.probe()
  let source = new FakeCache()
  source.clearError = 201
  let port = new CachePort(gate, gate, source)
  await rejects(() => port.clear('com.example.a'), 'unsupported', '清除被拒')
  require(gate.clearCache().status === 'unsupported' && gate.clearCache().reason === 'cleanBundleCacheFiles:201',
    'ProbedGate 记下 clearCache 被拒')
  require(gate.cacheStats().status === 'ready' && gate.grants().status === 'ready', '只改被拒的那一项')

  let store = new MemoryStore()
  let system = new FakePersist()
  system.persistError = 801
  let grants = new FileGrants(gate, gate, store, system, (): string => '')
  await rejects(() => grants.remember(DIR_A, 'Download'), 'unsupported', '持久化方法不存在')
  require(gate.persistFileGrant().status === 'unsupported', '方法不存在时 persistFileGrant() 为 unsupported')

  gate.invalidate()
  await gate.probe()
  require(gate.clearCache().status === 'ready' && gate.persistFileGrant().status === 'ready',
    '被拒不缓存到进程结束，下一次 probe 重新探测')
}

class FakeTool implements UninstallTool {
  calls: string[] = []
  error: number = 0

  async uninstall(bundleName: string): Promise<void> {
    this.calls.push(bundleName)
    if (this.error !== 0) {
      throw new Coded(this.error)
    }
  }
}

async function checkInstaller(): Promise<void> {
  let tool = new FakeTool()
  let opened = 0
  let port = new GatedInstallerPort(async (): Promise<UninstallTool> => {
    opened++
    return tool
  })
  await port.uninstall('com.example.a')
  require(opened === 1 && tool.calls.join(',') === 'com.example.a', 'uninstall 只卸载这一个包')
  await rejects(() => port.uninstall(''), 'io', '空包名')
  require(tool.calls.length === 1, '空包名不调用卸载')

  tool.error = 201
  let refused = await rejects(() => port.uninstall('com.example.b'), 'unsupported', '卸载被拒')
  require(refused.raw === 'uninstall:201', '卸载被拒写返回码')
  tool.error = 17700020
  let other = await rejects(() => port.uninstall('com.example.c'), 'io', '卸载失败')
  require(other.raw === 'uninstall:17700020', '卸载失败写返回码')
}

export async function runSystemPortsChecks(): Promise<void> {
  await checkPicked()
  await checkUnsupported()
  await checkRemember()
  await checkPersistRefused()
  await checkOpenFailure()
  await checkStoreDamage()
  await checkCache()
  await checkProbedGateRefusal()
  await checkInstaller()
}
