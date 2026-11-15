import { CenterError } from '../main/ets/center/CenterError'
import type {
  AccessFacts, BundleRow, CacheStats, FileGrant, FileSource, Gate, GrantLookup, JobKind, JobProgress, JobRecord,
  JobRequest, PermissionFact, PosturePort, ProtectFact, ScanScope, UseFact
} from '../main/ets/center/CenterTypes'
import { groupOf } from '../main/ets/center/SensitiveCatalog'
import type { AppJudge } from '../main/ets/engine/AppJudge'
import { hashFd } from '../main/ets/engine/Hash'
import type { Digest, HashIo } from '../main/ets/engine/Hash'
import { Writer } from '../main/ets/record/Writer'
import type { CenterFiles } from '../main/ets/record/Writer'
import type { BundleCensus } from '../main/ets/system/BundleCensus'
import type { FileOpen } from '../main/ets/system/FileOpen'
import type { SystemGate } from '../main/ets/system/SystemGate'
import { CANCEL_BYTES, CancelFlag, readCancel } from '../main/ets/task/CancelFlag'
import type { Clock, JobBase } from '../main/ets/task/Contexts'
import { HEAVY_KEY, isJobId, JobQueue, LIGHT_KEY, normalizeUris, sameRequest } from '../main/ets/task/JobQueue'
import type { ProgressSink } from '../main/ets/task/JobQueue'
import { JobRunner } from '../main/ets/task/JobRunner'
import type { CenterPorts } from '../main/ets/task/JobRunner'
import { RunEnd, RunnerRegistry, RunnerTable } from '../main/ets/task/RunnerRegistry'
import type { ResultHand } from '../main/ets/task/RunnerRegistry'

const INDEX: string = 'center/jobs/index.json'
const CHUNK: number = 1024 * 1024
const KINDS: JobKind[] = ['exam', 'malware', 'clean', 'duplicate', 'large-file', 'permission', 'apps', 'protect']

function require(ok: boolean, message: string): void {
  if (!ok) {
    throw new Error(message)
  }
}

class MemoryFiles implements CenterFiles {
  data: Map<string, string> = new Map()

  read(path: string): string | null {
    let text = this.data.get(path)
    return text === undefined ? null : text
  }

  write(path: string, text: string): void {
    this.data.set(path, text)
  }

  rename(from: string, to: string): void {
    let text = this.data.get(from)
    if (text === undefined) {
      throw new Error('missing ' + from)
    }
    this.data.delete(from)
    this.data.set(to, text)
  }

  remove(path: string): void {
    this.data.delete(path)
  }
}

class Latch {
  promise: Promise<void>
  open: () => void = () => {}

  constructor() {
    this.promise = new Promise<void>((resolve) => {
      this.open = resolve
    })
  }
}

class StubGate implements SystemGate {
  isStale: boolean = false
  probes: number = 0
  latch: Latch | null = null

  private gate(id: string): Gate {
    let g: Gate = { id: id, status: 'ready', reason: '' }
    return g
  }

  bundles(): Gate { return this.gate('bundles') }
  grants(): Gate { return this.gate('grants') }
  revoke(): Gate { return this.gate('revoke') }
  usedStats(): Gate { return this.gate('usedStats') }
  cacheStats(): Gate { return this.gate('cacheStats') }
  clearCache(): Gate { return this.gate('clearCache') }
  uninstall(): Gate { return this.gate('uninstall') }
  persistFileGrant(): Gate { return this.gate('persistFileGrant') }
  userPickedFiles(): Gate { return this.gate('userPickedFiles') }
  ownCache(): Gate { return this.gate('ownCache') }
  posture(): Gate { return this.gate('posture') }
  huks(): Gate { return this.gate('huks') }

  probe(): Promise<void> {
    this.probes++
    this.isStale = false
    return this.latch === null ? Promise.resolve() : this.latch.promise
  }

  invalidate(): void {
    this.isStale = true
  }

  stale(): boolean {
    return this.isStale
  }
}

class StepClock implements Clock {
  ticks: number = 0

  nowIso(): string {
    this.ticks++
    return 't' + this.ticks
  }
}

class SinkLog implements ProgressSink {
  writes: string[] = []
  last: Map<string, JobProgress> = new Map()

  publish(key: string, progress: JobProgress): void {
    this.writes.push(key + ':' + progress.state)
    this.last.set(key, progress)
  }
}

class Posted {
  works: (() => void)[] = []

  post(work: () => void): void {
    this.works.push(work)
  }

  flush(): void {
    let pending = this.works
    this.works = []
    for (let i = 0; i < pending.length; i++) {
      pending[i]()
    }
  }
}

class NoPosture implements PosturePort {
  pureMode(): Promise<ProtectFact> { return Promise.reject(new Error('unused')) }
  lockdown(): Promise<ProtectFact> { return Promise.reject(new Error('unused')) }
  el5(): Promise<ProtectFact> { return Promise.reject(new Error('unused')) }
}

class NoCensus implements BundleCensus {
  list(): Promise<BundleRow[]> { return Promise.resolve([]) }
}

class NoCache implements CacheStats {
  stats(bundleName: string): Promise<number> { return Promise.resolve(0) }
}

class NoFiles implements FileSource {
  persisted(): FileGrant[] { return [] }
  forget(uri: string): void {}
}

class NoAccess implements AccessFacts, GrantLookup {
  facts(bundles: BundleRow[]): Promise<PermissionFact[]> { return Promise.resolve([]) }
  recentUses(): Promise<UseFact[]> { return Promise.resolve([]) }
  ready(): boolean { return false }
  grantedOf(bundleName: string): Promise<string[]> { return Promise.resolve([]) }
}

class OpenMarker {
  marker: string = 'open'
}

class JudgeMarker {
  marker: string = 'judge'
}

function ports(): CenterPorts {
  let access = new NoAccess()
  let p: CenterPorts = {
    posture: new NoPosture(),
    census: new NoCensus(),
    cache: new NoCache(),
    files: new NoFiles(),
    open: new OpenMarker() as Object as FileOpen,
    access: access,
    grants: access,
    judge: new JudgeMarker() as Object as AppJudge
  }
  return p
}

class Harness {
  files: MemoryFiles = new MemoryFiles()
  gate: StubGate = new StubGate()
  clock: StepClock = new StepClock()
  sink: SinkLog = new SinkLog()
  posted: Posted = new Posted()
  table: RunnerTable = new RunnerTable()
  queue: JobQueue

  constructor(seed: string) {
    Writer.bind(this.files)
    if (seed.length > 0) {
      this.files.write(INDEX, seed)
    }
    let runner = new JobRunner(ports(), () => this.table)
    this.queue = new JobQueue(runner, this.gate, this.clock, this.sink, (work: () => void) => {
      this.posted.post(work)
    })
  }

  rows(): JobRecord[] {
    let text = this.files.read(INDEX)
    return text === null ? [] : JSON.parse(text) as JobRecord[]
  }

  row(jobId: string): JobRecord {
    let rows = this.rows()
    for (let i = 0; i < rows.length; i++) {
      if (rows[i].jobId === jobId) {
        return rows[i]
      }
    }
    throw new Error('no index row for ' + jobId)
  }
}

function request(kind: JobKind, scope: ScanScope, uris: string[], focus: string): JobRequest {
  let r: JobRequest = { kind: kind, scope: scope, uris: uris, focus: focus }
  return r
}

function end(itemCount: number, summary: string): RunEnd {
  let out = new RunEnd()
  out.itemCount = itemCount
  out.summary = summary
  return out
}

async function tick(): Promise<void> {
  await new Promise<void>((resolve) => {
    setTimeout(resolve, 0)
  })
}

async function until(ok: () => boolean, message: string): Promise<void> {
  for (let i = 0; i < 200; i++) {
    if (ok()) {
      return
    }
    await tick()
  }
  throw new Error('timed out: ' + message)
}

function terminal(state: string): boolean {
  return state === 'done' || state === 'failed' || state === 'cancelled' || state === 'interrupted'
}

async function lanesAndOrder(): Promise<void> {
  let h = new Harness('')
  let examGo = new Latch()
  let started: string[] = []
  h.table.exam = async (ctx, hand) => {
    started.push('exam')
    await examGo.promise
    return end(1, '')
  }
  h.table.malware = async (ctx, hand) => {
    started.push('malware')
    return end(1, '')
  }
  h.table.apps = async (ctx, hand) => {
    started.push('apps')
    return end(2, '')
  }
  let exam = h.queue.enqueue(request('exam', 'quick', [], ''))
  let malware = h.queue.enqueue(request('malware', 'quick', [], ''))
  let apps = h.queue.enqueue(request('apps', 'quick', [], ''))
  require(h.row(exam).lane === 'heavy' && h.row(malware).lane === 'heavy' && h.row(apps).lane === 'light',
    'exam、malware 走重车道，apps 走轻车道')
  await until(() => h.row(apps).state === 'done', '轻作业在重作业运行时完成')
  require(h.row(exam).state === 'running', '重作业仍在运行')
  require(h.row(malware).state === 'queued', '同一车道同时只跑一个')
  require(started.indexOf('malware') < 0, '前一个重作业没结束时不开始下一个')
  examGo.open()
  await until(() => h.row(malware).state === 'done', '重车道依次跑完')
  require(started.join(',') === 'exam,apps,malware', '轻作业不等重车道：' + started.join(','))

  let lanes = new Harness('')
  for (let i = 0; i < KINDS.length; i++) {
    let id = lanes.queue.enqueue(request(KINDS[i], 'quick', [], ''))
    let light = KINDS[i] === 'protect' || KINDS[i] === 'permission' || KINDS[i] === 'apps'
    require(lanes.row(id).lane === (light ? 'light' : 'heavy'), KINDS[i] + ' 的车道不对')
  }
  await until(() => lanes.rows().every((r) => terminal(r.state)), '空表作业全部收口')
}

async function contextsOnlyOwnPorts(): Promise<void> {
  let h = new Harness('')
  let seen: Map<string, string> = new Map()
  let record = (kind: string, ctx: Object): RunEnd => {
    seen.set(kind, Object.keys(ctx).sort().join(','))
    return end(0, '')
  }
  h.table.exam = async (ctx, hand) => record('exam', ctx)
  h.table.malware = async (ctx, hand) => record('malware', ctx)
  h.table.clean = async (ctx, hand) => record('clean', ctx)
  h.table.duplicate = async (ctx, hand) => record('duplicate', ctx)
  h.table.largeFile = async (ctx, hand) => record('large-file', ctx)
  h.table.permission = async (ctx, hand) => record('permission', ctx)
  h.table.apps = async (ctx, hand) => record('apps', ctx)
  h.table.protect = async (ctx, hand) => {
    require(Object.keys(ctx.base).sort().join(',') === 'cancel,clock,job,report,request', 'JobBase 字段不对')
    require(ctx.base.cancel instanceof CancelFlag, 'base.cancel 是 CancelFlag')
    return record('protect', ctx)
  }
  for (let i = 0; i < KINDS.length; i++) {
    h.queue.enqueue(request(KINDS[i], 'quick', [], ''))
  }
  await until(() => seen.size === KINDS.length && h.rows().every((r) => terminal(r.state)), '八种作业都拿到上下文')
  let expect: Map<string, string> = new Map()
  expect.set('exam', 'access,base,cache,census,files,judge,open,posture')
  expect.set('malware', 'base,census,files,grants,judge,open')
  expect.set('clean', 'base,cache,census,files,open')
  expect.set('permission', 'access,base,census')
  expect.set('apps', 'base,census,grants,judge')
  expect.set('protect', 'base,posture')
  expect.set('duplicate', 'base,files,open')
  expect.set('large-file', 'base,files,open')
  expect.forEach((keys: string, kind: string) => {
    require(seen.get(kind) === keys, kind + ' 的上下文应只有 ' + keys + '，实际 ' + seen.get(kind))
  })
}

async function sameRequestRules(): Promise<void> {
  require(normalizeUris(['b', '', 'a', 'b', '']).join(',') === 'a,b', 'uris 去空串、去重、排序')
  let astral = '\u{1F600}'
  let bmp = '\uFF5E'
  let sorted = normalizeUris([astral, bmp])
  require(sorted[0] === bmp && sorted[1] === astral, '按 UTF-8 字节序，不按 UTF-16 码元')
  require(sameRequest(request('malware', 'custom', ['x', 'y'], ''), request('malware', 'custom', ['y', '', 'x', 'y'], '')),
    'uris 规范化后全等即相同请求')

  let h = new Harness('')
  let go = new Latch()
  let scopes: string[] = []
  h.table.malware = async (ctx, hand) => {
    scopes.push(ctx.base.request.scope + ':' + ctx.base.request.uris.join('|'))
    await go.promise
    return end(1, '')
  }
  h.table.permission = async (ctx, hand) => end(0, '')
  let first = h.queue.enqueue(request('malware', 'custom', ['file:///b', 'file:///a', ''], ''))
  require(first.length > 0, '成功入队的 jobId 非空')
  let selected = h.queue.requestOf(first)
  require(selected !== null && selected.scope === 'custom' && selected.uris.length === 2,
    '用户当次选择的路径可供同一次作业的后续处置使用')
  if (selected !== null) selected.uris.length = 0
  let saved = h.queue.requestOf(first)
  require(saved !== null && saved.uris.length === 2 && h.queue.requestOf('missing') === null,
    '查询请求必须返回独立快照，并拒绝未知作业')
  let again = h.queue.enqueue(request('malware', 'custom', ['file:///a', 'file:///b', 'file:///a'], ''))
  require(again === first, '相同请求返回已有 jobId')
  require(h.queue.enqueue(request('malware', 'full', [], '')) === '', '同 kind 不同 scope 返回空串')
  require(h.queue.enqueue(request('malware', 'custom', ['file:///a', 'file:///b'], 'x')) === '',
    '同 kind 不同 focus 返回空串')
  require(h.queue.enqueue(request('malware', 'custom', ['file:///a'], '')) === '', '同 kind 不同 uris 返回空串')
  let running = h.queue.active('malware')
  require(running !== null && running.scope === 'custom', '页面能读到正在跑的 scope')
  require(h.rows().length === 1, '被拒绝或合并的请求不新写记录')

  let perm = h.queue.enqueue(request('permission', 'quick', [], ''))
  let anomaly = h.queue.enqueue(request('permission', 'quick', [], 'anomaly:job-1-00000000'))
  await until(() => h.row(perm).state === 'done', '权限作业结束')
  require(anomaly === '', 'focus 不同的权限请求不并成同一个 jobId')
  let later = h.queue.enqueue(request('permission', 'quick', [], 'anomaly:job-1-00000000'))
  require(later.length > 0 && later !== perm, 'done 不占用名额')

  go.open()
  await until(() => h.row(first).state === 'done', '原作业按自己的请求跑完')
  require(scopes.length === 1 && scopes[0] === 'custom:file:///a|file:///b', '原作业仍是自己的请求：' + scopes.join(';'))
  let next = h.queue.enqueue(request('malware', 'full', [], ''))
  require(next.length > 0 && next !== first, '收口后同 kind 可以再入队')
  await until(() => h.rows().every((r) => terminal(r.state)), '新作业结束')

  let stale = new Harness(JSON.stringify([
    { jobId: 'job-3-aaaaaaaa', seq: 3, kind: 'malware', lane: 'heavy', startedAt: '', finishedAt: '',
      state: 'interrupted', itemCount: 0, riskCount: 0, summary: '扫描已中断', resultFile: '' },
    { jobId: 'job-4-bbbbbbbb', seq: 4, kind: 'apps', lane: 'light', startedAt: '', finishedAt: '',
      state: 'failed', itemCount: 0, riskCount: 0, summary: '', resultFile: '' },
    { jobId: 'job-5-cccccccc', seq: 5, kind: 'protect', lane: 'light', startedAt: '', finishedAt: '',
      state: 'cancelled', itemCount: 0, riskCount: 0, summary: '', resultFile: '' }
  ]))
  stale.table.malware = async (ctx, hand) => end(0, '')
  stale.table.apps = async (ctx, hand) => end(0, '')
  stale.table.protect = async (ctx, hand) => end(0, '')
  require(stale.queue.enqueue(request('malware', 'quick', [], '')).length > 0, 'interrupted 不占用名额')
  require(stale.queue.enqueue(request('apps', 'quick', [], '')).length > 0, 'failed 不占用名额')
  require(stale.queue.enqueue(request('protect', 'quick', [], 'rules')).length > 0, 'cancelled 不占用名额')
  await until(() => stale.rows().every((r) => terminal(r.state)), '全部收口')
}

async function jobIdRules(): Promise<void> {
  let permissions = [
    'LOCATION', 'CAMERA', 'MICROPHONE', 'READ_CONTACTS', 'READ_CALENDAR', 'RECEIVE_SMS', 'PLACE_CALL', 'READ_MEDIA',
    'INTERNET'
  ]
  let reserved = ['', 'quick', 'full', 'custom', 'rules', 'sensitive', 'anomaly:', 'anomaly:job-1']
  for (let i = 0; i < permissions.length; i++) {
    reserved.push(groupOf('ohos.permission.' + permissions[i]))
  }
  for (let i = 0; i < reserved.length; i++) {
    require(!isJobId(reserved[i]), '「' + reserved[i] + '」不是 jobId')
  }
  let files = new MemoryFiles()
  Writer.bind(files)
  let offered = ['quick', 'anomaly:x', '', '位置', 'job-1-12345678']
  let at = 0
  let table = new RunnerTable()
  let queue = new JobQueue(new JobRunner(ports(), () => table), new StubGate(), new StepClock(), new SinkLog(),
    (work: () => void) => {}, (seq: number) => offered[at++])
  let id = queue.enqueue(request('protect', 'quick', [], ''))
  require(id === 'job-1-12345678', '跳过保留名，实际 ' + id)
  await until(() => {
    let text = files.read(INDEX)
    return text !== null && (JSON.parse(text) as JobRecord[]).every((r) => terminal(r.state))
  }, '收口')
  let real = new Harness('')
  for (let i = 0; i < KINDS.length; i++) {
    let made = real.queue.enqueue(request(KINDS[i], 'quick', [], ''))
    require(isJobId(made) && /^job-\d+-[0-9a-f]{8}$/.test(made), '默认 jobId 形如 job-<seq>-<hex>：' + made)
  }
  await until(() => real.rows().every((r) => terminal(r.state)), '全部收口')
}

async function gateAndWriter(): Promise<void> {
  let h = new Harness(JSON.stringify([
    { jobId: 'job-7-aaaaaaaa', seq: 7, kind: 'exam', lane: 'heavy', startedAt: '', finishedAt: '', state: 'done',
      itemCount: 0, riskCount: 0, summary: '', resultFile: '' }
  ]))
  h.gate.isStale = true
  h.gate.latch = new Latch()
  let ran = false
  h.table.apps = async (ctx, hand) => {
    ran = true
    return end(4, '')
  }
  let id = h.queue.enqueue(request('apps', 'quick', [], ''))
  require(h.gate.probes === 1, 'Gate 缓存过期时入队前调用 probe()')
  let row = h.row(id)
  require(row.state === 'queued' && row.seq === 8, '入队立刻写 queued，seq 取最大值加 1')
  require(row.startedAt.length > 0 && row.finishedAt === '', 'startedAt 来自 Clock')
  await tick()
  require(!ran && h.row(id).state === 'queued', 'probe 完成前不开始 Runner')
  h.gate.latch.open()
  await until(() => h.row(id).state === 'done', '作业完成')
  require(ran && h.row(id).itemCount === 4, 'Runner 跑完后写 done 与 itemCount')

  let fresh = new Harness('')
  fresh.table.protect = async (ctx, hand) => end(0, '')
  let first = fresh.queue.enqueue(request('protect', 'quick', [], ''))
  require(fresh.gate.probes === 0, 'Gate 缓存未过期时不调用 probe()')
  require(fresh.row(first).seq === 1, '空索引从 1 开始')
  await until(() => fresh.row(first).state === 'done', '完成')

  let states: string[] = []
  let watch = new Harness('')
  watch.table.protect = async (ctx, hand) => {
    states.push(watch.row(ctx.base.job.jobId).state)
    return end(0, '')
  }
  let wid = watch.queue.enqueue(request('protect', 'quick', [], ''))
  states.push(watch.row(wid).state)
  await until(() => watch.row(wid).state === 'done', '完成')
  require(states.join(',') === 'queued,running', '先 queued 再 running：' + states.join(','))

  let both = new Harness('')
  let heavyGo = new Latch()
  let lightGo = new Latch()
  both.table.exam = async (ctx, hand) => {
    await heavyGo.promise
    return end(1, '')
  }
  both.table.apps = async (ctx, hand) => {
    await lightGo.promise
    return end(1, '')
  }
  let heavy = both.queue.enqueue(request('exam', 'quick', [], ''))
  let light = both.queue.enqueue(request('apps', 'quick', [], ''))
  await until(() => both.row(heavy).state === 'running' && both.row(light).state === 'running', '两条车道同时运行')
  heavyGo.open()
  lightGo.open()
  await until(() => both.row(heavy).state === 'done' && both.row(light).state === 'done', '两条同时结束')
  require(both.rows().length === 2, '两条车道同时结束时 index.json 里两条记录都在')
}

async function cancelRules(): Promise<void> {
  let flag = new CancelFlag()
  require(flag.buffer instanceof SharedArrayBuffer && flag.buffer.byteLength === CANCEL_BYTES && CANCEL_BYTES === 4,
    'CancelFlag 是 4 字节 SharedArrayBuffer')
  let cells = new Int32Array(flag.buffer)
  require(cells[0] === 0 && !flag.cancelled() && !readCancel(flag), '0 表示继续')
  flag.cancel()
  require(cells[0] === 1 && flag.cancelled() && readCancel(flag), '1 表示取消')
  require(!readCancel(new OpenMarker()), '别的对象不算取消')

  let h = new Harness('')
  let step = new Latch()
  let examHold = new Latch()
  let processedSeen = 0
  h.table.malware = async (ctx, hand) => {
    let done = 0
    for (let i = 0; i < 10; i++) {
      if (ctx.base.cancel.cancelled()) {
        break
      }
      done++
      ctx.base.report(done, 10, '快速扫描')
      if (done === 3) {
        step.open()
        await examHold.promise
      }
    }
    processedSeen = done
    return end(done, '')
  }
  h.table.exam = async (ctx, hand) => end(0, '')
  let id = h.queue.enqueue(request('malware', 'quick', [], ''))
  let waiting = h.queue.enqueue(request('exam', 'quick', [], ''))
  await step.promise
  require(h.queue.cancel(waiting), '排队中的作业可以取消')
  require(h.row(waiting).state === 'cancelled' && h.row(waiting).itemCount === 0, '没开始的作业 cancelled，条数 0')
  require(h.queue.cancel(id), 'cancel 找到运行中的作业')
  examHold.open()
  await until(() => h.row(id).state === 'cancelled', '运行中的作业记 cancelled')
  require(h.row(id).itemCount === 3 && processedSeen === 3, 'itemCount 等于已处理数：' + h.row(id).itemCount)
  require(!h.queue.cancel(id), '已收口的作业不再取消')
  require(!h.queue.cancel(''), '空串不是 jobId')

  let thrower = new Harness('')
  let hold = new Latch()
  let entered = new Latch()
  thrower.table.clean = async (ctx, hand) => {
    ctx.base.report(2, 5, '')
    entered.open()
    await hold.promise
    throw new CenterError('cancelled', 'stopped')
  }
  let cid = thrower.queue.enqueue(request('clean', 'quick', [], ''))
  await entered.promise
  thrower.queue.cancel(cid)
  hold.open()
  await until(() => thrower.row(cid).state === 'cancelled', '抛 cancelled 也记 cancelled')
  require(thrower.row(cid).itemCount === 2, 'Runner 抛出时 itemCount 取最近一次 report 的 done')
}

async function failureRules(): Promise<void> {
  let h = new Harness('')
  h.table.exam = async (ctx, hand) => {
    hand.save({ partial: 'kept' } as Object)
    ctx.base.report(1, 9, '')
    throw new Error('boom')
  }
  h.table.malware = async (ctx, hand) => {
    hand.save({ hits: 1 } as Object)
    throw new CenterError('io', 'hash-worker:spawn')
  }
  h.table.clean = async (ctx, hand) => end(5000, '已达本次扫描上限')
  h.table.permission = async (ctx, hand) => {
    throw new CenterError('unsupported', 'grants')
  }
  h.table.apps = async (ctx, hand) => {
    throw new CenterError('cloud', 'offline')
  }
  let exam = h.queue.enqueue(request('exam', 'quick', [], ''))
  let malware = h.queue.enqueue(request('malware', 'quick', [], ''))
  let clean = h.queue.enqueue(request('clean', 'quick', [], ''))
  let perm = h.queue.enqueue(request('permission', 'quick', [], ''))
  let apps = h.queue.enqueue(request('apps', 'quick', [], ''))
  let protect = h.queue.enqueue(request('protect', 'quick', [], ''))
  await until(() => h.rows().every((r) => terminal(r.state)), '全部收口')

  let failed = h.row(exam)
  require(failed.state === 'failed' && failed.itemCount === 1, 'Runner 抛错时作业记 failed')
  require(failed.resultFile.length > 0 && h.files.read(failed.resultFile) === '{"partial":"kept"}', '已写入的结果保留')
  let down = h.row(malware)
  require(down.state === 'failed' && down.summary === '文件处理失败', 'Worker 起不来时作业 failed，原因走 io')
  require(h.files.read(down.resultFile) === '{"hits":1}', 'Worker 起不来时已完成条目保留')
  require(h.row(clean).state === 'done' && h.row(clean).summary === '已达本次扫描上限', '触到上限时作业是 done')
  require(h.row(perm).state === 'done', 'unsupported 不让作业 failed')
  require(h.row(apps).state === 'done', '云查询失败不让作业 failed')
  require(h.row(protect).state === 'failed' && h.row(protect).summary === '暂不支持', '没有 Runner 时 failed，写暂不支持')
}

interface ExamPeek {
  state: string
  appsComplete: boolean
  summary: Record<string, number>
  items: Record<string, string>[]
}

function examBody(jobId: string, appsLevel: string, appLevels: string[], appsComplete: boolean): Object {
  let items: Object[] = [
    { id: 'exam.protect.pure-mode', title: '纯净模式', group: 'protect', status: 'ok', kind: 'state',
      source: 'system', detail: '', action: { route: 'protect', params: '' }, countsTowardState: true }
  ]
  if (appsLevel.length > 0) {
    items.push({ id: 'exam.malware.apps', title: '应用信誉', group: 'threat', status: appsLevel, kind: 'state',
      source: 'local-rule', detail: '', action: { route: 'malware', params: jobId }, countsTowardState: true })
  }
  let apps: Object[] = []
  for (let i = 0; i < appLevels.length; i++) {
    apps.push({ displayName: 'app' + i, quarantined: false, action: 'none', granted: [],
      verdict: { level: appLevels[i], source: 'local-rule', reason: '', evidence: '', cloud: 'reached' } })
  }
  return {
    jobId: jobId, state: 'clear', items: items, apps: apps, appsComplete: appsComplete,
    summary: { riskApps: 0, suspiciousApps: 0, unknownApps: 0, okApps: 0, parts: [], cleanableBytes: 0,
      cleanableKnown: false, cleanableNote: '', sensitiveApps: 0, sensitiveKnown: false, anomalyApps: 0 },
    skipped: 0, advice: 0, generatedAt: ''
  } as Object
}

function peekExam(h: Harness, jobId: string): ExamPeek {
  let text = h.files.read('center/jobs/' + jobId + '.json')
  if (text === null) {
    throw new Error('no exam result for ' + jobId)
  }
  return JSON.parse(text) as ExamPeek
}

async function settleStoppedExams(): Promise<void> {
  let cancel = new Harness('')
  let entered = new Latch()
  let hold = new Latch()
  cancel.table.exam = async (ctx, hand) => {
    hand.save(examBody(ctx.base.job.jobId, 'ok', ['ok', 'ok'], true))
    ctx.base.report(2, 4, '正在计算可清理空间')
    entered.open()
    await hold.promise
    return end(2, '')
  }
  let cid = cancel.queue.enqueue(request('exam', 'quick', [], ''))
  await entered.promise
  cancel.queue.cancel(cid)
  hold.open()
  await until(() => cancel.row(cid).state === 'cancelled', '体检取消')
  let afterCancel = peekExam(cancel, cid)
  let cancelApps = afterCancel.items[1]
  require(cancel.row(cid).state === 'cancelled', '收口后作业状态保持 cancelled')
  require(afterCancel.summary.okApps === 2, 'cancel 之后调用 settleStoppedExam')
  require(afterCancel.appsComplete && cancelApps.detail.indexOf('本次扫描未完成') < 0 && cancelApps.status === 'ok',
    '应用循环写完后在统计缓存阶段取消，详情不含本次扫描未完成：' + cancelApps.detail)
  require(afterCancel.state === 'clear', '没有风险和未知时圆环不是未完成')

  let early = new Harness('')
  early.table.exam = async (ctx, hand) => {
    hand.save(examBody(ctx.base.job.jobId, '', [], false))
    throw new Error('boom')
  }
  let eid = early.queue.enqueue(request('exam', 'quick', [], ''))
  await until(() => terminal(early.row(eid).state), '体检抛错')
  let afterThrow = peekExam(early, eid)
  require(early.row(eid).state === 'failed', 'Runner 抛错时作业保持 failed')
  require(afterThrow.state === 'incomplete', '只写了姿态 ok 的半成品收口后不是 clear：' + afterThrow.state)

  let down = new Harness('')
  down.table.exam = async (ctx, hand) => {
    hand.save(examBody(ctx.base.job.jobId, 'ok', ['risk', 'suspicious'], false))
    throw new CenterError('io', 'hash-worker:spawn')
  }
  let did = down.queue.enqueue(request('exam', 'quick', [], ''))
  await until(() => terminal(down.row(did).state), 'Worker 起不来')
  let afterDown = peekExam(down, did)
  require(down.row(did).state === 'failed' && down.row(did).summary === '文件处理失败',
    'Worker 起不来时体检记 failed，原因走 io')
  require(afterDown.state === 'risk' && afterDown.summary.riskApps === 1 && afterDown.items[1].status === 'risk',
    'Worker 起不来时同样收口，apps[] 已有风险时 state 是 risk')
  require(afterDown.items.length === 3 && afterDown.items[2].id === 'exam.malware.suspicious',
    '收口时补上可疑应用项')
  require(!afterDown.appsComplete, 'appsComplete 为 false 时保持 false')

  let bare = new Harness('')
  bare.table.exam = async (ctx, hand) => {
    throw new Error('before save')
  }
  let bid = bare.queue.enqueue(request('exam', 'quick', [], ''))
  await until(() => terminal(bare.row(bid).state), '没有结果文件的体检抛错')
  require(bare.row(bid).state === 'failed' && bare.files.read('center/jobs/' + bid + '.json') === null,
    '没有结果文件时不合成 clear')

  let other = new Harness('')
  other.table.exam = async (ctx, hand) => {
    hand.save(examBody(ctx.base.job.jobId, 'ok', ['risk'], true))
    return end(1, '')
  }
  let first = other.queue.enqueue(request('exam', 'quick', [], ''))
  await until(() => other.row(first).state === 'done', '第一份体检 done')
  let firstText = other.files.read('center/jobs/' + first + '.json')
  other.table.exam = async (ctx, hand) => {
    hand.save(examBody(ctx.base.job.jobId, '', [], false))
    throw new Error('boom')
  }
  let second = other.queue.enqueue(request('exam', 'quick', [], ''))
  await until(() => terminal(other.row(second).state), '第二份体检抛错')
  require(other.files.read('center/jobs/' + first + '.json') === firstText, '不改另一条已经 done 的体检')
}

async function reportOnUiThread(): Promise<void> {
  let h = new Harness('')
  let reported = new Latch()
  let hold = new Latch()
  h.table.exam = async (ctx, hand) => {
    ctx.base.report(1, 4, '体检中')
    reported.open()
    await hold.promise
    return end(4, '')
  }
  h.table.apps = async (ctx, hand) => end(0, '')
  h.queue.enqueue(request('exam', 'quick', [], ''))
  await reported.promise
  require(h.sink.writes.length === 0, 'report 不直接写 AppStorage')
  h.posted.flush()
  let heavy = h.sink.last.get(HEAVY_KEY)
  require(heavy !== undefined && heavy.done === 1 && heavy.total === 4 && heavy.message === '体检中',
    '切回 UI 线程后写 center.job.heavy')
  require(h.sink.last.get(LIGHT_KEY) === undefined, '重车道不写 center.job.light')
  h.queue.enqueue(request('apps', 'quick', [], ''))
  hold.open()
  await until(() => h.rows().every((r) => terminal(r.state)), '全部收口')
  h.posted.flush()
  let light = h.sink.last.get(LIGHT_KEY)
  require(light !== undefined && light.state === 'done' && light.kind === 'apps', '轻车道写 center.job.light')
  require(h.sink.last.get(HEAVY_KEY)?.state === 'done', '收尾也经 UI 线程发布')
}

function registryIsEmpty(): void {
  RunnerRegistry.registerAll()
  let table = RunnerRegistry.table()
  for (let i = 0; i < KINDS.length; i++) {
    require(!table.has(KINDS[i]), '本轮注册空的 Runner 表：' + KINDS[i])
  }
}

class ChunkIo implements HashIo {
  size: number
  reads: number = 0
  onRead: (reads: number) => void = (reads: number) => {}
  failAt: number = -1

  constructor(size: number) {
    this.size = size
  }

  read(fd: number, buffer: ArrayBuffer, offset: number): number {
    if (this.reads === this.failAt) {
      throw new Error('eio')
    }
    let count = Math.min(buffer.byteLength, this.size - offset)
    if (count <= 0) {
      return 0
    }
    this.reads++
    this.onRead(this.reads)
    return count
  }
}

class SizeDigest implements Digest {
  sizes: number[] = []

  update(bytes: Uint8Array): void {
    this.sizes.push(bytes.length)
  }

  hex(): string {
    return 'digest'
  }
}

function hashRules(): void {
  let flag = new CancelFlag()
  let io = new ChunkIo(3 * CHUNK + 5)
  let digest = new SizeDigest()
  let whole = hashFd(io, digest, 3, flag.buffer)
  require(whole.sha256 === 'digest' && whole.bytes === 3 * CHUNK + 5 && !whole.cancelled, '读完整个文件')
  require(digest.sizes.join(',') === [CHUNK, CHUNK, CHUNK, 5].join(','), '按 hashChunk 分块更新')

  let stop = new CancelFlag()
  let big = new ChunkIo(50 * CHUNK)
  big.onRead = (reads: number) => {
    if (reads === 2) {
      stop.cancel()
    }
  }
  let cut = hashFd(big, new SizeDigest(), 3, stop.buffer)
  require(cut.cancelled && cut.sha256 === '' && big.reads === 2, '取消后在下一个分块之前停止，读了 ' + big.reads + ' 块')

  let pre = new CancelFlag()
  pre.cancel()
  let none = new ChunkIo(CHUNK)
  require(hashFd(none, new SizeDigest(), 3, pre.buffer).cancelled && none.reads === 0, '已取消时不读')

  let bad = new ChunkIo(4 * CHUNK)
  bad.failAt = 1
  let broken = hashFd(bad, new SizeDigest(), 3, new CancelFlag().buffer)
  require(broken.error.indexOf('read:') === 0 && broken.sha256 === '', '读失败只记在这一个文件上')
}

export async function runTaskQueueChecks(): Promise<void> {
  registryIsEmpty()
  hashRules()
  await lanesAndOrder()
  await contextsOnlyOwnPorts()
  await sameRequestRules()
  await jobIdRules()
  await gateAndWriter()
  await cancelRules()
  await failureRules()
  await settleStoppedExams()
  await reportOnUiThread()
}
