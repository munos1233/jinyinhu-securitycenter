import type {
  BundleRow, CheckItem, ExamReport, Gate, JobKind, JobRecord, JobState, PermissionFact, ScanHit, ScanReport, UseFact
} from '../main/ets/center/CenterTypes'
import { CenterError } from '../main/ets/center/CenterError'
import { RulePack } from '../main/ets/engine/RulePack'
import { PermissionActions } from '../main/ets/record/PermissionActions'
import type { PermissionAccess, PermissionGate } from '../main/ets/record/PermissionActions'
import type { CenterFiles } from '../main/ets/record/Writer'
import { Writer } from '../main/ets/record/Writer'

const CAMERA: string = 'ohos.permission.CAMERA'
const BACKGROUND: string = 'ohos.permission.LOCATION_IN_BACKGROUND'
const APPROXIMATE: string = 'ohos.permission.APPROXIMATELY_LOCATION'
const NAME: string = 'com.test.permissions'

function require(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message)
  }
}

class Memory implements CenterFiles {
  data: Map<string, string> = new Map()
  read(path: string): string | null { return this.data.get(path) || null }
  write(path: string, text: string): void { this.data.set(path, text) }
  remove(path: string): void { this.data.delete(path) }
  rename(from: string, to: string): void {
    let text = this.read(from)
    if (text !== null) { this.data.set(to, text); this.data.delete(from) }
  }
}

class GatePort implements PermissionGate {
  reading: boolean = true
  revoking: boolean = true
  used: boolean = true
  stale(): boolean { return false }
  grants(): Gate { return { id: 'grants', status: this.reading ? 'ready' : 'unsupported', reason: '' } }
  revoke(): Gate { return { id: 'revoke', status: this.revoking ? 'ready' : 'unsupported', reason: '' } }
  usedStats(): Gate { return { id: 'used', status: this.used ? 'ready' : 'unsupported', reason: '' } }
}

class Access implements PermissionAccess {
  rows: PermissionFact[] = [fact(CAMERA), fact(BACKGROUND)]
  calls: number[] = []
  fail: boolean = false
  flagsReadable: boolean = true
  flagChecks: number = 0
  readCalls: number = 0
  async facts(bundles: BundleRow[]): Promise<PermissionFact[]> {
    this.readCalls++
    return this.rows.filter((row: PermissionFact): boolean => bundles.some((b: BundleRow): boolean =>
      b.bundleName === row.bundleName && b.declaredPermissions.indexOf(row.permission) >= 0))
  }
  async recentUses(): Promise<UseFact[]> { return [] }
  async canRevoke(tokenId: number, permission: string): Promise<boolean> {
    this.flagChecks++
    return this.flagsReadable
  }
  async revoke(tokenId: number, permission: string): Promise<void> {
    this.calls.push(tokenId)
    if (this.fail) { throw new CenterError('unsupported', 'revokeUserGrantedPermission:201') }
    for (let row of this.rows) { if (row.permission === permission) { row.grant = 'denied' } }
  }
}

function fact(permission: string, tokenId: number = 42): PermissionFact {
  return { bundleName: NAME, displayName: '测试应用', permission: permission, label: permission,
    group: permission === CAMERA ? '相机' : '位置', sensitive: true, declared: true, grant: 'granted',
    fixed: false, tokenId: tokenId, source: 'unknown' }
}

function bundle(): BundleRow {
  return { bundleName: NAME, version: '1', versionCode: 1, certSha256: 'aabb', certAlgo: 'platform-fingerprint',
    declaredPermissions: [CAMERA, BACKGROUND], source: 'unknown',
    verdict: { level: 'unknown', source: 'system', reason: '', evidence: '', cloud: 'unchecked' } }
}

function hit(): ScanHit {
  return { fingerprint: { kind: 'bundle', id: NAME, bundleName: NAME, version: '1', versionCode: 1,
      certSha256: 'aabb', certAlgo: 'platform-fingerprint', sha256: '', size: 0, label: '' },
    displayName: '测试应用', verdict: { level: 'suspicious', source: 'local-rule', reason: '后台定位和相机',
      evidence: 'heuristic', cloud: 'reached' }, quarantined: false, action: 'none', granted: [CAMERA, BACKGROUND] }
}

function item(id: string, status: CheckItem['status'], advice: boolean = false): CheckItem {
  return { id: id, title: '', group: 'threat', status: status, kind: advice ? 'advice' : 'state',
    source: 'local-rule', detail: '', action: { route: '', params: '' }, countsTowardState: !advice }
}

function exam(): ExamReport {
  return { jobId: '', state: 'clear', apps: [hit()], appsComplete: true,
    items: [item('exam.malware.apps', 'ok'), item('exam.malware.suspicious', 'attention', true),
      item('exam.permission.anomaly', 'attention', true)],
    summary: { riskApps: 0, suspiciousApps: 1, unknownApps: 0, okApps: 0, parts: [], cleanableBytes: 0,
      cleanableKnown: false, cleanableNote: '', sensitiveApps: 1, sensitiveKnown: true, anomalyApps: 1 },
    skipped: 0, advice: 2, generatedAt: '' }
}

function scan(): ScanReport {
  return { hits: [hit()], complete: true, note: '', judged: 1, risk: 0, suspicious: 1, unknown: 0, ok: 0 }
}

function record(id: string, seq: number, kind: JobKind, state: JobState = 'done'): JobRecord {
  return { jobId: id, seq: seq, kind: kind, state: state, lane: kind === 'permission' ? 'light' : 'heavy',
    startedAt: '', finishedAt: '', itemCount: 1, riskCount: 0, summary: '', resultFile: Writer.resultFileOf(id) }
}

class Setup {
  memory: Memory = new Memory()
  access: Access = new Access()
  gate: GatePort = new GatePort()
  bundles: BundleRow[] = [bundle()]
  user: boolean = true
  censusFail: boolean = false
  actions: PermissionActions
  constructor() {
    Writer.bind(this.memory)
    RulePack.load(JSON.stringify({ version: '2026.11.15', bundles: [], officials: [], files: [],
      heuristics: [{ id: 'background-camera', permissions: [CAMERA, BACKGROUND], reason: '后台定位和相机',
        level: 'suspicious' }] }))
    this.actions = new PermissionActions({ census: { list: async (): Promise<BundleRow[]> => {
      if (this.censusFail) throw new CenterError('unsupported', 'list:201')
      return this.bundles
    } },
      access: this.access, gate: this.gate, userGrant: async (name: string): Promise<boolean> => this.user })
    Writer.saveIndex([record('permission', 4, 'permission'), record('exam-done', 1, 'exam'),
      record('exam-viewing', 3, 'exam', 'interrupted'), record('malware', 2, 'malware')])
    this.put('permission', { facts: [fact(CAMERA, 999), fact(BACKGROUND, 999)], uses: [],
      counts: [{ group: '位置', count: 17, known: false }, { group: '相机', count: 19, known: true }],
      bundlesAvailable: true, usesAvailable: true })
    this.put('exam-done', exam()); this.put('exam-viewing', exam()); this.put('malware', scan())
  }
  put(id: string, report: Object): void { this.memory.write(Writer.resultFileOf(id), JSON.stringify(report)) }
  text(id: string): string { return this.memory.read(Writer.resultFileOf(id)) || '' }
  exam(id: string = 'exam-done'): ExamReport { return JSON.parse(this.text(id)) as ExamReport }
  scan(): ScanReport { return JSON.parse(this.text('malware')) as ScanReport }
}

class PermissionBody {
  facts: PermissionFact[] = []
  counts: GroupCount[] = []
  usesAvailable: boolean = false
  bundlesAvailable: boolean = false
}
class GroupCount { group: string = ''; count: number = 0; known: boolean = false }

export async function runPermissionActionsChecks(): Promise<void> {
  let setup = new Setup()
  let done = await setup.actions.revoke('permission', NAME, CAMERA, 'anomaly:exam-viewing')
  require(done.done, 'a known anomaly target with a fresh grant must close')
  require(setup.access.calls.length === 1 && setup.access.calls[0] === 42,
    'revoke must use the freshly read token, never token 999 from stored permission facts')
  let body = JSON.parse(setup.text('permission')) as PermissionBody
  require(body.facts[0].grant === 'denied' && body.counts[1].count === 18 && body.counts[0].count === 17 &&
    body.usesAvailable && body.bundlesAvailable && !body.counts[0].known && body.counts[1].known,
    'success preserves report availability and whole-census counts, decrementing only the affected group')
  for (let id of ['exam-done', 'exam-viewing']) {
    let report = setup.exam(id)
    require(report.apps[0].granted.indexOf(CAMERA) < 0 && report.apps[0].verdict.evidence === 'heuristic-cleared' &&
      report.summary.suspiciousApps === 0 && report.summary.unknownApps === 1 && report.appsComplete,
      'success must rejudge each selected exam using existing rules and preserve appsComplete')
  }
  require(setup.scan().hits[0].verdict.evidence === 'heuristic-cleared' && setup.scan().complete,
    'the latest settled reputation result must be rejudged without changing completeness')
  require(Writer.loadIndex().length === 4, 'revoke must not create a running job or replace the index')

  setup = new Setup()
  setup.access.fail = true
  let oldExam = setup.text('exam-done'); let oldScan = setup.text('malware')
  done = await setup.actions.revoke('permission', NAME, CAMERA, '')
  require(!done.done && done.message.indexOf('201') >= 0 && setup.text('exam-done') === oldExam &&
    setup.text('malware') === oldScan && (JSON.parse(setup.text('permission')) as PermissionBody).facts[0].grant === 'granted',
    'a platform refusal preserves granted state and all exam/reputation reports with the return code')

  for (let mode of ['token', 'fixed', 'denied', 'unknown', 'system', 'gate', 'flags', 'foreign']) {
    setup = new Setup()
    if (mode === 'token') setup.access.rows[0].tokenId = 0
    if (mode === 'fixed') setup.access.rows[0].fixed = true
    if (mode === 'denied') setup.access.rows[0].grant = 'denied'
    if (mode === 'unknown') setup.access.rows[0].grant = 'unknown'
    if (mode === 'system') setup.user = false
    if (mode === 'gate') setup.gate.revoking = false
    if (mode === 'flags') setup.access.flagsReadable = false
    done = await setup.actions.revoke('permission', mode === 'foreign' ? 'com.foreign' : NAME, CAMERA, '')
    require(!done.done && setup.access.calls.length === 0, mode + ' must not invoke platform revoke')
  }

  setup = new Setup()
  require(await setup.actions.canRevoke(fact(CAMERA)), 'the button may be offered only after a successful current flag read')
  setup.access.flagsReadable = false
  done = await setup.actions.revoke('permission', NAME, CAMERA, '')
  require(!done.done && setup.access.calls.length === 0 && setup.access.flagChecks === 2,
    'revoke must reread flags instead of relying on a previously enabled switch')

  setup = new Setup()
  let trusted = setup.exam('exam-viewing'); trusted.apps[0].verdict.source = 'trust'; setup.put('exam-viewing', trusted)
  require((await setup.actions.revoke('', NAME, CAMERA, 'anomaly:exam-viewing')).done,
    'trust is still eligible for anomaly permission handling without a permission job')
  setup = new Setup()
  let official = setup.exam('exam-viewing'); official.apps[0].verdict.evidence = 'official'; setup.put('exam-viewing', official)
  require(!(await setup.actions.revoke('permission', NAME, CAMERA, 'anomaly:exam-viewing')).done &&
    setup.access.calls.length === 0, 'an official anomaly row must not be expanded or acted on')
  setup = new Setup()
  require((await setup.actions.revoke('', NAME, CAMERA, NAME)).done,
    'a bundle-name route may close a current permission named in its latest finished scan')
  setup = new Setup()
  require(!(await setup.actions.revoke('', NAME, 'ohos.permission.MICROPHONE', NAME)).done,
    'a caller cannot fabricate a permission absent from every settled snapshot')

  // A directly opened, installed bundle can be managed before any scan result exists.
  setup = new Setup()
  Writer.saveIndex([])
  done = await setup.actions.revoke('', NAME, CAMERA, NAME)
  require(done.done && setup.access.calls.length === 1 && setup.access.calls[0] === 42 &&
    Writer.loadIndex().length === 0,
    'a no-history bundle route must use live census declarations and fresh access without creating a job')
  for (let mode of ['fabricated', 'absent', 'census-failed', 'token', 'fixed', 'denied', 'system', 'wrong-focus']) {
    setup = new Setup()
    Writer.saveIndex([])
    let permission = CAMERA
    if (mode === 'fabricated') {
      permission = 'ohos.permission.MICROPHONE'
      setup.access.rows.push(fact(permission))
    }
    if (mode === 'absent') setup.bundles = []
    if (mode === 'census-failed') setup.censusFail = true
    if (mode === 'token') setup.access.rows[0].tokenId = 0
    if (mode === 'fixed') setup.access.rows[0].fixed = true
    if (mode === 'denied') setup.access.rows[0].grant = 'denied'
    if (mode === 'system') setup.user = false
    done = await setup.actions.revoke('', NAME, permission, mode === 'wrong-focus' ? '' : NAME)
    require(!done.done && setup.access.calls.length === 0,
      mode + ': no-history routes must not fabricate an eligible declaration or bypass current checks')
    if (mode === 'fabricated' || mode === 'census-failed' || mode === 'absent') {
      require(setup.access.readCalls === 0, 'a failed live declaration check must not query fabricated permission facts')
    }
  }

  // Truncated input contains only CAMERA. The fresh, complete access read must preserve BACKGROUND and APPROXIMATE.
  setup = new Setup()
  setup.bundles[0].declaredPermissions.push(APPROXIMATE)
  setup.access.rows.push(fact(APPROXIMATE))
  setup.access.rows[0].grant = 'denied'
  await setup.actions.reconcile('permission', '', [fact(CAMERA)])
  require(setup.scan().hits[0].granted.indexOf(APPROXIMATE) >= 0 &&
    setup.scan().hits[0].granted.indexOf(BACKGROUND) >= 0 && setup.scan().hits[0].granted.indexOf(CAMERA) < 0,
    'refresh must reread complete bundle grants instead of replacing from truncated permission rows')
  for (let mode of ['unknown', 'missing', 'zero']) {
    setup = new Setup()
    if (mode === 'unknown') setup.access.rows[0].grant = 'unknown'
    if (mode === 'missing') setup.access.rows.pop()
    if (mode === 'zero') setup.access.rows[0].tokenId = 0
    oldScan = setup.text('malware')
    await setup.actions.reconcile('permission', '', [fact(CAMERA)])
    require(setup.text('malware') === oldScan, mode + ' refresh must leave unknown or incomplete grants untouched')
  }

  setup = new Setup()
  setup.access.rows.push(fact(APPROXIMATE)); setup.bundles[0].declaredPermissions.push(APPROXIMATE)
  done = await setup.actions.revoke('permission', NAME, BACKGROUND, '')
  body = JSON.parse(setup.text('permission')) as PermissionBody
  require(done.done && body.counts[0].count === 17,
    'closing one permission must not decrement people count while another permission in that group is granted')
}
