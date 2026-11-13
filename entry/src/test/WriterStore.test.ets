import { jobMax, listMax } from '../main/ets/center/CenterLimits'
import type {
  ActionRef,
  BundleRow,
  CacheRow,
  CheckItem,
  CleanReport,
  DuplicateGroup,
  ExamReport,
  FileHit,
  FileToolReport,
  JobKind,
  JobRecord,
  JobState,
  PermissionFact,
  ProtectFact,
  ScanHit,
  ScanReport,
  UseFact,
  Verdict
} from '../main/ets/center/CenterTypes'
import { CenterStore, grantsKey, preferencesName, rulesVersionKey } from '../main/ets/record/CenterStore'
import { ResultStore } from '../main/ets/record/ResultStore'
import type { CenterFiles } from '../main/ets/record/Writer'
import {
  fileToolLimited,
  fileToolNote,
  limitExamApps,
  limitFacts,
  limitFileHits,
  limitScanReport,
  Writer
} from '../main/ets/record/Writer'

class MemoryFiles implements CenterFiles {
  values: Map<string, string> = new Map()

  read(path: string): string | null {
    if (!this.values.has(path)) {
      return null
    }
    let text = this.values.get(path)
    if (text === undefined) {
      return null
    }
    return text
  }

  write(path: string, text: string): void {
    this.values.set(path, text)
  }

  rename(from: string, to: string): void {
    let text = this.read(from)
    if (text === null) {
      return
    }
    this.values.delete(from)
    this.values.set(to, text)
  }

  remove(path: string): void {
    this.values.delete(path)
  }
}

class VerdictValue implements Verdict {
  level: 'ok' | 'unknown' | 'suspicious' | 'risk' = 'ok'
  source: 'local-rule' | 'cloud' | 'system' | 'trust' | 'local-black' | 'probe' = 'local-rule'
  reason: string = ''
  evidence: string = ''
  cloud: 'unchecked' | 'offline' | 'reached' = 'unchecked'
}

class Hit implements ScanHit {
  fingerprint = {
    kind: 'bundle' as 'bundle' | 'file',
    id: '',
    bundleName: '',
    version: '',
    versionCode: 0,
    certSha256: '',
    certAlgo: 'none' as 'none' | 'platform-fingerprint' | 'sha256-of-cert-bytes',
    sha256: '',
    size: 0,
    label: ''
  }
  displayName: string = ''
  verdict: Verdict = new VerdictValue()
  quarantined: boolean = false
  action: 'none' | 'quarantine' | 'uninstall' | 'cleared' | 'revoked' = 'none'
  granted: string[] = []
}

class Scan implements ScanReport {
  hits: ScanHit[] = []
  complete: boolean = true
  note: string = ''
  judged: number = 0
  risk: number = 0
  suspicious: number = 0
  unknown: number = 0
  ok: number = 0
}

class FileRow implements FileHit {
  uri: string = ''
  name: string = ''
  size: number = 0
  sha256: string = ''
  clazz: 'cache' | 'residue' | 'installer' | 'large' | 'duplicate' = 'installer'
  reason: string = ''
  selected: boolean = true
  groupId: string = ''
}

class Fact implements PermissionFact {
  bundleName: string = ''
  displayName: string = ''
  permission: string = ''
  label: string = ''
  group: string = ''
  sensitive: boolean = false
  declared: boolean = true
  grant: 'granted' | 'denied' | 'unknown' = 'unknown'
  fixed: boolean = false
  tokenId: number = 0
  source: 'unknown' | 'system' | 'preinstalled' | 'store' | 'sideload' = 'unknown'
}

class ExamBody implements ExamReport {
  jobId: string = ''
  state: 'not-run' | 'risk' | 'incomplete' | 'clear' = 'clear'
  items: CheckItem[] = []
  apps: ScanHit[] = []
  appsComplete: boolean = true
  summary = {
    riskApps: 0,
    suspiciousApps: 0,
    unknownApps: 0,
    okApps: 0,
    parts: [],
    cleanableBytes: 0,
    cleanableKnown: false,
    cleanableNote: '',
    sensitiveApps: 0,
    sensitiveKnown: false,
    anomalyApps: 0
  }
  skipped: number = 0
  advice: number = 0
  generatedAt: string = ''
}

class ActionValue implements ActionRef {
  route: string = 'malware'
  params: string = ''
}

class CheckLine implements CheckItem {
  id: string = 'exam.malware.apps'
  title: string = '应用信誉'
  group: 'threat' | 'clean' | 'permission' | 'protect' | 'rules' = 'threat'
  status: 'ok' | 'unknown' | 'risk' | 'attention' | 'unsupported' | 'unverified' = 'risk'
  kind: 'state' | 'advice' = 'state'
  source: 'local-rule' | 'cloud' | 'system' | 'trust' | 'local-black' | 'probe' = 'local-rule'
  detail: string = ''
  action: ActionRef = new ActionValue()
  countsTowardState: boolean = true
}

class CacheLine implements CacheRow {
  bundleName: string = ''
  displayName: string = ''
  cacheBytes: number = 0
  selected: boolean = true
}

class CleanBody implements CleanReport {
  caches: CacheRow[] = []
  hits: FileHit[] = []
  groups: DuplicateGroup[] = []
  complete: boolean = true
  note: string = ''
}

class FileBody implements FileToolReport {
  hits: FileHit[] = []
  groups: DuplicateGroup[] = []
  complete: boolean = true
  note: string = ''
}

class UseLine implements UseFact {
  bundleName: string = ''
  displayName: string = ''
  permission: string = ''
  label: string = ''
  at: string = ''
}

class BundleLine implements BundleRow {
  bundleName: string = ''
  version: string = ''
  versionCode: number = 0
  certSha256: string = ''
  certAlgo: 'none' | 'platform-fingerprint' | 'sha256-of-cert-bytes' = 'none'
  declaredPermissions: string[] = []
  source: 'unknown' | 'system' | 'preinstalled' | 'store' | 'sideload' = 'unknown'
  verdict: Verdict = new VerdictValue()
}

class ProtectLine implements ProtectFact {
  id: string = ''
  status: 'ok' | 'unknown' | 'risk' | 'attention' | 'unsupported' | 'unverified' = 'ok'
  expected: string = ''
  actual: string = ''
  detail: string = ''
}

class Stored implements JobRecord {
  jobId: string = ''
  seq: number = 0
  seqPresent: boolean = true
  kind: JobKind = 'malware'
  lane: 'light' | 'heavy' = 'heavy'
  startedAt: string = ''
  finishedAt: string = ''
  state: JobState = 'done'
  itemCount: number = 0
  riskCount: number = 0
  summary: string = ''
  resultFile: string = ''
}

const INDEX: string = 'center/jobs/index.json'

interface HilogHost {
  __centerHilog?: string[]
}

function fail(message: string): void {
  throw new Error(message)
}

function hilogCount(message: string): number {
  let host = globalThis as HilogHost
  let lines = host.__centerHilog
  if (lines === undefined) {
    return 0
  }
  let count = 0
  for (let i = 0; i < lines.length; i++) {
    if (lines[i] === message) {
      count++
    }
  }
  return count
}

function indexHas(id: string): boolean {
  let text = filesReadIndex()
  let rows = JSON.parse(text) as Stored[]
  for (let i = 0; i < rows.length; i++) {
    if (rows[i].jobId === id) {
      return true
    }
  }
  return false
}

let bound: MemoryFiles | null = null

function filesReadIndex(): string {
  if (bound === null) {
    fail('还没有绑定文件')
    return ''
  }
  let text = bound.read(INDEX)
  if (text === null) {
    fail('索引不存在')
    return ''
  }
  return text
}

function hit(level: 'ok' | 'unknown' | 'suspicious' | 'risk'): ScanHit {
  let value = new Hit()
  let verdict = new VerdictValue()
  verdict.level = level
  value.verdict = verdict
  return value
}

function record(id: string, seq: number, kind: JobKind, state: JobState): Stored {
  let row = new Stored()
  row.jobId = id
  row.seq = seq
  row.seqPresent = true
  row.kind = kind
  row.state = state
  row.resultFile = 'center/jobs/' + id + '.json'
  return row
}

export function runWriterStoreChecks(): void {
  let files = new MemoryFiles()
  bound = files
  Writer.bind(files)
  Writer.replaceText('center/jobs/a.txt', 'one')
  Writer.replaceText('center/jobs/a.txt', 'two')
  if (files.read('center/jobs/a.txt') !== 'two' || files.read('center/jobs/a.txt.tmp') !== null) {
    fail('连续替换丢了更新或留下了临时文件')
  }

  let empty = Writer.nextSeq([])
  let missing = new Stored()
  missing.seqPresent = false
  let noSeq = Writer.nextSeq([missing])
  let third = Writer.nextSeq([record('a', 2, 'malware', 'done')])
  if (empty !== 1 || noSeq !== 1 || third !== 3) {
    fail('seq 没有从最大 seq 加 1，或空索引不是从 1 开始')
  }

  files.write('center/audit.log', 'keep')
  files.write(INDEX, '{')
  CenterStore.prepare(files)
  if (files.read(INDEX) !== '[]') {
    fail('坏索引没有另起空索引')
  }
  let renamed = false
  files.values.forEach((value, key) => {
    if (key.indexOf(INDEX + '.bad-') === 0 && value === '{') {
      renamed = true
    }
  })
  if (!renamed) {
    fail('坏 index.json 被删掉了')
  }
  if (hilogCount('index.json parse failed') !== 1) {
    fail('坏索引没有写 hilog')
  }
  CenterStore.prepare(files)
  if (files.read(INDEX) !== '[]') {
    fail('下次 prepare 没有读到已经写好的空索引')
  }
  if (hilogCount('index.json parse failed') !== 1) {
    fail('空索引被再次当成解析失败')
  }
  if (preferencesName !== 'jinyinhu' || rulesVersionKey !== 'center.rulesVersion' ||
    grantsKey !== 'center.grants') {
    fail('preferences 名或 center. 键名不对')
  }
  files.values.forEach((value, key) => {
    if (key === preferencesName || key === rulesVersionKey || key === grantsKey) {
      fail('prepare 写了 preferences')
    }
  })
  if (files.read('center/audit.log') !== 'keep') {
    fail('prepare 改写了 audit.log')
  }

  let queued = record('q', 3, 'malware', 'queued')
  let done = record('d', 1, 'exam', 'done')
  done.summary = 'keep'
  done.finishedAt = 'old'
  files.write(done.resultFile, '{"state":"clear"}')
  files.write(INDEX, JSON.stringify([queued, done]))
  Writer.recover()
  let after = JSON.parse(files.read(INDEX) as string) as Stored[]
  if (after.length !== 2 || after[0].jobId !== 'q' || after[1].jobId !== 'd' ||
    after[0].state !== 'interrupted' || after[0].summary !== '扫描已中断' ||
    after[0].seq !== 3 || after[0].finishedAt.length === 0) {
    fail('recover 没有按原 seq 把 queued 收成扫描已中断，或又执行了一次')
  }
  if (after[1].state !== 'done' || after[1].summary !== 'keep' || after[1].finishedAt !== 'old') {
    fail('recover 改了已经 done 的体检')
  }
  if (files.read(done.resultFile) !== '{"state":"clear"}') {
    fail('recover 改了结果文件，像是调用了 settleStoppedExam')
  }

  let many: Stored[] = []
  for (let i = 1; i <= jobMax + 1; i++) {
    let row = record('m' + i.toString(), i, 'malware', 'done')
    files.write(row.resultFile, '{}')
    many.push(row)
  }
  Writer.saveIndex(many)
  let trimmed = JSON.parse(files.read(INDEX) as string) as Stored[]
  if (trimmed.length !== jobMax || files.read('center/jobs/m1.json') !== null) {
    fail('没有从 seq 最小的已结束记录开始丢，或没有删结果文件')
  }

  let terminal: Stored[] = []
  let failed = record('failed-1', 1, 'malware', 'failed')
  let cancelled = record('cancelled-1', 2, 'malware', 'cancelled')
  let interrupted = record('interrupted-1', 3, 'malware', 'interrupted')
  files.write(failed.resultFile, '{}')
  files.write(cancelled.resultFile, '{}')
  files.write(interrupted.resultFile, '{}')
  terminal.push(failed)
  terminal.push(cancelled)
  terminal.push(interrupted)
  for (let i = 4; i <= 103; i++) {
    let row = record('d' + i.toString(), i, 'malware', 'done')
    files.write(row.resultFile, '{}')
    terminal.push(row)
  }
  terminal.push(record('q-keep', 200, 'malware', 'queued'))
  terminal.push(record('r-keep', 201, 'malware', 'running'))
  Writer.saveIndex(terminal)
  if (indexHas('failed-1') || indexHas('cancelled-1') || indexHas('interrupted-1') ||
    files.read(failed.resultFile) !== null || files.read(cancelled.resultFile) !== null ||
    files.read(interrupted.resultFile) !== null) {
    fail('failed、cancelled、interrupted 没有按已结束记录丢掉')
  }
  if (!indexHas('q-keep') || !indexHas('r-keep') || !indexHas('d103') || indexHas('d4')) {
    fail('排队中的记录被丢掉了，或没有先丢 seq 更小的已结束记录')
  }

  let queuedMany: Stored[] = []
  for (let i = 1; i <= jobMax + 1; i++) {
    queuedMany.push(record('wait' + i.toString(), i, 'malware', 'queued'))
  }
  Writer.saveIndex(queuedMany)
  let keptRun = JSON.parse(files.read(INDEX) as string) as Stored[]
  if (keptRun.length !== jobMax + 1) {
    fail('排队中的记录被 jobMax 丢掉了')
  }

  let fillers: Stored[] = []
  for (let i = 1; i <= jobMax; i++) {
    let row = record('f' + i.toString(), i, 'malware', 'done')
    files.write(row.resultFile, '{}')
    fillers.push(row)
  }
  let doneExam = record('done-exam', 40, 'exam', 'done')
  files.write(doneExam.resultFile, '{"state":"clear"}')
  let riskExam = record('risk-exam', 50, 'exam', 'interrupted')
  files.write(riskExam.resultFile, '{"state":"risk"}')
  fillers.push(doneExam)
  fillers.push(riskExam)
  Writer.saveIndex(fillers)
  let protectedIndex = JSON.parse(files.read(INDEX) as string) as Stored[]
  let sawDone = false
  let sawRisk = false
  for (let i = 0; i < protectedIndex.length; i++) {
    if (protectedIndex[i].jobId === 'done-exam') {
      sawDone = true
    }
    if (protectedIndex[i].jobId === 'risk-exam') {
      sawRisk = true
    }
  }
  if (!sawDone || !sawRisk || files.read(doneExam.resultFile) === null ||
    files.read(riskExam.resultFile) === null) {
    fail('settledHome 或最近一次 done 体检被丢掉了')
  }

  let scan = new Scan()
  scan.hits.push(hit('risk'))
  scan.hits.push(hit('suspicious'))
  for (let i = 0; i < listMax; i++) {
    scan.hits.push(hit('unknown'))
  }
  scan.hits.push(hit('ok'))
  scan.risk = 1
  scan.suspicious = 1
  scan.unknown = listMax
  scan.ok = 1
  scan.judged = 1
  limitScanReport(scan, true)
  if (scan.complete || scan.note.indexOf('结果较多，仅显示部分') < 0 || scan.hits[0].verdict.level !== 'risk' ||
    scan.hits[1].verdict.level !== 'suspicious' || scan.risk !== 1 || scan.unknown !== listMax) {
    fail('放不下的 unknown 没有保住风险，或改了等级计数')
  }
  let onlyOk = new Scan()
  for (let i = 0; i < listMax + 1; i++) {
    onlyOk.hits.push(hit('ok'))
  }
  onlyOk.ok = listMax + 1
  onlyOk.judged = listMax + 1
  onlyOk.complete = true
  limitScanReport(onlyOk, false)
  if (!onlyOk.complete || onlyOk.note.length !== 0 || onlyOk.hits.length !== listMax ||
    onlyOk.ok !== listMax + 1) {
    fail('只丢掉 ok 时 complete 被写成了 false，或按留下的数组改了 ok 计数')
  }
  let ordered = new Scan()
  ordered.hits.push(hit('ok'))
  ordered.ok = 1
  ordered.judged = 1
  ordered.complete = true
  ordered.note = '结果较多，仅显示部分,已达本次扫描上限'
  limitScanReport(ordered, false)
  if (ordered.note !== '已达本次扫描上限、结果较多，仅显示部分' || !ordered.complete) {
    fail('两句 note 没有按顿号把上限放在前面')
  }
  let later = new Scan()
  later.hits.push(hit('risk'))
  later.risk = 0
  later.judged = 2
  later.complete = true
  limitScanReport(later, false)
  if (!later.complete || later.risk !== 0 || later.judged !== 2 || later.hits.length !== 1) {
    fail('处置之后又用 judged 等式改了 complete，或按留下的数组改了等级计数')
  }

  let exam = new ExamBody()
  exam.appsComplete = true
  exam.summary.unknownApps = listMax + 1
  exam.summary.okApps = 4
  let keptStatus = new CheckLine()
  keptStatus.status = 'risk'
  exam.items.push(keptStatus)
  for (let i = 0; i < listMax + 1; i++) {
    exam.apps.push(hit('unknown'))
  }
  let examRecord = record('exam-cut', 1, 'exam', 'done')
  limitExamApps(exam, examRecord)
  if (exam.appsComplete || examRecord.summary !== '结果较多，仅显示部分' ||
    exam.summary.unknownApps !== listMax + 1 || exam.summary.okApps !== 4 ||
    exam.items[0].status !== 'risk') {
    fail('体检截断丢掉 unknown 时没有写 appsComplete 和 summary，或按留下的数组改了计数和状态')
  }
  let examOk = new ExamBody()
  examOk.appsComplete = true
  for (let i = 0; i < listMax + 1; i++) {
    examOk.apps.push(hit('ok'))
  }
  let examOkRecord = record('exam-ok', 2, 'exam', 'done')
  examOkRecord.summary = 'keep'
  limitExamApps(examOk, examOkRecord)
  if (!examOk.appsComplete || examOkRecord.summary !== 'keep') {
    fail('体检只丢掉 ok 时 appsComplete 被改成 false')
  }

  let filesHits: FileHit[] = []
  for (let i = 0; i < listMax + 1; i++) {
    let row = new FileRow()
    row.uri = 'u' + i.toString()
    filesHits.push(row)
  }
  if (fileToolLimited(filesHits, true, '') || fileToolNote(filesHits, '').indexOf('结果较多，仅显示部分') < 0 ||
    fileToolNote(filesHits, '结果较多，仅显示部分,已达本次扫描上限') !== '已达本次扫描上限、结果较多，仅显示部分') {
    fail('文件工具超出 listMax 时没有把 complete 写成 false，或 note 没用顿号按顺序连接')
  }
  let keptFiles = limitFileHits(filesHits, true, '')
  if (keptFiles.length !== listMax || keptFiles[0].selected) {
    fail('写回文件时 selected 没有变成 false')
  }

  let facts: PermissionFact[] = []
  for (let i = 0; i < listMax; i++) {
    let fact = new Fact()
    fact.permission = 'p' + i.toString()
    facts.push(fact)
  }
  let granted = new Fact()
  granted.permission = 'ohos.permission.CAMERA'
  granted.sensitive = true
  granted.grant = 'granted'
  facts.push(granted)
  let limited = limitFacts(facts)
  if (limited.length !== listMax || limited[0].permission !== 'ohos.permission.CAMERA') {
    fail('权限截断没有先留下已授予的敏感权限')
  }

  files.write('center/jobs/bad.json', '{')
  if (ResultStore.read('bad') !== null || files.read('center/jobs/bad.json') !== '{') {
    fail('结果文件解析失败时被删掉了')
  }
  files.write('center/jobs/good.json', '{"state":"clear"}')
  if (ResultStore.read('good') !== '{"state":"clear"}') {
    fail('合法结果文件没有读出来')
  }

  let created = record('first', 4, 'exam', 'running')
  created.resultFile = ''
  created.summary = ''
  files.write(INDEX, JSON.stringify([created]))
  let body = new ExamBody()
  body.jobId = 'first'
  body.state = 'incomplete'
  body.appsComplete = true
  body.summary.okApps = 9
  body.summary.unknownApps = listMax + 1
  let item = new CheckLine()
  item.status = 'risk'
  body.items.push(item)
  for (let i = 0; i < listMax + 1; i++) {
    body.apps.push(hit('unknown'))
  }
  ResultStore.saveExam(created, body)
  let examText = files.read('center/jobs/first.json')
  if (created.resultFile !== 'center/jobs/first.json' || examText === null) {
    fail('第一条体检结果没有经 Writer 写到 center/jobs/<jobId>.json')
  }
  let examSaved = JSON.parse(examText as string) as ExamBody
  if (examSaved.state !== 'incomplete' || examSaved.appsComplete || examSaved.summary.okApps !== 9 ||
    examSaved.summary.unknownApps !== listMax + 1 || examSaved.items[0].status !== 'risk' ||
    examSaved.apps.length !== listMax || examText.indexOf('"judged"') >= 0) {
    fail('体检结果被写成了信誉 JSON，或截断后重算了计数和状态')
  }
  let createdIndex = JSON.parse(files.read(INDEX) as string) as Stored[]
  if (createdIndex[0].resultFile !== 'center/jobs/first.json' ||
    createdIndex[0].summary !== '结果较多，仅显示部分') {
    fail('JobRecord.resultFile 没有指向结果文件')
  }

  let wrong = record('nope', 1, 'malware', 'running')
  wrong.resultFile = ''
  ResultStore.saveExam(wrong, new ExamBody())
  if (wrong.resultFile.length !== 0 || files.read('center/jobs/nope.json') !== null) {
    fail('种类不符时仍写入了结果文件')
  }

  let mal = record('rep', 7, 'malware', 'running')
  mal.resultFile = ''
  let scanBody = new Scan()
  scanBody.complete = true
  scanBody.judged = 3
  scanBody.risk = 0
  scanBody.hits.push(hit('risk'))
  ResultStore.saveScan(mal, scanBody, false)
  let scanText = files.read('center/jobs/rep.json')
  if (mal.resultFile !== 'center/jobs/rep.json' || scanText === null || !scanBody.complete ||
    scanBody.risk !== 0 || scanBody.judged !== 3 || scanText.indexOf('"hits"') < 0 ||
    scanText.indexOf('"apps"') >= 0) {
    fail('信誉结果路径或 JSON 种类不对，或处置之后改了 complete 和计数')
  }

  let cleanJob = record('clean-1', 8, 'clean', 'running')
  cleanJob.resultFile = ''
  let clean = new CleanBody()
  clean.note = '请先选择目录,已达本次扫描上限'
  let cache = new CacheLine()
  cache.selected = true
  clean.caches.push(cache)
  let cleanHit = new FileRow()
  cleanHit.selected = true
  clean.hits.push(cleanHit)
  ResultStore.saveClean(cleanJob, clean)
  let cleanText = files.read('center/jobs/clean-1.json')
  if (cleanText === null || clean.note !== '已达本次扫描上限、请先选择目录' || !clean.complete ||
    cleanText.indexOf('"selected":true') >= 0 || cleanText.indexOf('"caches"') < 0) {
    fail('清理结果的 note 顺序不对，或把勾选写进了文件')
  }

  let dup = record('dup-1', 9, 'duplicate', 'running')
  dup.resultFile = ''
  let dupBody = new FileBody()
  dupBody.note = '已达本次扫描上限'
  let dupHit = new FileRow()
  dupHit.selected = true
  dupBody.hits.push(dupHit)
  ResultStore.saveFileTool(dup, dupBody)
  let dupText = files.read('center/jobs/dup-1.json')
  if (dupText === null || dupText.indexOf('"caches"') >= 0 || dupText.indexOf('"selected":true') >= 0 ||
    dupBody.note !== '已达本次扫描上限') {
    fail('重复文件没有写成 FileToolReport，或勾选被写进文件')
  }
  let large = record('large-1', 10, 'large-file', 'running')
  large.resultFile = ''
  ResultStore.saveFileTool(large, new FileBody())
  if (files.read('center/jobs/large-1.json') === null || large.resultFile !== 'center/jobs/large-1.json') {
    fail('大文件结果没有写到 center/jobs/<jobId>.json')
  }

  let perm = record('perm-1', 11, 'permission', 'done')
  perm.resultFile = ''
  let other = new Fact()
  other.permission = 'ohos.permission.INTERNET'
  let camera = new Fact()
  camera.permission = 'ohos.permission.CAMERA'
  camera.sensitive = true
  camera.grant = 'granted'
  let use = new UseLine()
  use.permission = 'ohos.permission.CAMERA'
  ResultStore.savePermission(perm, [other, camera], [use])
  let permText = files.read('center/jobs/perm-1.json')
  let permSaved = JSON.parse(permText as string) as PermissionFilePeek
  if (permText === null || permSaved.facts[0].permission !== 'ohos.permission.CAMERA' ||
    permSaved.uses[0].permission !== 'ohos.permission.CAMERA') {
    fail('权限结果不是 { facts, uses }，或没有先留下已授予的敏感权限')
  }

  let appJob = record('app-1', 12, 'apps', 'done')
  appJob.resultFile = ''
  let bundle = new BundleLine()
  bundle.bundleName = 'com.example.app'
  ResultStore.saveApps(appJob, [bundle])
  let appText = files.read('center/jobs/app-1.json')
  if (appText === null || appText.charAt(0) !== '[' || appText.indexOf('com.example.app') < 0) {
    fail('软件结果不是 BundleRow[]')
  }

  let protectJob = record('protect-1', 13, 'protect', 'done')
  protectJob.resultFile = ''
  let posture = new ProtectLine()
  posture.id = 'exam.protect.pure-mode'
  ResultStore.saveProtect(protectJob, [posture])
  let protectText = files.read('center/jobs/protect-1.json')
  if (protectText === null || protectText.charAt(0) !== '[' ||
    protectText.indexOf('exam.protect.pure-mode') < 0) {
    fail('防护结果不是 ProtectFact[]')
  }
}

class PermissionFilePeek {
  facts: Fact[] = []
  uses: UseLine[] = []
}
