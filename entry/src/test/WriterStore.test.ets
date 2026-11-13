import { jobMax, listMax } from '../main/ets/center/CenterLimits'
import type {
  ExamReport,
  FileHit,
  JobKind,
  JobRecord,
  JobState,
  PermissionFact,
  ScanHit,
  ScanReport,
  Verdict
} from '../main/ets/center/CenterTypes'
import { CenterStore } from '../main/ets/record/CenterStore'
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
  items = []
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

function fail(message: string): void {
  throw new Error(message)
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
  if (after.length !== 2 || after[0].state !== 'interrupted' || after[0].summary !== '扫描已中断' ||
    after[0].seq !== 3 || after[0].finishedAt.length === 0) {
    fail('recover 没有按原 seq 把 queued 收成扫描已中断')
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
  if (!onlyOk.complete || onlyOk.note.length !== 0 || onlyOk.hits.length !== listMax) {
    fail('只丢掉 ok 时 complete 被写成了 false')
  }

  let exam = new ExamBody()
  exam.appsComplete = true
  for (let i = 0; i < listMax + 1; i++) {
    exam.apps.push(hit('unknown'))
  }
  let examRecord = record('exam-cut', 1, 'exam', 'done')
  limitExamApps(exam, examRecord)
  if (exam.appsComplete || examRecord.summary !== '结果较多，仅显示部分') {
    fail('体检截断丢掉 unknown 时没有写 appsComplete 和 summary')
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
  if (fileToolLimited(filesHits, true, '') || fileToolNote(filesHits, '').indexOf('结果较多，仅显示部分') < 0) {
    fail('文件工具超出 listMax 时没有把 complete 写成 false')
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
}
