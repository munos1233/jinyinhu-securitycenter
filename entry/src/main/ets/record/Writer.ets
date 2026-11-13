import fs from '@ohos.file.fs';
import { hilog } from '@kit.PerformanceAnalysisKit';
import { nowIso } from '../center/Clock';
import { jobMax, listMax } from '../center/CenterLimits';
import type {
  CacheRow,
  ExamReport,
  ExamState,
  ExamSummary,
  FileHit,
  JobRecord,
  JobState,
  PermissionFact,
  ScanHit,
  ScanReport
} from '../center/CenterTypes'
import { settledHome } from '../feature/exam/ExamState'
import type { HomeCandidate } from '../feature/exam/ExamState'

const DOMAIN: number = 0x4A59
const TAG: string = 'Center'
const INDEX_PATH: string = 'center/jobs/index.json'
const MANY: string = '结果较多，仅显示部分'
const INTERRUPTED: string = '扫描已中断'

export interface CenterFiles {
  read(path: string): string | null
  write(path: string, text: string): void
  rename(from: string, to: string): void
  remove(path: string): void
}

class IndexRow implements JobRecord {
  jobId: string = ''
  seq: number = 0
  seqPresent: boolean = false
  kind: JobRecord['kind'] = 'exam'
  lane: JobRecord['lane'] = 'heavy'
  startedAt: string = ''
  finishedAt: string = ''
  state: JobState = 'done'
  itemCount: number = 0
  riskCount: number = 0
  summary: string = ''
  resultFile: string = ''
}

class ExamStub implements ExamReport {
  jobId: string = ''
  state: ExamState = 'not-run'
  items: ExamReport['items'] = []
  apps: ScanHit[] = []
  appsComplete: boolean = false
  summary: ExamSummary = {
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

class Candidate implements HomeCandidate {
  record: JobRecord = new IndexRow()
  report: ExamReport | null = null
}

class SplitHits {
  risk: ScanHit[] = []
  suspicious: ScanHit[] = []
  unknown: ScanHit[] = []
  ok: ScanHit[] = []
  droppedUnknown: boolean = false
}

export class Writer {
  private static files: CenterFiles | null = null
  private static wait: Array<() => void> = []
  private static busy: boolean = false

  static bind(files: CenterFiles): void {
    Writer.files = files
  }

  static exclusive<T>(work: () => T): T {
    if (Writer.busy) {
      let boxed: T | null = null
      Writer.wait.push(() => {
        boxed = work()
      })
      return boxed as T
    }
    Writer.busy = true
    let value = work()
    Writer.busy = false
    while (Writer.wait.length > 0) {
      let next = Writer.wait.shift()
      if (next !== undefined) {
        Writer.busy = true
        next()
        Writer.busy = false
      }
    }
    return value
  }

  static replaceText(path: string, text: string): void {
    Writer.exclusive(() => {
      Writer.replaceNow(path, text)
    })
  }

  static readText(path: string): string | null {
    return Writer.exclusive(() => {
      if (Writer.files === null) {
        return null
      }
      return Writer.files.read(path)
    })
  }

  static nextSeq(records: JobRecord[]): number {
    let max = 0
    let seen = false
    for (let i = 0; i < records.length; i++) {
      let row = records[i] as IndexRow
      let present = row.seqPresent === true || (row.seqPresent !== false && row.seq !== 0)
      if (row.seqPresent === false) {
        present = false
      }
      if (!present) {
        continue
      }
      seen = true
      if (row.seq > max) {
        max = row.seq
      }
    }
    if (!seen) {
      return 1
    }
    return max + 1
  }

  static recover(): void {
    Writer.exclusive(() => {
      Writer.recoverNow()
    })
  }

  static loadIndex(): JobRecord[] {
    return Writer.exclusive(() => {
      return Writer.readIndex()
    })
  }

  static saveIndex(records: JobRecord[]): void {
    Writer.exclusive(() => {
      let trimmed = Writer.trim(records as IndexRow[])
      Writer.replaceNow(INDEX_PATH, JSON.stringify(Writer.plainIndex(trimmed)))
    })
  }

  private static replaceNow(path: string, text: string): void {
    if (Writer.files === null) {
      return
    }
    let temp = path + '.tmp'
    Writer.files.write(temp, text)
    if (Writer.files.read(path) !== null) {
      Writer.files.remove(path)
    }
    Writer.files.rename(temp, path)
  }

  private static recoverNow(): void {
    if (Writer.files === null) {
      return
    }
    let text = Writer.files.read(INDEX_PATH)
    if (text === null || text.length === 0) {
      return
    }
    let records = Writer.parseIndex(text)
    if (records === null) {
      let bad = INDEX_PATH + '.bad-' + nowIso()
      Writer.files.rename(INDEX_PATH, bad)
      Writer.replaceNow(INDEX_PATH, '[]')
      hilog.error(DOMAIN, TAG, 'index.json parse failed')
      return
    }
    for (let i = 0; i < records.length; i++) {
      let row = records[i]
      if (row.state === 'queued' || row.state === 'running') {
        row.state = 'interrupted'
        row.finishedAt = nowIso()
        row.summary = INTERRUPTED
      }
    }
    let trimmed = Writer.trim(records)
    Writer.replaceNow(INDEX_PATH, JSON.stringify(Writer.plainIndex(trimmed)))
  }

  private static readIndex(): IndexRow[] {
    if (Writer.files === null) {
      return []
    }
    let text = Writer.files.read(INDEX_PATH)
    if (text === null || text.length === 0) {
      return []
    }
    let parsed = Writer.parseIndex(text)
    if (parsed === null) {
      return []
    }
    return parsed
  }

  private static parseIndex(text: string): IndexRow[] | null {
    try {
      let parsed = JSON.parse(text) as Object[]
      if (!(parsed instanceof Array)) {
        return null
      }
      let rows: IndexRow[] = []
      for (let i = 0; i < parsed.length; i++) {
        rows.push(Writer.rowFrom(parsed[i]))
      }
      return rows
    } catch (err) {
      return null
    }
  }

  private static rowFrom(raw: Object): IndexRow {
    let peek = raw as IndexRow
    let row = new IndexRow()
    row.jobId = typeof peek.jobId === 'string' ? peek.jobId : ''
    row.seqPresent = typeof peek.seq === 'number'
    row.seq = row.seqPresent ? peek.seq : 0
    row.kind = peek.kind
    row.lane = peek.lane
    row.startedAt = typeof peek.startedAt === 'string' ? peek.startedAt : ''
    row.finishedAt = typeof peek.finishedAt === 'string' ? peek.finishedAt : ''
    row.state = peek.state
    row.itemCount = typeof peek.itemCount === 'number' ? peek.itemCount : 0
    row.riskCount = typeof peek.riskCount === 'number' ? peek.riskCount : 0
    row.summary = typeof peek.summary === 'string' ? peek.summary : ''
    row.resultFile = typeof peek.resultFile === 'string' ? peek.resultFile : ''
    return row
  }

  private static plainIndex(records: IndexRow[]): JobRecord[] {
    let plain: JobRecord[] = []
    for (let i = 0; i < records.length; i++) {
      let row = records[i]
      let copy = new IndexRow()
      copy.jobId = row.jobId
      copy.seq = row.seq
      copy.seqPresent = true
      copy.kind = row.kind
      copy.lane = row.lane
      copy.startedAt = row.startedAt
      copy.finishedAt = row.finishedAt
      copy.state = row.state
      copy.itemCount = row.itemCount
      copy.riskCount = row.riskCount
      copy.summary = row.summary
      copy.resultFile = row.resultFile
      plain.push(copy)
    }
    return plain
  }

  private static trim(records: IndexRow[]): IndexRow[] {
    if (records.length <= jobMax) {
      return records
    }
    let home = settledHome(Writer.examRows(records))
    let doneId = Writer.latestDoneId(records)
    let order: number[] = []
    for (let i = 0; i < records.length; i++) {
      if (!Writer.canDrop(records[i], home, doneId)) {
        continue
      }
      order.push(i)
    }
    order.sort((left, right) => {
      let delta = records[left].seq - records[right].seq
      if (delta !== 0) {
        return delta
      }
      return left - right
    })
    let doomed: boolean[] = []
    for (let i = 0; i < records.length; i++) {
      doomed.push(false)
    }
    let extra = records.length - jobMax
    let marked = 0
    for (let i = 0; i < order.length && marked < extra; i++) {
      doomed[order[i]] = true
      marked++
    }
    let kept: IndexRow[] = []
    for (let i = 0; i < records.length; i++) {
      if (!doomed[i]) {
        kept.push(records[i])
        continue
      }
      Writer.removeResult(records[i])
    }
    return kept
  }

  private static canDrop(row: IndexRow, home: string, doneId: string): boolean {
    if (row.state === 'queued' || row.state === 'running') {
      return false
    }
    if (row.kind === 'exam' && (row.jobId === home || row.jobId === doneId)) {
      return false
    }
    return row.state === 'done' || row.state === 'failed' || row.state === 'cancelled' ||
      row.state === 'interrupted'
  }

  private static latestDoneId(records: IndexRow[]): string {
    let id = ''
    let seq = -1
    let at = -1
    for (let i = 0; i < records.length; i++) {
      let row = records[i]
      if (row.kind !== 'exam' || row.state !== 'done') {
        continue
      }
      if (row.seq > seq || (row.seq === seq && i > at)) {
        seq = row.seq
        at = i
        id = row.jobId
      }
    }
    return id
  }

  private static examRows(records: IndexRow[]): HomeCandidate[] {
    let rows: HomeCandidate[] = []
    for (let i = 0; i < records.length; i++) {
      if (records[i].kind !== 'exam') {
        continue
      }
      let row = new Candidate()
      row.record = records[i]
      row.report = Writer.readExam(records[i])
      rows.push(row)
    }
    return rows
  }

  private static readExam(record: IndexRow): ExamReport | null {
    if (Writer.files === null) {
      return null
    }
    let text = Writer.files.read(Writer.resultPath(record))
    if (text === null) {
      return null
    }
    try {
      let parsed = JSON.parse(text) as ExamStub
      if (parsed.state !== 'not-run' && parsed.state !== 'risk' && parsed.state !== 'incomplete' &&
        parsed.state !== 'clear') {
        return null
      }
      let report = new ExamStub()
      report.jobId = record.jobId
      report.state = parsed.state
      return report
    } catch (err) {
      return null
    }
  }

  private static resultPath(record: JobRecord): string {
    if (record.resultFile.length > 0) {
      return record.resultFile
    }
    return 'center/jobs/' + record.jobId + '.json'
  }

  private static removeResult(record: JobRecord): void {
    if (Writer.files === null || record.jobId.length === 0) {
      return
    }
    let path = Writer.resultPath(record)
    if (Writer.files.read(path) !== null) {
      Writer.files.remove(path)
    }
  }
}

export function limitScanReport(report: ScanReport, finishing: boolean): void {
  let split = splitHits(report.hits)
  report.hits = joinHits(split)
  if (split.droppedUnknown) {
    report.complete = false
    report.note = appendNote(report.note)
  }
  let sum = report.risk + report.suspicious + report.unknown + report.ok
  if (finishing && report.judged !== sum) {
    report.complete = false
    hilog.error(DOMAIN, TAG, 'judged does not equal level counts')
  }
}

export function limitExamApps(report: ExamReport, record: JobRecord): void {
  let split = splitHits(report.apps)
  report.apps = joinHits(split)
  if (split.droppedUnknown) {
    report.appsComplete = false
    record.summary = MANY
  }
}

export function limitFileHits(hits: FileHit[], complete: boolean, note: string): FileHit[] {
  for (let i = 0; i < hits.length; i++) {
    hits[i].selected = false
  }
  if (hits.length <= listMax) {
    return hits
  }
  let kept: FileHit[] = []
  for (let i = 0; i < listMax; i++) {
    kept.push(hits[i])
  }
  return kept
}

export function fileToolLimited(hits: FileHit[], complete: boolean, note: string): boolean {
  return hits.length > listMax ? false : complete
}

export function fileToolNote(hits: FileHit[], note: string): string {
  if (hits.length <= listMax) {
    return note
  }
  return appendNote(note)
}

export function clearCacheSelection(rows: CacheRow[]): void {
  for (let i = 0; i < rows.length; i++) {
    rows[i].selected = false
  }
}

export function limitFacts(facts: PermissionFact[]): PermissionFact[] {
  let first: PermissionFact[] = []
  let rest: PermissionFact[] = []
  for (let i = 0; i < facts.length; i++) {
    if (facts[i].grant === 'granted' && facts[i].sensitive) {
      first.push(facts[i])
    } else {
      rest.push(facts[i])
    }
  }
  let all: PermissionFact[] = []
  for (let i = 0; i < first.length; i++) {
    all.push(first[i])
  }
  for (let i = 0; i < rest.length; i++) {
    all.push(rest[i])
  }
  if (all.length <= listMax) {
    return all
  }
  let cut: PermissionFact[] = []
  for (let i = 0; i < listMax; i++) {
    cut.push(all[i])
  }
  return cut
}

function splitHits(hits: ScanHit[]): SplitHits {
  let split = new SplitHits()
  for (let i = 0; i < hits.length; i++) {
    let level = hits[i].verdict.level
    if (level === 'risk') {
      split.risk.push(hits[i])
    } else if (level === 'suspicious') {
      split.suspicious.push(hits[i])
    } else if (level === 'unknown') {
      split.unknown.push(hits[i])
    } else {
      split.ok.push(hits[i])
    }
  }
  return split
}

function joinHits(split: SplitHits): ScanHit[] {
  let kept: ScanHit[] = []
  for (let i = 0; i < split.risk.length; i++) {
    kept.push(split.risk[i])
  }
  for (let i = 0; i < split.suspicious.length; i++) {
    kept.push(split.suspicious[i])
  }
  let room = listMax - kept.length
  if (room < 0) {
    room = 0
  }
  let unknownKeep = split.unknown.length
  if (unknownKeep > room) {
    unknownKeep = room
    split.droppedUnknown = true
  }
  for (let i = 0; i < unknownKeep; i++) {
    kept.push(split.unknown[i])
  }
  room = listMax - kept.length
  if (room < 0) {
    room = 0
  }
  let okKeep = split.ok.length
  if (okKeep > room) {
    okKeep = room
  }
  for (let i = 0; i < okKeep; i++) {
    kept.push(split.ok[i])
  }
  return kept
}

function appendNote(note: string): string {
  if (note.indexOf(MANY) >= 0) {
    return note
  }
  if (note.length === 0) {
    return MANY
  }
  return note + '、' + MANY
}

export class SandboxFiles implements CenterFiles {
  root: string

  constructor(root: string) {
    this.root = root
  }

  read(path: string): string | null {
    try {
      let opened = fs.openSync(this.full(path), fs.OpenMode.READ_ONLY)
      let stat = fs.statSync(opened.fd)
      let buffer = new ArrayBuffer(stat.size)
      fs.readSync(opened.fd, buffer)
      fs.closeSync(opened)
      return decodeUtf8(new Uint8Array(buffer))
    } catch (err) {
      return null
    }
  }

  write(path: string, text: string): void {
    this.ensureParent(path)
    let bytes = encodeUtf8(text)
    let opened = fs.openSync(this.full(path),
      fs.OpenMode.CREATE | fs.OpenMode.READ_WRITE | fs.OpenMode.TRUNC)
    fs.writeSync(opened.fd, bytes.buffer)
    fs.closeSync(opened)
  }

  rename(from: string, to: string): void {
    this.ensureParent(to)
    fs.renameSync(this.full(from), this.full(to))
  }

  remove(path: string): void {
    fs.unlinkSync(this.full(path))
  }

  private full(path: string): string {
    return this.root + '/' + path
  }

  private ensureParent(path: string): void {
    let parts = path.split('/')
    let acc = ''
    for (let i = 0; i < parts.length - 1; i++) {
      if (parts[i].length === 0) {
        continue
      }
      acc = acc.length === 0 ? parts[i] : acc + '/' + parts[i]
      try {
        fs.mkdirSync(this.root + '/' + acc)
      } catch (err) {
      }
    }
  }
}

function encodeUtf8(text: string): Uint8Array {
  let codes: number[] = []
  for (let i = 0; i < text.length; i++) {
    let code = text.charCodeAt(i)
    if (code < 0x80) {
      codes.push(code)
    } else if (code < 0x800) {
      codes.push(0xC0 | (code >> 6))
      codes.push(0x80 | (code & 0x3F))
    } else {
      codes.push(0xE0 | (code >> 12))
      codes.push(0x80 | ((code >> 6) & 0x3F))
      codes.push(0x80 | (code & 0x3F))
    }
  }
  let out = new Uint8Array(codes.length)
  for (let i = 0; i < codes.length; i++) {
    out[i] = codes[i]
  }
  return out
}

function decodeUtf8(bytes: Uint8Array): string {
  let text = ''
  let i = 0
  while (i < bytes.length) {
    let lead = bytes[i]
    if (lead < 0x80) {
      text += String.fromCharCode(lead)
      i++
    } else if (lead < 0xE0) {
      text += String.fromCharCode(((lead & 0x1F) << 6) | (bytes[i + 1] & 0x3F))
      i += 2
    } else {
      text += String.fromCharCode(((lead & 0x0F) << 12) | ((bytes[i + 1] & 0x3F) << 6) | (bytes[i + 2] & 0x3F))
      i += 3
    }
  }
  return text
}
