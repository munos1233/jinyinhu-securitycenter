import { hilog } from '@kit.PerformanceAnalysisKit';
import type {
  BundleRow,
  CleanReport,
  ExamReport,
  FileToolReport,
  JobRecord,
  PermissionFact,
  ProtectFact,
  ScanReport,
  UseFact
} from '../center/CenterTypes'
import { limitExamApps, limitFacts, limitRows, limitScanReport, normalizeClean, normalizeFileTool, Writer } from './Writer'

const DOMAIN: number = 0x4A59
const TAG: string = 'Center'
const KIND: string = 'result kind does not match job'

class PermissionFile {
  facts: PermissionFact[] = []
  uses: UseFact[] = []
}

export class ResultStore {
  static read(jobId: string): string | null {
    let text = Writer.readText(Writer.resultFileOf(jobId))
    if (text === null) {
      return null
    }
    try {
      JSON.parse(text)
      return text
    } catch (err) {
      return null
    }
  }

  static saveExam(record: JobRecord, report: ExamReport): void {
    if (record.kind !== 'exam') {
      hilog.error(DOMAIN, TAG, KIND)
      return
    }
    limitExamApps(report, record)
    Writer.commit(record, JSON.stringify(report))
  }

  static saveScan(record: JobRecord, report: ScanReport, beforeDisposition: boolean): void {
    if (record.kind !== 'malware') {
      hilog.error(DOMAIN, TAG, KIND)
      return
    }
    limitScanReport(report, beforeDisposition)
    Writer.commit(record, JSON.stringify(report))
  }

  static saveClean(record: JobRecord, report: CleanReport): void {
    if (record.kind !== 'clean') {
      hilog.error(DOMAIN, TAG, KIND)
      return
    }
    normalizeClean(report)
    Writer.commit(record, JSON.stringify(report))
  }

  static saveFileTool(record: JobRecord, report: FileToolReport): void {
    if (record.kind !== 'duplicate' && record.kind !== 'large-file') {
      hilog.error(DOMAIN, TAG, KIND)
      return
    }
    normalizeFileTool(report)
    Writer.commit(record, JSON.stringify(report))
  }

  static savePermission(record: JobRecord, facts: PermissionFact[], uses: UseFact[]): void {
    if (record.kind !== 'permission') {
      hilog.error(DOMAIN, TAG, KIND)
      return
    }
    let body = new PermissionFile()
    body.facts = limitFacts(facts)
    body.uses = limitRows(uses)
    Writer.commit(record, JSON.stringify(body))
  }

  static saveApps(record: JobRecord, rows: BundleRow[]): void {
    if (record.kind !== 'apps') {
      hilog.error(DOMAIN, TAG, KIND)
      return
    }
    Writer.commit(record, JSON.stringify(limitRows(rows)))
  }

  static saveProtect(record: JobRecord, facts: ProtectFact[]): void {
    if (record.kind !== 'protect') {
      hilog.error(DOMAIN, TAG, KIND)
      return
    }
    Writer.commit(record, JSON.stringify(limitRows(facts)))
  }
}
