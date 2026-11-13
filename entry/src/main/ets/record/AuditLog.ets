import type { AuditLine } from '../center/CenterTypes';
import { nowIso } from '../center/Clock';
import { Writer } from './Writer';

const AUDIT_PATH: string = 'center/audit.log'
const SUCCESS: string = '成功'

class AuditRow implements AuditLine {
  at: string = ''
  kind: string = ''
  action: string = ''
  jobId: string = ''
  target: string = ''
  result: string = ''
}

export class AuditLog {
  static append(line: AuditLine, succeeded: boolean): void {
    let row = new AuditRow()
    row.at = line.at.length > 0 ? line.at : nowIso()
    row.kind = line.kind
    row.action = line.action
    row.jobId = line.jobId
    row.target = line.target
    row.result = line.result
    if (!succeeded && row.result === SUCCESS) {
      row.result = ''
    }
    let prior = Writer.readText(AUDIT_PATH)
    let body = prior === null ? '' : prior
    if (body.length > 0 && body.charAt(body.length - 1) !== '\n') {
      body += '\n'
    }
    body += JSON.stringify(row) + '\n'
    Writer.replaceText(AUDIT_PATH, body)
  }

  static read(): AuditLine[] {
    let text = Writer.readText(AUDIT_PATH)
    if (text === null || text.length === 0) {
      return []
    }
    let lines = text.split('\n')
    let rows: AuditLine[] = []
    for (let i = 0; i < lines.length; i++) {
      let line = lines[i]
      if (line.length > 0 && line.charAt(line.length - 1) === '\r') {
        line = line.substring(0, line.length - 1)
      }
      if (line.length === 0) {
        continue
      }
      let row = AuditLog.parseLine(line)
      if (row !== null) {
        rows.push(row)
      }
    }
    return rows
  }

  private static parseLine(line: string): AuditRow | null {
    try {
      let peek = JSON.parse(line) as AuditRow
      if (peek === null || typeof peek !== 'object') {
        return null
      }
      let row = new AuditRow()
      row.at = typeof peek.at === 'string' ? peek.at : ''
      row.kind = typeof peek.kind === 'string' ? peek.kind : ''
      row.action = typeof peek.action === 'string' ? peek.action : ''
      row.jobId = typeof peek.jobId === 'string' ? peek.jobId : ''
      row.target = typeof peek.target === 'string' ? peek.target : ''
      row.result = typeof peek.result === 'string' ? peek.result : ''
      return row
    } catch (err) {
      return null
    }
  }
}
