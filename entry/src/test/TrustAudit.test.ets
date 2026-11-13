import type { AuditLine, CertAlgo } from '../main/ets/center/CenterTypes'
import { AuditLog } from '../main/ets/record/AuditLog'
import { TrustList } from '../main/ets/record/TrustList'
import type { CenterFiles } from '../main/ets/record/Writer'
import { Writer } from '../main/ets/record/Writer'

const HEX64: string = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
const TRUST: string = 'center/trust.json'
const AUDIT: string = 'center/audit.log'
const ACTIONS: string[] = ['作业完成', '隔离', '恢复', '卸载', '清缓存', '撤权', '信任']

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

class TrustPeek {
  kind: string = ''
  fingerprint: string = ''
  id: string = ''
  versionCode: number = 0
  at: string = ''
}

class Line implements AuditLine {
  at: string = '2026-11-13T00:00:00+08:00'
  kind: string = 'exam'
  action: string = ''
  jobId: string = 'job-1'
  target: string = 'com.example.app'
  result: string = '成功'
}

function fail(message: string): void {
  throw new Error(message)
}

function upperHex(value: string): string {
  let out = ''
  for (let i = 0; i < value.length; i++) {
    let code = value.charCodeAt(i)
    if (code >= 97 && code <= 102) {
      out += String.fromCharCode(code - 32)
    } else {
      out += value.charAt(i)
    }
  }
  return out
}

function trustRows(files: MemoryFiles): TrustPeek[] {
  let text = files.read(TRUST)
  if (text === null) {
    fail('信任区没有写入')
    return []
  }
  return JSON.parse(text) as TrustPeek[]
}

export function runTrustAuditChecks(): void {
  let files = new MemoryFiles()
  Writer.bind(files)
  let algo: CertAlgo = 'sha256-of-cert-bytes'
  if (TrustList.trustBundle('SHA-256:' + upperHex(HEX64), 'none', 'com.example.app', 3) ||
    files.read(TRUST) !== null) {
    fail('certAlgo=none 的包被写进了信任区')
  }
  if (TrustList.trustBundle('   ', algo, 'com.example.app', 3) || files.read(TRUST) !== null) {
    fail('空证书参与了信任比较或被写进信任区')
  }
  if (!TrustList.trustBundle('SHA-256:' + upperHex(HEX64), algo, 'com.example.app', 3)) {
    fail('合法包信任没有写入')
  }
  let stored = trustRows(files)
  if (stored.length !== 1 || stored[0].fingerprint !== HEX64 || stored[0].id !== 'com.example.app' ||
    stored[0].versionCode !== 3 || stored[0].kind !== 'bundle' || stored[0].at.length === 0) {
    fail('包信任没有在写入前规范化证书，或没有记下 bundleName 和 versionCode')
  }
  if (!TrustList.matchesBundle('SHA256:' + HEX64, 'com.example.app', 3) ||
    TrustList.matchesBundle('SHA256:' + HEX64, 'com.example.app', 4) ||
    TrustList.matchesBundle('SHA256:' + HEX64, 'com.other.app', 3) ||
    TrustList.matchesBundle('', 'com.example.app', 3)) {
    fail('包信任没有同时比较 kind、证书、包名和 versionCode')
  }
  if (!TrustList.trustBundle('SHA256:' + HEX64, algo, 'com.example.app', 3) ||
    trustRows(files).length !== 1) {
    fail('同一条包信任写了第二条')
  }
  TrustList.trustBundle('SHA256:' + HEX64, algo, 'com.example.app', 9)
  if (trustRows(files).length !== 2 || !TrustList.matchesBundle(HEX64, 'com.example.app', 3) ||
    !TrustList.matchesBundle(HEX64, 'com.example.app', 9)) {
    fail('同一证书的另一个 versionCode 没有单独覆盖')
  }
  if (!TrustList.trustBundle('AA BB', algo, 'com.spaced', 1)) {
    fail('带空格的证书没有写入')
  }
  let spaced = false
  let afterSpace = trustRows(files)
  for (let i = 0; i < afterSpace.length; i++) {
    if (afterSpace[i].id === 'com.spaced' && afterSpace[i].fingerprint === 'aabb') {
      spaced = true
    }
  }
  if (!spaced || !TrustList.matchesBundle('aa:bb', 'com.spaced', 1)) {
    fail('包信任写入前没有去掉证书里的空格和冒号')
  }

  if (!TrustList.trustFile('abc123', 'file://one') || !TrustList.matchesFile('abc123') ||
    TrustList.matchesBundle('abc123', 'file://one', 0)) {
    fail('文件信任没有只按 kind 和 fingerprint 命中')
  }
  if (!TrustList.trustFile('abc123', 'file://two')) {
    fail('同一哈希再信任被拒绝了')
  }
  let filesOnly = 0
  let rows = trustRows(files)
  for (let i = 0; i < rows.length; i++) {
    if (rows[i].kind === 'file-sha256' && rows[i].fingerprint === 'abc123') {
      filesOnly++
      if (rows[i].id !== 'file://one' || rows[i].versionCode !== 0) {
        fail('同一哈希又写了一条，或用 uri、versionCode 参与了比较')
      }
    }
  }
  if (filesOnly !== 1) {
    fail('同一哈希增加了第二条文件信任')
  }

  files.write(TRUST, '{')
  if (TrustList.trustBundle(HEX64, algo, 'com.example.app', 1) || files.read(TRUST) !== '{') {
    fail('坏的 trust.json 被删掉或覆盖了')
  }

  let fresh = new MemoryFiles()
  Writer.bind(fresh)
  for (let i = 0; i < ACTIONS.length; i++) {
    let line = new Line()
    line.action = ACTIONS[i]
    line.result = '成功'
    AuditLog.append(line, true)
  }
  let kept = fresh.read(AUDIT)
  if (kept === null) {
    fail('审计没有写入')
    return
  }
  let logged = AuditLog.read()
  if (logged.length !== ACTIONS.length) {
    fail('作业完成、隔离、恢复、卸载、清缓存、撤权、信任没有各写一条')
  }
  for (let i = 0; i < ACTIONS.length; i++) {
    if (logged[i].action !== ACTIONS[i] || logged[i].result !== '成功') {
      fail('审计动作或成功结果丢了')
    }
  }
  fresh.write(AUDIT, kept + '{"at":')
  if (AuditLog.read().length !== ACTIONS.length) {
    fail('最后一行不完整时没有忽略，或前面的行没有保留')
  }
  let added = new Line()
  added.action = '信任'
  added.result = '成功'
  added.target = 'com.example.added'
  AuditLog.append(added, true)
  let grown = fresh.read(AUDIT)
  if (grown === null || grown.indexOf(kept) !== 0 || grown.indexOf('{"at":') < 0 ||
    grown.length <= kept.length) {
    fail('append 截断了已有日志')
  }
  let after = AuditLog.read()
  if (after.length !== ACTIONS.length + 1 || after[0].action !== '作业完成' ||
    after[after.length - 1].target !== 'com.example.added') {
    fail('追加之后前面的审计行没有保留')
  }

  let failed = new MemoryFiles()
  Writer.bind(failed)
  let bad = new Line()
  bad.action = '卸载'
  bad.result = '成功'
  bad.target = 'com.example.app'
  AuditLog.append(bad, false)
  let failureText = failed.read(AUDIT)
  if (failureText === null || failureText.indexOf('成功') >= 0) {
    fail('失败把成功结果写进了审计')
  }
  let failureRows = AuditLog.read()
  if (failureRows.length !== 1 || failureRows[0].action !== '卸载' || failureRows[0].result === '成功') {
    fail('失败的卸载没有留下一条非成功的审计')
  }
}
