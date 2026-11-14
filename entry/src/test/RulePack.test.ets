import { rulesVersionKey } from '../main/ets/record/CenterStore'
import { CenterStore } from '../main/ets/record/CenterStore'
import { RulePack } from '../main/ets/engine/RulePack'
import type { CenterFiles } from '../main/ets/record/Writer'
import { Writer } from '../main/ets/record/Writer'

const INDEX: string = 'center/jobs/index.json'

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

export function runRulePackChecks(): void {
  let host = globalThis as HilogHost
  host.__centerHilog = []
  let missing = RulePack.load(null)
  if (missing.rulesVersion !== 'none' || missing.notice.length !== 0 || missing.versionComparable ||
    rulesVersionKey !== 'center.rulesVersion') {
    fail('没有上一份时 center.rulesVersion 不是 none')
  }

  let text = '{' +
    '"version":"2026.1.2",' +
    '"bundles":[' +
    '{"bundleName":"com.bad.algo","certAlgo":"none","certSha256":"abc","level":"risk","reason":"x"},' +
    '{"bundleName":"com.name.only","certAlgo":"platform-fingerprint","certSha256":"","level":"risk","reason":"仅包名"},' +
    '{"bundleName":"com.kept","certAlgo":"platform-fingerprint","certSha256":"AA:BB","level":"risk","reason":"黑"}' +
    '],' +
    '"officials":[' +
    '{"bundleName":"com.empty.official","certAlgo":"platform-fingerprint","certSha256":[],"reason":"空"},' +
    '{"bundleName":"com.bad.official","certAlgo":"sha256","certSha256":["abc"],"reason":"算法"},' +
    '{"bundleName":"com.good.official","certAlgo":"sha256-of-cert-bytes","certSha256":["","AA BB"],"reason":"登记"}' +
    '],' +
    '"files":[' +
    '{"sha256":"","level":"risk","reason":""},' +
    '{"sha256":"  ","level":"ok","reason":""},' +
    '{"sha256":"abc123","level":"ok","reason":"白"},' +
    '{"sha256":"def456","level":"risk","reason":"黑文件"}' +
    '],' +
    '"heuristics":[' +
    '{"id":"short","permissions":["ohos.permission.CAMERA"],"reason":"一项"},' +
    '{"id":"risky","permissions":["ohos.permission.A","ohos.permission.B"],"level":"risk","reason":"降级"}' +
    ']}'
  let pack = RulePack.load(text)
  if (pack.rulesVersion !== '2026.1.2' || pack.versionComparable || pack.rulesVersion === 'unknown' ||
    pack.unavailable !== 2 || pack.disabled !== 2) {
    fail('版本或 N、M 不对')
  }
  if (hilogCount('certAlgo ignored') !== 2 || hilogCount('bundle downgraded to step 12') !== 1 ||
    hilogCount('officials certSha256 empty') !== 1 || hilogCount('heuristic level downgraded') !== 1) {
    fail('降级或忽略没有打 hilog')
  }
  let sawName = false
  let sawKept = false
  let sawBad = false
  for (let i = 0; i < pack.bundles.length; i++) {
    let row = pack.bundles[i]
    if (row.bundleName === 'com.bad.algo') {
      sawBad = true
    }
    if (row.bundleName === 'com.name.only') {
      sawName = row.step === 12 && row.level !== 'risk'
    }
    if (row.bundleName === 'com.kept') {
      sawKept = row.step === 2 && row.level === 'risk' && row.certSha256 === 'aabb'
    }
  }
  if (!sawName || !sawKept || sawBad || pack.bundles.length !== 2) {
    fail('仅包名没有降到第 12 步，或非法 certAlgo 被降成了仅包名')
  }
  if (pack.officials.length !== 1 || pack.officials[0].bundleName !== 'com.good.official' ||
    pack.officials[0].certSha256.length !== 1 || pack.officials[0].certSha256[0] !== 'aabb') {
    fail('空登记证书没有计入 M，或仍参加后续步骤')
  }
  if (pack.files.length !== 2 || pack.files[0].sha256 !== 'abc123' || pack.files[0].level !== 'ok' ||
    pack.files[1].level !== 'risk') {
    fail('空 sha256 没有被忽略')
  }
  if (pack.heuristics.length !== 1 || pack.heuristics[0].id !== 'risky' ||
    pack.heuristics[0].level !== 'suspicious') {
    fail('启发式 level=risk 没有降为 suspicious，或少权限的规则没有计入 M')
  }

  let keptVersion = pack.rulesVersion
  let broken = RulePack.load('{')
  if (broken.notice !== '规则文件损坏，仍使用上一份' || broken.rulesVersion !== keptVersion ||
    broken.bundles.length !== 2 || broken.unavailable !== 2) {
    fail('损坏时没有继续用上一份')
  }

  let fresh = RulePack.load('{"version":"2026.11.12","files":[{"sha256":"abc","level":"ok","reason":""}]}')
  if (fresh.notice.length !== 0 || !fresh.versionComparable || fresh.rulesVersion !== '2026.11.12' ||
    fresh.files.length !== 1) {
    fail('定宽版本没有被接受，或损坏文案留在了新包上')
  }

  let files = new MemoryFiles()
  files.write('center/rules.json', '{"version":"1999.01.01"}')
  files.write(INDEX, '[{"jobId":"q","seq":3,"kind":"malware","lane":"heavy","startedAt":"","finishedAt":"",' +
    '"state":"queued","itemCount":0,"riskCount":0,"summary":"","resultFile":""}]')
  CenterStore.prepare(files, () => {
    return '{"version":"2026.11.12"}'
  })
  let after = JSON.parse(files.read(INDEX) as string) as JobPeek[]
  let active = RulePack.active()
  if (after.length !== 1 || after[0].state !== 'interrupted' || after[0].summary !== '扫描已中断' ||
    after[0].seq !== 3 || active.rulesVersion !== '2026.11.12' || active.notice.length !== 0) {
    fail('prepare 改了 recover，或没有在 recover 之后读规则')
  }
  if (files.read('center/rules.json') !== '{"version":"1999.01.01"}') {
    fail('规则从 filesDir 读入了')
  }
}

class JobPeek {
  state: string = ''
  summary: string = ''
  seq: number = 0
}
