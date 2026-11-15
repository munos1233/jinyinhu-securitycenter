import { spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../../..')
const DISPOSITION = 'entry/src/main/ets/record/Disposition.ets'
const files = [
  ['entry/src/main/ets/center/CenterTypes.ets', 'CenterTypes.ts'],
  ['entry/src/main/ets/center/CenterLimits.ets', 'CenterLimits.ts'],
  ['entry/src/main/ets/center/CenterError.ets', 'CenterError.ts'],
  ['entry/src/main/ets/center/Clock.ets', 'Clock.ts'],
  ['entry/src/main/ets/center/CleanMath.ets', 'CleanMath.ts'],
  ['entry/src/main/ets/center/SensitiveCatalog.ets', 'SensitiveCatalog.ts'],
  ['entry/src/main/ets/center/Anomaly.ets', 'Anomaly.ts'],
  ['entry/src/main/ets/engine/Decide.ets', 'Decide.ts'],
  ['entry/src/main/ets/engine/LocalRuleEngine.ets', 'LocalRuleEngine.ts'],
  ['entry/src/main/ets/engine/Lookalike.ets', 'Lookalike.ts'],
  ['entry/src/main/ets/engine/Heuristic.ets', 'Heuristic.ts'],
  ['entry/src/main/ets/engine/RulePack.ets', 'RulePack.ts'],
  ['entry/src/main/ets/feature/exam/ExamState.ets', 'ExamState.ts'],
  ['entry/src/main/ets/record/Writer.ets', 'Writer.ts'],
  ['entry/src/main/ets/record/AuditLog.ets', 'AuditLog.ts'],
  ['entry/src/main/ets/record/TrustList.ets', 'TrustList.ts'],
  [DISPOSITION, 'Disposition.ts'],
  ['entry/src/test/Disposition.test.ets', 'Disposition.test.ts']
]

const problems = []
const read = (path) => readFileSync(resolve(root, path), 'utf8').replace(/\r\n/g, '\n')
const code = (text) => text.replace(/\/\*[\s\S]*?\*\/|\/\/.*$/gm, '')
const body = (text, start, end) => {
  const from = text.indexOf(start)
  const to = text.indexOf(end, from + start.length)
  return from < 0 || to < 0 ? '' : text.substring(from, to)
}

const source = read(DISPOSITION)
const sourceCode = code(source)
if (!source.includes('const DOMAIN: number = 0x4A59') || !source.includes("const TAG: string = 'Center'")) {
  problems.push('Disposition 的 hilog 域必须是 0x4A59，标签 Center')
}
for (const [, path] of source.matchAll(/from '([^']+)'/g)) {
  if (/^\.\.\/(pages|task|system|cloud|probe)\//.test(path) ||
    (path.startsWith('../feature/') && path !== '../feature/exam/ExamState')) {
    problems.push(`Disposition 不得 import ${path}`)
  }
}
for (const banned of ['已安全', '云查杀已开启', '已防护', '已拦截', '人工智能引擎已防护', '病毒', '分数',
  'cleanBundleDataFiles', 'clearUpApplicationData', 'saveIndex']) {
  if (sourceCode.includes(banned)) {
    problems.push(`Disposition 出现了「${banned}」`)
  }
}
if (/\.state\s*=\s*'(done|running|queued|interrupted|failed|cancelled)'/.test(sourceCode)) {
  problems.push('Disposition 不改作业状态')
}
if (!/examWritebackTargets\(/.test(sourceCode)) {
  problems.push('体检回写必须调用 examWritebackTargets')
}
const clearBody = body(sourceCode, 'async clearCache(', '  trust(')
if (clearBody.length === 0 || /quarantine|Quarantine/.test(clearBody)) {
  problems.push('清缓存不调用 Quarantine.put')
}
const viewBody = body(sourceCode, 'private updateViewing(', 'private writeBack(')
if (viewBody.length === 0 || /examAppsStatus|stateOf|settleExam/.test(viewBody)) {
  problems.push('ScanReport 上不调用 examAppsStatus 或 stateOf')
}
for (const page of ['entry/src/main/ets/pages/HomeView.ets', 'entry/src/main/ets/pages/ExamView.ets']) {
  if (/fs\.|bundleManager|installer\./.test(code(read(page)))) {
    problems.push(`${page} 不读盘、不调包管理`)
  }
}

if (problems.length > 0) {
  process.stderr.write(problems.join('\n') + '\n')
  process.exit(1)
}

const stubs = {
  'hilog-sdk.mjs': `export const hilog = { info() {}, warn() {}, error() {} };\n`,
  'fs-sdk.mjs': `export default {
  openSync() { throw new Error('fs is replaced by MemoryFiles in tests'); },
  listFileSync() { throw new Error('fs is replaced by FakeOwn in tests'); },
  OpenMode: { READ_ONLY: 0, CREATE: 0, READ_WRITE: 0, TRUNC: 0 }
};\n`
}

function prepare(text) {
  return text.replace(/\r\n/g, '\n')
    .replace(/^import type [^;]*?from '[^']+';?\n?/gms, '')
    .replace(/from '(@[^']+)'/g, (original, module) => {
      if (module === '@kit.PerformanceAnalysisKit') return "from './hilog-sdk.mjs'"
      if (module === '@ohos.file.fs') return "from './fs-sdk.mjs'"
      return original
    })
    .replace(/from '(\.{1,2}\/[^']+)'/g, (original, path) =>
      path.endsWith('.mjs') ? original : `from './${path.split('/').at(-1)}.ts'`)
}

const dir = mkdtempSync(join(tmpdir(), 'disposition-'))
try {
  for (const [name, text] of Object.entries(stubs)) {
    writeFileSync(join(dir, name), text)
  }
  for (const [from, to] of files) {
    writeFileSync(join(dir, to), prepare(read(from)))
  }
  writeFileSync(join(dir, 'main.ts'),
    "import { runDispositionChecks } from './Disposition.test.ts';\nawait runDispositionChecks();\nprocess.stdout.write('Disposition checks passed\\n');\n")
  const result = spawnSync(process.execPath, ['--experimental-strip-types', join(dir, 'main.ts')], {
    encoding: 'utf8'
  })
  process.stdout.write(result.stdout || '')
  process.stderr.write(result.stderr || '')
  if (result.status !== 0) {
    process.exitCode = result.status === null ? 1 : result.status
  }
} finally {
  rmSync(dir, { recursive: true, force: true })
}
