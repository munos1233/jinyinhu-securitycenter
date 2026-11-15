import { spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../../..')
const CLEAN = 'entry/src/main/ets/feature/clean/CleanRunner.ets'
const CORPSE = 'entry/src/main/ets/feature/clean/CorpseFinder.ets'
const DUP = 'entry/src/main/ets/feature/clean/DuplicateFinder.ets'
const LARGE = 'entry/src/main/ets/feature/clean/LargeFileFinder.ets'
const REGISTRY = 'entry/src/main/ets/task/RunnerRegistry.ets'
const EXAM = 'entry/src/main/ets/feature/exam/ExamRunner.ets'
const files = [
  ['entry/src/main/ets/center/CenterTypes.ets', 'CenterTypes.ts'],
  ['entry/src/main/ets/center/CenterLimits.ets', 'CenterLimits.ts'],
  ['entry/src/main/ets/center/CenterError.ets', 'CenterError.ts'],
  ['entry/src/main/ets/task/CancelFlag.ets', 'CancelFlag.ts'],
  ['entry/src/main/ets/task/Contexts.ets', 'Contexts.ts'],
  [REGISTRY, 'RunnerRegistry.ts'],
  [CORPSE, 'CorpseFinder.ts'],
  [CLEAN, 'CleanRunner.ts'],
  [DUP, 'DuplicateFinder.ts'],
  [LARGE, 'LargeFileFinder.ts'],
  ['entry/src/test/CleanFinders.test.ets', 'CleanFinders.test.ts']
]

const problems = []
const read = (path) => readFileSync(resolve(root, path), 'utf8').replace(/\r\n/g, '\n')
const code = (text) => text.replace(/\/\*[\s\S]*?\*\/|\/\/.*$/gm, '')

for (const path of [CLEAN, CORPSE, DUP, LARGE]) {
  const text = read(path)
  if (!text.includes('const DOMAIN: number = 0x4A59') || !text.includes("const TAG: string = 'Center'")) {
    problems.push(`${path} 的 hilog 域必须是 0x4A59，标签 Center`)
  }
  for (const banned of ['已安全', '云查杀已开启', '已防护', '已拦截', '人工智能引擎已防护', '病毒', '分数']) {
    if (text.includes(banned)) {
      problems.push(`${path} 出现了「${banned}」`)
    }
  }
  if (/from '\.\.\/(exam|malware|apps|protect)\//.test(text) || /from '\.\.\/\.\.\/pages\//.test(text)) {
    problems.push(`${path}：功能模块互不 import，也不 import 页面`)
  }
}

const clean = read(CLEAN)
const cleanCode = code(clean)
for (const banned of ['Quarantine', 'Disposition', '.clear(', 'CacheClear', 'uninstall', 'AccessRevoke']) {
  if (cleanCode.includes(banned)) {
    problems.push(`CleanRunner 不在 Runner 里清缓存/隔离/卸载：出现了 ${banned}`)
  }
}
if (!clean.includes('无法读取其他应用缓存') || !clean.includes('请先选择目录')) {
  problems.push('CleanRunner 必须能写出缓存身份与目录授权说明')
}
if (!/selected\s*=\s*false/.test(cleanCode)) {
  problems.push('CleanRunner 写回时 selected 为 false')
}

const corpse = read(CORPSE)
const corpseCode = code(corpse)
if (!/listInstallers\(/.test(corpseCode)) {
  problems.push('CorpseFinder 只调用 InstallerScan.listInstallers')
}
if (/HapReader|fs\.|hashFd|FileOpen/.test(corpseCode)) {
  problems.push('CorpseFinder 禁止再实现打开、扩展名和 HapReader')
}

const exam = read(EXAM)
if (/CorpseFinder/.test(exam)) {
  problems.push('ExamRunner 仍然不 import CorpseFinder')
}

const dup = read(DUP)
const dupCode = code(dup)
if (/Quarantine|CleanReport|CacheStats|CacheClear/.test(dupCode)) {
  problems.push('DuplicateFinder 不产生 CleanReport，不调用隔离或缓存')
}
if (!/DuplicateGroup/.test(dup) || !/FileToolReport/.test(dup)) {
  problems.push('DuplicateFinder 产出 FileToolReport / DuplicateGroup')
}

const large = read(LARGE)
const largeCode = code(large)
if (/Quarantine|CleanReport|CacheStats/.test(largeCode)) {
  problems.push('LargeFileFinder 不产生 CleanReport，不调用隔离')
}
if (!large.includes('1GB+') || !large.includes('500MB+') || !large.includes('100MB+')) {
  problems.push('LargeFileFinder 必须按 1024 进位写三档 reason')
}
if (!/largeTiers/.test(largeCode)) {
  problems.push('大文件阈值使用 CenterLimits.largeTiers')
}

const registry = read(REGISTRY)
if (/from '\.\.\/(feature|pages)\//.test(registry)) {
  problems.push('RunnerRegistry 在 task 里，不 import feature 或页面')
}
const registerBody = code(registry).match(/static registerAll\(.*\): void \{([\s\S]*?)\n {2}\}/)
if (registerBody === null ||
  !/table\.clean = runners\.clean/.test(registerBody[1]) ||
  !/table\.duplicate = runners\.duplicate/.test(registerBody[1]) ||
  !/table\.largeFile = runners\.largeFile/.test(registerBody[1]) ||
  /table\.(apps|protect)\s*=/.test(registerBody[1])) {
  problems.push('RunnerRegistry.registerAll 只追加 clean、duplicate、large-file')
}

if (problems.length > 0) {
  process.stderr.write(problems.join('\n') + '\n')
  process.exit(1)
}

const stubs = {
  'hilog-sdk.mjs': `export const hilog = {
  info() {},
  warn() {},
  error() {}
};
`,
  'InstallerScan.ts': `export class FsInstallerIo {
  list() { throw new Error('fs replaced'); }
  stat() { throw new Error('fs replaced'); }
  size() { throw new Error('fs replaced'); }
  now() { return Date.now(); }
}
export function listInstallers() {
  throw new Error('listInstallers replaced by StubCorpse in tests');
}
`,
  'HashWorker.ts': `import { CenterError } from './CenterError.ts';
export const WORKER_DOWN = 'hash-worker:';
export class HashWorker { async hash() { throw new Error('HashWorker replaced'); } }
export function isWorkerDown(err) {
  return err instanceof CenterError && err.code === 'io' && String(err.raw).indexOf(WORKER_DOWN) === 0;
}
`
}

function prepare(text) {
  return text.replace(/\r\n/g, '\n')
    .replace(/^import type [^;]*?from '[^']+';?\n?/gms, '')
    .replace(/^@Concurrent\n/gm, '')
    .replace(/from '(@[^']+)'/g, (original, module) => {
      if (module === '@kit.PerformanceAnalysisKit') return "from './hilog-sdk.mjs'"
      if (module === '@kit.ArkTS') return "from './arkts-sdk.mjs'"
      return original
    })
    .replace(/from '(\.{1,2}\/[^']+)'/g, (original, path) =>
      path.endsWith('.mjs') ? original : `from './${path.split('/').at(-1)}.ts'`)
}

const dir = mkdtempSync(join(tmpdir(), 'clean-finders-'))
try {
  for (const [name, body] of Object.entries(stubs)) {
    writeFileSync(join(dir, name), body)
  }
  for (const [from, to] of files) {
    writeFileSync(join(dir, to), prepare(read(from)))
  }
  writeFileSync(join(dir, 'main.ts'),
    "import { runCleanFindersChecks } from './CleanFinders.test.ts';\nawait runCleanFindersChecks();\nprocess.stdout.write('CleanFinders and RunnerRegistry checks passed\\n');\n")
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
