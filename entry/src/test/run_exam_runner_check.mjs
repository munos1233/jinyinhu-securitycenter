import { spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../../..')
const RUNNER = 'entry/src/main/ets/feature/exam/ExamRunner.ets'
const REGISTRY = 'entry/src/main/ets/task/RunnerRegistry.ets'
const files = [
  ['entry/src/main/ets/center/CenterTypes.ets', 'CenterTypes.ts'],
  ['entry/src/main/ets/center/CenterLimits.ets', 'CenterLimits.ts'],
  ['entry/src/main/ets/center/CenterError.ets', 'CenterError.ts'],
  ['entry/src/main/ets/center/CleanMath.ets', 'CleanMath.ts'],
  ['entry/src/main/ets/center/Anomaly.ets', 'Anomaly.ts'],
  ['entry/src/main/ets/center/SensitiveCatalog.ets', 'SensitiveCatalog.ts'],
  ['entry/src/main/ets/engine/LocalRuleEngine.ets', 'LocalRuleEngine.ts'],
  ['entry/src/main/ets/engine/Lookalike.ets', 'Lookalike.ts'],
  ['entry/src/main/ets/engine/Heuristic.ets', 'Heuristic.ts'],
  ['entry/src/main/ets/engine/RulePack.ets', 'RulePack.ts'],
  ['entry/src/main/ets/engine/Decide.ets', 'Decide.ts'],
  ['entry/src/main/ets/engine/QueryKey.ets', 'QueryKey.ts'],
  ['entry/src/main/ets/engine/AppJudge.ets', 'AppJudge.ts'],
  ['entry/src/main/ets/feature/exam/ExamState.ets', 'ExamState.ts'],
  ['entry/src/main/ets/task/CancelFlag.ets', 'CancelFlag.ts'],
  ['entry/src/main/ets/task/Contexts.ets', 'Contexts.ts'],
  [REGISTRY, 'RunnerRegistry.ts'],
  [RUNNER, 'ExamRunner.ts'],
  ['entry/src/test/ExamRunner.test.ets', 'ExamRunner.test.ts']
]

const problems = []
const read = (path) => readFileSync(resolve(root, path), 'utf8').replace(/\r\n/g, '\n')
const code = (text) => text.replace(/\/\*[\s\S]*?\*\/|\/\/.*$/gm, '')

const runner = read(RUNNER)
const runnerCode = code(runner)
if (!runner.includes('const DOMAIN: number = 0x4A59') || !runner.includes("const TAG: string = 'Center'")) {
  problems.push('ExamRunner 的 hilog 域必须是 0x4A59，标签 Center')
}
for (const banned of ['probe/', 'ProbeMap', 'CorpseFinder']) {
  if (runner.includes(banned)) {
    problems.push(`ExamRunner 不得引用 ${banned}`)
  }
}
for (const banned of ['Quarantine', 'Disposition', 'InstallerPort', 'CacheClear', 'AccessRevoke', 'TrustList',
  'uninstall', 'revoke', '.clear(', 'HapReader', 'HashWorker', 'Hash\'', 'requestPermissionsFromUser']) {
  if (runnerCode.includes(banned)) {
    problems.push(`ExamRunner 不清除、撤权、卸载、隔离，也不自己读安装包：出现了 ${banned}`)
  }
}
for (const banned of ['已安全', '云查杀已开启', '已防护', '已拦截', '人工智能引擎已防护', '分数', '没有侧载应用']) {
  if (runner.includes(banned)) {
    problems.push(`ExamRunner 出现了「${banned}」`)
  }
}
if (/from '\.\.\/(malware|clean|permission|apps|protect)\//.test(runner) || /from '\.\.\/\.\.\/pages\//.test(runner)) {
  problems.push('功能模块互不 import，也不 import 页面')
}
if ((runnerCode.match(/listInstallers\(/g) || []).length !== 1 ||
  !runner.includes("import { listInstallers } from '../../engine/InstallerScan'")) {
  problems.push('安装包字节只通过 InstallerScan.listInstallers')
}
if ((runnerCode.match(/examAppsStatus\(/g) || []).length !== 2 || !runnerCode.includes('appendExamAppsDetail(')) {
  problems.push('应用信誉项只经 examAppsStatus 得到状态，写回后再调用 appendExamAppsDetail')
}
if (!runnerCode.includes('sumParts(parts)')) {
  problems.push('cleanableBytes 用 sumParts')
}
if (!/judge\.judge\(/.test(runnerCode) || (runnerCode.match(/Anomaly\.count\(/g) || []).length !== 1) {
  problems.push('应用判定走 AppJudge，权限异常只调用一次 Anomaly.count')
}

const registry = read(REGISTRY)
if (/from '\.\.\/(feature|pages)\//.test(registry)) {
  problems.push('RunnerRegistry 在 task 里，不 import feature 或页面')
}
const registerBody = code(registry).match(/static registerAll\(.*\): void \{([\s\S]*?)\n {2}\}/)
if (registerBody === null || !/table\.exam = runners\.exam/.test(registerBody[1]) ||
  /table\.(clean|duplicate|largeFile|permission|apps|protect)\s*=/.test(registerBody[1])) {
  problems.push('RunnerRegistry.registerAll 只登记 exam 和 malware')
}

if (problems.length > 0) {
  process.stderr.write(problems.join('\n') + '\n')
  process.exit(1)
}

const stubs = {
  'InstallerScan.ts': `export function listInstallers(files, open, installed, stopped, maxFiles, maxBytes, deadlineMs) {
  const bag = globalThis.__installers;
  if (typeof maxFiles !== 'number' || typeof maxBytes !== 'number' || typeof deadlineMs !== 'number' ||
    typeof stopped !== 'function' || files.persisted().length === 0) {
    throw new Error('listInstallers called with wrong arguments');
  }
  bag.calls.push(installed.slice());
  return { hits: bag.hits.map((hit) => ({ ...hit })), stoppedByLimit: bag.stoppedByLimit };
}
`,
  'fs-sdk.mjs': `const tree = new Map([
  ['/cache', { dir: true, link: false, size: 0, names: ['a', 'sub', 'link'] }],
  ['/cache/a', { dir: false, link: false, size: 10 }],
  ['/cache/sub', { dir: true, link: false, size: 0, names: ['b'] }],
  ['/cache/sub/b', { dir: false, link: false, size: 20 }],
  ['/cache/link', { dir: false, link: true, size: 999 }]
]);
export default {
  lstatSync(path) {
    const node = tree.get(path);
    return { size: node.size, isDirectory: () => node.dir, isSymbolicLink: () => node.link };
  },
  listFileSync(path) { return tree.get(path).names.slice(); }
};
`,
  'hilog-sdk.mjs': `export const hilog = {
  info(d, t, ...m) { (globalThis.__hilog ??= []).push(m.join(' ')); },
  warn(d, t, ...m) { (globalThis.__hilog ??= []).push(m.join(' ')); },
  error(d, t, ...m) { (globalThis.__hilog ??= []).push(m.join(' ')); }
};
`
}

function prepare(text, name) {
  let out = text.replace(/\r\n/g, '\n')
    .replace(/^import type [^;]*?from '[^']+';?\n?/gms, '')
    .replace(/from '(@[^']+)'/g, (original, module) => {
      if (module === '@kit.PerformanceAnalysisKit') return "from './hilog-sdk.mjs'"
      if (module === '@ohos.file.fs') return "from './fs-sdk.mjs'"
      return original
    })
    .replace(/from '(\.{1,2}\/[^']+)'/g, (original, path) =>
      path.endsWith('.mjs') ? original : `from './${path.split('/').at(-1)}.ts'`)
  if (name === 'Anomaly.ts') {
    out = out.replace('    let count = 0', '    globalThis.__anomalyCalls = (globalThis.__anomalyCalls ?? 0) + 1;\n    let count = 0')
  }
  return out
}

const dir = mkdtempSync(join(tmpdir(), 'exam-runner-'))
try {
  for (const [name, body] of Object.entries(stubs)) {
    writeFileSync(join(dir, name), body)
  }
  for (const [from, to] of files) {
    writeFileSync(join(dir, to), prepare(read(from), to))
  }
  writeFileSync(join(dir, 'main.ts'),
    "import { runExamRunnerChecks } from './ExamRunner.test.ts';\nawait runExamRunnerChecks();\nprocess.stdout.write('ExamRunner and RunnerRegistry checks passed\\n');\n")
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
