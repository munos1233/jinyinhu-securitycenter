import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../../..')
const view = readFileSync(resolve(root, 'entry/src/main/ets/pages/ScanView.ets'), 'utf8').replaceAll('\r\n', '\n')
const methods = ['checkStatus', 'phraseText', 'phraseDetail', 'phraseColor', 'cardColor', 'showingRun']

function extract(name) {
  const start = view.indexOf(`  private ${name}(`)
  assert(start >= 0, `ScanView method ${name} is missing`)
  const next = view.indexOf('\n  private ', start + 1)
  assert(next > start, `ScanView method ${name} boundary is missing`)
  return view.slice(start, next).replace('  private ', '  ')
}

const bodies = methods.map(extract)
assert.match(view, /import \{ toCheck \} from '\.\.\/center\/ProbeMap'/)
assert.match(extract('checkStatus'), /toCheck\(id, this\.visibleRun\(id\)\)\.status/)
assert.match(extract('phraseDetail'), /toCheck\(id, this\.visibleRun\(id\)\)\.detail/)
assert.match(view, /if \(this\.showingRun\(id\) && this\.phraseDetail\(id\)\.length > 0\)/)
assert.match(view, /Text\(this\.phraseDetail\(id\)\)/)
for (const name of ['phraseText', 'phraseColor', 'cardColor']) {
  assert.match(extract(name), /this\.checkStatus\(id\)/)
  assert.doesNotMatch(extract(name), /run\.verdict|return run\.phrase/)
}
assert.match(view, /const TAG = 'ScanView'/)
assert.match(view, /const DOMAIN = 0x4A59/)

const files = [
  ['entry/src/main/ets/center/CenterTypes.ets', 'CenterTypes.ts'],
  ['entry/src/main/ets/center/ProbeMap.ets', 'ProbeMap.ts'],
  ['entry/src/main/ets/probe/ProbeTypes.ets', 'ProbeTypes.ts'],
  ['entry/src/main/ets/common/Theme.ets', 'Theme.ts'],
  ['entry/src/test/ProbeMap.test.ets', 'ProbeMap.test.ts']
]

function prepare(source) {
  return source.replaceAll('\r\n', '\n')
    .replace("import { common } from '@kit.AbilityKit';\n", '')
    .replaceAll('common.UIAbilityContext', 'Object')
    .replaceAll('@Observed\n', '')
    .replace(/from '(\.{1,2}\/[^']+)'/g, (_, path) => `from './${path.split('/').at(-1)}.ts'`)
}

const dir = mkdtempSync(join(tmpdir(), 'probe-map-'))
try {
  for (const [from, to] of files) {
    writeFileSync(join(dir, to), prepare(readFileSync(resolve(root, from), 'utf8')))
  }
  writeFileSync(join(dir, 'ScanViewHarness.ts'), [
    "import type { CheckStatus } from './CenterTypes.ts'",
    "import type { ProbeResult } from './ProbeTypes.ts'",
    "import { toCheck } from './ProbeMap.ts'",
    "import { Theme } from './Theme.ts'",
    'export class ScanViewHarness {',
    '  run: ProbeResult | undefined = undefined',
    '  running: boolean = false',
    '  fault: boolean = false',
    '  visibleRun(id: string): ProbeResult | undefined { return this.run }',
    '  visibleFault(id: string): Object | undefined { return this.fault ? {} : undefined }',
    '  scanningThis(id: string): boolean { return this.running }',
    ...bodies,
    '}'
  ].join('\n'))
  writeFileSync(join(dir, 'main.ts'), `
import assert from 'node:assert/strict';
import { runProbeMapChecks, probeResult } from './ProbeMap.test.ts';
import { ScanViewHarness } from './ScanViewHarness.ts';
import { Theme } from './Theme.ts';
runProbeMapChecks();
const view = new ScanViewHarness();
assert.equal(view.phraseText('P1'), '尚未检测');
assert.equal(view.phraseDetail('P1'), '');
assert.equal(view.phraseColor('P1'), Theme.muted);
assert.equal(view.cardColor('P1'), Theme.line);
view.fault = true;
assert.equal(view.phraseText('P1'), '检测未完成');
assert.equal(view.phraseColor('P1'), Theme.warn);
assert.equal(view.cardColor('P1'), Theme.warn);
view.fault = false;
for (const [id, verdict, level, kinds, label, color] of [
  ['P1', 'blocked', 'L2', ['source-ref'], '未验证', Theme.accent],
  ['P1', 'blocked', 'L2', ['sidecar-state'], '通过', Theme.ok],
  ['P1', 'hit', 'L2', ['cmd-transcript'], '风险', Theme.danger],
  ['P1', 'blocked', 'L1', ['sidecar-state'], '未验证', Theme.accent],
  ['P2', 'blocked', 'L1', ['errno'], '通过', Theme.ok],
  ['P2', 'hit', 'L2', ['errno', 'source-ref'], '未验证', Theme.accent],
  ['P3', 'passive', 'L2', ['source-ref'], '未验证', Theme.accent],
  ['P3', 'blocked', 'L2', ['source-ref'], '通过', Theme.ok]
] as const) {
  view.run = probeResult(id, verdict, level, [...kinds]);
  assert.equal(view.phraseText(id), label);
  assert.equal(view.phraseColor(id), color);
  assert.equal(view.cardColor(id), color);
  assert.equal(view.phraseDetail(id), '暂未发现异常');
  assert.equal(view.showingRun(id), true);
}
view.running = true;
assert.equal(view.phraseText('P3'), '正在检测');
assert.equal(view.phraseColor('P3'), Theme.muted);
assert.equal(view.cardColor('P3'), Theme.accent);
assert.equal(view.showingRun('P3'), false);
process.stdout.write('ProbeMap matrix and ScanView wiring checks passed\\n');
`)
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
