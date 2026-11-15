import { spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../../..')
const files = [
  'center/CenterTypes', 'center/CenterLimits', 'center/CenterError', 'center/Clock',
  'feature/exam/ExamState', 'record/Writer', 'task/RunnerRegistry', 'feature/permission/PermissionRunner'
]
const dir = mkdtempSync(join(tmpdir(), 'permission-runner-'))
try {
  writeFileSync(join(dir, 'hilog-sdk.mjs'), 'export const hilog = {info(){},warn(){},error(){}};\n')
  writeFileSync(join(dir, 'fs-sdk.mjs'), 'export default {};\n')
  for (const name of files) {
    const source = readFileSync(resolve(root, 'entry/src/main/ets', name + '.ets'), 'utf8')
      .replaceAll('\r\n', '\n')
      .replaceAll("from '@kit.PerformanceAnalysisKit'", "from './hilog-sdk.mjs'")
      .replaceAll("from '@ohos.file.fs'", "from './fs-sdk.mjs'")
      .replace(/from '(\.{1,2}\/[^']+)'/g, (original, path) =>
        path.endsWith('.mjs') ? original : `from './${path.split('/').at(-1)}.ts'`)
    writeFileSync(join(dir, name.split('/').at(-1) + '.ts'), source)
  }
  writeFileSync(join(dir, 'main.ts'), `
import assert from 'node:assert/strict';
import { CenterError } from './CenterError.ts';
import { PermissionRunner, groupCounts } from './PermissionRunner.ts';
import { RunnerRegistry, RunnerSet } from './RunnerRegistry.ts';
const report = { saved: null, save(value) { this.saved = value; } };
const fact = (bundleName, permission, group, grant = 'granted') => ({ bundleName,
  displayName: bundleName, permission, label: permission, group, sensitive: true,
  declared: true, grant, fixed: false, tokenId: 7, source: 'unknown' });
const rows = [fact('app.a', 'A', '位置'), fact('app.a', 'B', '位置'),
  fact('app.b', 'C', '位置'), fact('app.c', 'D', '相机', 'unknown')];
const groups = groupCounts(rows);
assert.equal(groups.length, 8);
assert.equal(groups.find(x => x.group === '位置').count, 2);
assert.equal(groups.find(x => x.group === '相机').count, 0);
assert.equal(groups.find(x => x.group === '位置').known, true);
assert.equal(groups.find(x => x.group === '相机').known, false);
let cancelled = false;
let usesCalls = 0;
const ctx = { base: { cancel: { cancelled: () => cancelled }, report() {} },
  census: { async list() { return [{ bundleName: 'app.a' }, { bundleName: 'app.b' }]; } },
  access: { async facts(bundles) { assert.equal(bundles.length, 2); return rows; },
    async recentUses() { usesCalls++; return []; } } };
const runner = new PermissionRunner();
let end = await runner.run(ctx, report);
assert.equal(end.itemCount, 2);
assert.equal(report.saved.bundlesAvailable, true);
assert.equal(report.saved.usesAvailable, true);
assert.equal(report.saved.facts[3].grant, 'unknown');
assert.equal(report.saved.counts[0].count, 2);
ctx.access.recentUses = async () => { throw new CenterError('unsupported', 'usedStats'); };
await runner.run(ctx, report);
assert.equal(report.saved.usesAvailable, false);
assert.deepEqual(report.saved.uses, []);
ctx.census.list = async () => { throw new CenterError('unsupported', 'bundles'); };
end = await runner.run(ctx, report);
assert.equal(end.summary, '无法获取应用列表');
assert.equal(report.saved.bundlesAvailable, false);
ctx.census.list = async () => { throw new Error('io'); };
await assert.rejects(() => runner.run(ctx, report), /io/);
ctx.census.list = async () => [];
cancelled = true;
await runner.run(ctx, report);
assert.equal(report.saved.bundlesAvailable, true);
assert.equal(report.saved.usesAvailable, false);
assert.equal(usesCalls, 1);
const many = Array.from({ length: 2010 }, (_, i) => fact('app.' + i, 'A', '位置'));
ctx.access.facts = async () => many;
cancelled = false;
await runner.run(ctx, report);
assert.equal(report.saved.facts.length, 2000);
assert.equal(report.saved.counts[0].count, 2010);
const runners = new RunnerSet();
runners.permission = (context, hand) => runner.run(context, hand);
RunnerRegistry.registerAll(runners);
assert.equal(RunnerRegistry.table().has('permission'), true);
assert.equal(RunnerRegistry.table().has('apps'), false);
runners.apps = async () => ({ itemCount: 0, riskCount: 0, summary: '' });
runners.protect = async () => ({ itemCount: 0, riskCount: 0, summary: '' });
RunnerRegistry.registerAll(runners);
assert.equal(RunnerRegistry.table().has('permission'), true);
assert.equal(RunnerRegistry.table().has('apps'), true);
assert.equal(RunnerRegistry.table().has('protect'), true);
process.stdout.write('PermissionRunner census, limits, cancellation, and registry checks passed\\n');
`)
  const run = spawnSync(process.execPath, ['--experimental-strip-types', join(dir, 'main.ts')], { encoding: 'utf8' })
  process.stdout.write(run.stdout || '')
  process.stderr.write(run.stderr || '')
  if (run.status !== 0) process.exitCode = run.status === null ? 1 : run.status
} finally {
  rmSync(dir, { recursive: true, force: true })
}
