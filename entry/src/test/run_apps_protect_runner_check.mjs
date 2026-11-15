import { spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../../..')
const dir = mkdtempSync(join(tmpdir(), 'apps-protect-'))
try {
  writeFileSync(join(dir, 'hilog-sdk.mjs'), 'export const hilog = {info(){},warn(){},error(){}};\n')
  writeFileSync(join(dir, 'RulePack.ts'), 'export class RulePack { static active() { return {}; } }\n')
  writeFileSync(join(dir, 'Writer.ts'), 'export function limitRows(rows) { return rows.slice(0, 2000); }\n')
  writeFileSync(join(dir, 'RunnerRegistry.ts'), "export class RunEnd { itemCount=0; riskCount=0; summary=''; }\n")
  for (const name of ['apps/AppRunner', 'protect/ProtectRunner']) {
    const source = readFileSync(resolve(root, 'entry/src/main/ets/feature', name + '.ets'), 'utf8')
      .replaceAll('\r\n', '\n')
      .replaceAll("from '@kit.PerformanceAnalysisKit'", "from './hilog-sdk.mjs'")
      .replace(/from '(\.{1,2}\/[^']+)'/g, (original, path) =>
        path.endsWith('.mjs') ? original : `from './${path.split('/').at(-1)}.ts'`)
    writeFileSync(join(dir, name.split('/').at(-1) + '.ts'), source)
  }
  writeFileSync(join(dir, 'main.ts'), `
import assert from 'node:assert/strict';
import { AppRunner } from './AppRunner.ts';
import { ProtectRunner } from './ProtectRunner.ts';
const fact = (id, status) => ({ id, status, expected: '', actual: '', detail: id });
let calls = [];
let hand = { saved: null, save(value) { this.saved = value; } };
let posture = { pureMode: async () => { calls.push('pure'); return fact('pure-mode', 'ok'); },
  lockdown: async () => { calls.push('lockdown'); throw new Error('no'); },
  el5: async () => { calls.push('el5'); return fact('el5', 'risk'); } };
let end = await new ProtectRunner().run({ posture }, hand);
assert.deepEqual(calls, ['pure', 'lockdown', 'el5']);
assert.deepEqual(hand.saved.map(x => x.status), ['ok', 'unsupported', 'risk']);
assert.equal(hand.saved[1].detail, '无法读取锁定状态');
assert.equal(end.riskCount, 1);
const row = (name) => ({ bundleName: name, version: '', versionCode: 1, certSha256: '',
  certAlgo: 'none', declaredPermissions: [], source: 'unknown', verdict: {} });
const rows = ['ok.z', 'unknown.z', 'risk.b', 'suspicious.z', 'risk.a'].map(row);
let ready = false; let seenInputs = [];
const ctx = { base: { cancel: { cancelled: () => false } },
  census: { list: async () => rows },
  grants: { ready: () => ready, grantedOf: async () => { throw new Error('not called'); } },
  judge: { async judge(inputs) { seenInputs = inputs; return { complete: true, hits: inputs.map(input => ({
    fingerprint: input.fingerprint, verdict: { level: input.fingerprint.id.split('.')[0] } })) }; } } };
end = await new AppRunner({ trust: () => [] }).run(ctx, hand);
assert.deepEqual(hand.saved.map(x => x.bundleName), ['risk.a', 'risk.b', 'suspicious.z', 'unknown.z', 'ok.z']);
assert.equal(end.riskCount, 2);
assert.ok(seenInputs.every(x => !x.grantsReady && x.granted.length === 0));
ctx.census.list = async () => { throw new Error('unavailable'); };
end = await new AppRunner({ trust: () => [] }).run(ctx, hand);
assert.equal(end.summary, '无法获取应用列表');
process.stdout.write('Apps and protect runner checks passed\\n');
`)
  const run = spawnSync(process.execPath, ['--experimental-strip-types', join(dir, 'main.ts')], { encoding: 'utf8' })
  process.stdout.write(run.stdout || '')
  process.stderr.write(run.stderr || '')
  if (run.status !== 0) process.exitCode = run.status === null ? 1 : run.status
} finally {
  rmSync(dir, { recursive: true, force: true })
}
