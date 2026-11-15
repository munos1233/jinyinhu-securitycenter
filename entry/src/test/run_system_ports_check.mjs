import { spawnSync } from 'node:child_process'
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../../..')
const ported = [
  'entry/src/main/ets/system/FileGrant.ets',
  'entry/src/main/ets/system/CachePort.ets',
  'entry/src/main/ets/system/InstallerPort.ets'
]
const files = [
  ['entry/src/main/ets/center/CenterTypes.ets', 'CenterTypes.ts'],
  ['entry/src/main/ets/center/CenterLimits.ets', 'CenterLimits.ts'],
  ['entry/src/main/ets/center/CenterError.ets', 'CenterError.ts'],
  ['entry/src/main/ets/system/SystemGate.ets', 'SystemGate.ts'],
  ['entry/src/main/ets/system/FileGrant.ets', 'FileGrant.ts'],
  ['entry/src/main/ets/system/CachePort.ets', 'CachePort.ts'],
  ['entry/src/main/ets/system/InstallerPort.ets', 'InstallerPort.ts'],
  ['entry/src/test/SystemPorts.test.ets', 'SystemPorts.test.ts']
]

const problems = []
const read = (path) => readFileSync(resolve(root, path), 'utf8')
for (const path of ported) {
  const source = read(path)
  if (!source.includes('const DOMAIN: number = 0x4A59') || !source.includes("const TAG: string = 'Center'")) {
    problems.push(`${path} 的 hilog 域必须是 0x4A59，标签 Center`)
  }
  if (/from '\.\.\/(pages|task|feature)\//.test(source)) {
    problems.push(`${path} 系统端口不得 import 页面、任务或功能模块`)
  }
  for (const banned of ['已安全', '云查杀已开启', '已防护', '已拦截', '人工智能引擎已防护']) {
    if (source.includes(banned)) {
      problems.push(`${path} 出现了禁用文案「${banned}」`)
    }
  }
}
if (existsSync(resolve(root, 'entry/src/main/ets/system/StorageCensus.ets'))) {
  problems.push('本轮不新增 StorageCensus.ets')
}
const cache = read('entry/src/main/ets/system/CachePort.ets')
if (!cache.includes('storageStatistics.getBundleStats(') || !cache.includes('bundleManager.cleanBundleCacheFiles(')) {
  problems.push('CachePort 统计走 storageStatistics.getBundleStats，清除走 bundleManager.cleanBundleCacheFiles')
}
const sdkCalls = new Set([...cache.matchAll(/\b(storageStatistics|bundleManager)\.(\w+)/g)].map((m) => m[2]))
for (const name of sdkCalls) {
  if (name !== 'getBundleStats' && name !== 'cleanBundleCacheFiles') {
    problems.push(`CachePort 不得调用未列出的接口 ${name}`)
  }
}
if (/@ohos\.file\.fs|@kit\.CoreFileKit|preferences|ResultStore|Writer/.test(cache)) {
  problems.push('CachePort 不把统计写进第二个文件')
}
const installer = read('entry/src/main/ets/system/InstallerPort.ets').replace(/\/\*[\s\S]*?\*\/|\/\/.*$/gm, '')
if (/from '\.\/SystemGate'|ABSENT|getAllBundleInfo/.test(installer) || (installer.match(/\.uninstall\(/g) || []).length !== 1) {
  problems.push('InstallerPort.uninstall 只执行卸载，不做探测')
}
const gate = read('entry/src/main/ets/system/SystemGate.ets')
if (!gate.includes("await tool.uninstall(ABSENT_BUNDLE)")) {
  problems.push('不改 SystemGate.uninstall() 的探测')
}
const grant = read('entry/src/main/ets/system/FileGrant.ets')
if (!grant.includes('fileShare.persistPermission(') || !grant.includes('this.gate.invalidate()')) {
  problems.push('FileGrant 持久化走 fileShare.persistPermission，写入或删除后调用 SystemGate.invalidate()')
}
if (problems.length > 0) {
  process.stderr.write(problems.join('\n') + '\n')
  process.exit(1)
}

const mocks = {
  'abilityAccessCtrl': `export default { GrantStatus: { PERMISSION_GRANTED: 0 }, createAtManager() { return {}; } };`,
  'privacyManager': `export default {};`,
  'huks': `export default {};`,
  'bundleManager': `export default {
  BundleFlag: { GET_BUNDLE_INFO_DEFAULT: 0, GET_BUNDLE_INFO_WITH_APPLICATION: 1 },
  get cleanBundleCacheFiles() { return sdk().cleanBundleCacheFiles; }
};`,
  'storageStatistics': `export default {
  get getBundleStats() { return sdk().getBundleStats; }
};`,
  'installer': `export default {
  getBundleInstaller() { sdk().calls.push(['getBundleInstaller']); return Promise.resolve(sdk().installer); }
};`,
  'fileshare': `export default {
  OperationMode: { READ_MODE: 0b1, WRITE_MODE: 0b10 },
  get persistPermission() { return sdk().persistPermission; },
  get activatePermission() { return sdk().activatePermission; },
  get revokePermission() { return sdk().revokePermission; }
};`,
  'ability': `export const common = {};`,
  'arkdata': `export const preferences = {
  getPreferencesSync(ctx, options) { sdk().calls.push(['getPreferencesSync', options]); return sdk().pref; }
};`
}
const modules = {
  '@ohos.abilityAccessCtrl': 'abilityAccessCtrl',
  '@ohos.privacyManager': 'privacyManager',
  '@ohos.security.huks': 'huks',
  '@ohos.bundle.bundleManager': 'bundleManager',
  '@ohos.file.storageStatistics': 'storageStatistics',
  '@ohos.bundle.installer': 'installer',
  '@ohos.fileshare': 'fileshare',
  '@kit.AbilityKit': 'ability',
  '@kit.ArkData': 'arkdata'
}

function prepare(text) {
  return text.replace(/\r\n/g, '\n')
    .replace(/^import type [^;]*?from '[^']+'\n?/gms, '')
    .replace(/from '(@[^']+)'/g, (original, name) => {
      if (name === '@kit.PerformanceAnalysisKit') return "from './hilog-sdk.mjs'"
      return modules[name] ? `from './${modules[name]}-sdk.mjs'` : original
    })
    .replace(/from '(\.{1,2}\/[^']+)'/g, (original, path) => {
      if (path.endsWith('.mjs')) return original
      return `from './${path.split('/').at(-1)}.ts'`
    })
}

const store = read('entry/src/main/ets/record/CenterStore.ets')
const storeConsts = store.split('\n').filter((line) => /^export const (preferencesName|grantsKey)\b/.test(line))
if (storeConsts.length !== 2) {
  process.stderr.write('CenterStore 缺少 preferencesName 或 grantsKey\n')
  process.exit(1)
}

const dir = mkdtempSync(join(tmpdir(), 'system-ports-'))
try {
  const prelude = 'const sdk = () => globalThis.__sdk;\n'
  for (const [name, body] of Object.entries(mocks)) {
    writeFileSync(join(dir, `${name}-sdk.mjs`), prelude + body + '\n')
  }
  writeFileSync(join(dir, 'hilog-sdk.mjs'), `export const hilog = {
  info(d, t, ...m) { (globalThis.__hilog ??= []).push(m.join(' ')); },
  warn(d, t, ...m) { (globalThis.__hilog ??= []).push(m.join(' ')); },
  error(d, t, ...m) { (globalThis.__hilog ??= []).push(m.join(' ')); }
};
`)
  writeFileSync(join(dir, 'CenterStore.ts'), storeConsts.join('\n') + '\n')
  for (const [from, to] of files) {
    writeFileSync(join(dir, to), prepare(read(from)))
  }
  writeFileSync(join(dir, 'main.ts'), `
import assert from 'node:assert/strict';
import { runSystemPortsChecks } from './SystemPorts.test.ts';
import { CachePort, SdkCacheSource } from './CachePort.ts';
import { FileGrants, PreferencesGrantStore, SdkGrantPersist } from './FileGrant.ts';
import { GatedInstallerPort, sdkUninstallTool } from './InstallerPort.ts';
import { gateOf } from './SystemGate.ts';

function fresh() {
  globalThis.__sdk = { calls: [] };
  globalThis.__hilog = [];
  return globalThis.__sdk;
}
function stubGate() {
  const g = { refused: [], invalidations: 0 };
  for (const id of ['cacheStats', 'clearCache', 'persistFileGrant']) {
    g[id] = () => gateOf(id, g.refused.some((r) => r.startsWith(id + '=')) ? 'unsupported' : 'ready', '');
  }
  g.refuse = (id, reason) => g.refused.push(id + '=' + reason);
  g.invalidate = () => { g.invalidations++; };
  return g;
}

fresh();
await runSystemPortsChecks();

let sdk = fresh();
sdk.getBundleStats = (name) => { sdk.calls.push(['getBundleStats', name]); return Promise.resolve({ appSize: 7, cacheSize: 4096, dataSize: 9 }); };
sdk.cleanBundleCacheFiles = (name) => { sdk.calls.push(['cleanBundleCacheFiles', name]); return Promise.resolve(); };
const cacheSource = new SdkCacheSource();
assert.equal(await cacheSource.cacheBytes('com.example.a'), 4096, '只用 getBundleStats 里的缓存字节');
await cacheSource.clear('com.example.a');
assert.deepEqual(sdk.calls, [['getBundleStats', 'com.example.a'], ['cleanBundleCacheFiles', 'com.example.a']]);

sdk = fresh();
let g = stubGate();
const missing = new CachePort(g, g, new SdkCacheSource());
await assert.rejects(missing.stats('com.example.a'), (err) => err.code === 'unsupported' && err.raw === 'getBundleStats:801');
await assert.rejects(missing.clear('com.example.a'), (err) => err.code === 'unsupported' && err.raw === 'cleanBundleCacheFiles:801');
assert.deepEqual(g.refused, ['cacheStats=getBundleStats:801', 'clearCache=cleanBundleCacheFiles:801'],
  'SDK 里方法不存在时对应 Gate 为 unsupported');

sdk = fresh();
sdk.persistPermission = (p) => { sdk.calls.push(['persist', p]); return Promise.resolve(); };
sdk.activatePermission = (p) => { sdk.calls.push(['activate', p]); return Promise.resolve(); };
sdk.revokePermission = (p) => { sdk.calls.push(['revoke', p]); return Promise.resolve(); };
const persist = new SdkGrantPersist();
const uri = 'file:///storage/Users/currentUser/Download';
await persist.persist(uri);
await persist.activate(uri);
await persist.release(uri);
assert.deepEqual(sdk.calls, [
  ['persist', [{ uri, operationMode: 1 }]],
  ['activate', [{ uri, operationMode: 1 }]],
  ['revoke', [{ uri, operationMode: 1 }]]
], '只申请读权限');

sdk = fresh();
g = stubGate();
const values = new Map();
sdk.pref = {
  getSync(key, def) { sdk.calls.push(['getSync', key]); return values.has(key) ? values.get(key) : def; },
  putSync(key, value) { sdk.calls.push(['putSync', key]); values.set(key, value); },
  flush() { sdk.calls.push(['flush']); return Promise.resolve(); }
};
const grants = new FileGrants(g, g, new PreferencesGrantStore({}), new SdkGrantPersist(), () => 't');
await assert.rejects(grants.remember(uri, 'Download'), (err) => err.code === 'unsupported' && err.raw === 'persistPermission:801');
assert.deepEqual(g.refused, ['persistFileGrant=persistPermission:801'], 'persistPermission 不存在时 persistFileGrant() 为 unsupported');
assert.ok(!sdk.calls.some((c) => c[0] === 'putSync'), '方法不存在时不写 center.grants');
assert.deepEqual(sdk.calls[0], ['getPreferencesSync', { name: 'jinyinhu' }]);

sdk.persistPermission = () => Promise.resolve();
g.refused = [];
await grants.remember(uri, 'Download');
assert.deepEqual(sdk.calls.filter((c) => c[0] !== 'getSync').slice(-2), [['putSync', 'center.grants'], ['flush']]);
assert.equal(JSON.parse(values.get('center.grants'))[0].uri, uri);

sdk = fresh();
sdk.installer = { uninstall(name) { sdk.calls.push(['uninstall', name]); return Promise.resolve(); } };
await new GatedInstallerPort(sdkUninstallTool).uninstall('com.example.a');
assert.deepEqual(sdk.calls, [['getBundleInstaller'], ['uninstall', 'com.example.a']], '只调用 installer.uninstall');

process.stdout.write('FileGrant, CachePort and InstallerPort checks passed\\n');
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
