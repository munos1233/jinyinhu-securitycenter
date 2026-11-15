import { spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../../..')
const ported = [
  'entry/src/main/ets/system/SystemGate.ets',
  'entry/src/main/ets/system/BundleCensus.ets',
  'entry/src/main/ets/system/PosturePort.ets'
]
const files = [
  ['entry/src/main/ets/center/CenterTypes.ets', 'CenterTypes.ts'],
  ['entry/src/main/ets/center/CenterLimits.ets', 'CenterLimits.ts'],
  ['entry/src/main/ets/center/CenterError.ets', 'CenterError.ts'],
  ['entry/src/main/ets/center/PostureRule.ets', 'PostureRule.ts'],
  ['entry/src/main/ets/engine/LocalRuleEngine.ets', 'LocalRuleEngine.ts'],
  ['entry/src/main/ets/engine/Lookalike.ets', 'Lookalike.ts'],
  ['entry/src/main/ets/engine/Heuristic.ets', 'Heuristic.ts'],
  ['entry/src/main/ets/engine/Decide.ets', 'Decide.ts'],
  ['entry/src/main/ets/engine/BundleFinger.ets', 'BundleFinger.ts'],
  ['entry/src/main/ets/system/SystemGate.ets', 'SystemGate.ts'],
  ['entry/src/main/ets/system/BundleCensus.ets', 'BundleCensus.ts'],
  ['entry/src/main/ets/system/PosturePort.ets', 'PosturePort.ts'],
  ['entry/src/test/SystemGate.test.ets', 'SystemGate.test.ts']
]

const problems = []
for (const path of ported) {
  const source = readFileSync(resolve(root, path), 'utf8')
  if (!source.includes('const DOMAIN: number = 0x4A59') || !source.includes("const TAG: string = 'Center'")) {
    problems.push(`${path} 的 hilog 域必须是 0x4A59，标签 Center`)
  }
  if (source.includes('/sys/kernel/security/lockdown')) {
    problems.push(`${path} 不得打开 /sys/kernel/security/lockdown`)
  }
  if (/child_process|@ohos\.process|\.exec\(|\bspawn\(|\/bin\/sh/.test(source)) {
    problems.push(`${path} 不得执行 shell`)
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
const posture = readFileSync(resolve(root, 'entry/src/main/ets/system/PosturePort.ets'), 'utf8')
if (posture.includes('SystemGate') || posture.includes('posture()')) {
  problems.push('PosturePort 三项不看 SystemGate.posture()')
}
if (/=== 'confidentiality'|=== '1'/.test(posture)) {
  problems.push('PosturePort 必须调用 pureModeOk / lockdownOk，不得另写一套比较')
}
const census = readFileSync(resolve(root, 'entry/src/main/ets/system/BundleCensus.ets'), 'utf8')
if (!census.includes('GET_BUNDLE_INFO_WITH_SIGNATURE_INFO')) {
  problems.push('BundleCensus 列出时必须带 GET_BUNDLE_INFO_WITH_SIGNATURE_INFO')
}
if (/'sideload'/.test(census)) {
  problems.push('BundleCensus 不得产出 sideload')
}
if (problems.length > 0) {
  process.stderr.write(problems.join('\n') + '\n')
  process.exit(1)
}

const mocks = {
  'abilityAccessCtrl': `export default {
  GrantStatus: { PERMISSION_GRANTED: 0, PERMISSION_DENIED: -1 },
  createAtManager() { return {
    getPermissionFlags() {}, revokeUserGrantedPermission() {},
    checkAccessTokenSync(token, permission) { return sdk().granted.includes(permission) && token === 7 ? 0 : -1; }
  }; }
};`,
  'bundleManager': `export default {
  BundleFlag: { GET_BUNDLE_INFO_DEFAULT: 0, GET_BUNDLE_INFO_WITH_APPLICATION: 1,
    GET_BUNDLE_INFO_WITH_REQUESTED_PERMISSION: 0x10, GET_BUNDLE_INFO_WITH_SIGNATURE_INFO: 0x80 },
  getAllBundleInfo(flags) { sdk().listFlags.push(flags); return sdk().getAllBundleInfo(flags); },
  getBundleInfo(name, flags) { sdk().infoFlags.push(flags); return sdk().getBundleInfo(name, flags); },
  getBundleInfoForSelfSync() { return { name: 'com.jinyinhu.securitycenter', appInfo: { accessTokenId: 7 } }; },
  cleanBundleCacheFiles() { throw new Error('探测不得真的清缓存'); }
};`,
  'installer': `export default {
  getBundleInstaller() { return Promise.resolve({ uninstall(name) { sdk().uninstalled.push(name); return sdk().uninstall(name); } }); }
};`,
  'storageStatistics': `export default { getBundleStats(name) { return sdk().getBundleStats(name); } };`,
  'fileshare': `export default { persistPermission() { throw new Error('探测不得真的持久化授权'); } };`,
  'privacyManager': `export default { getPermissionUsedRecord() { throw new Error('unused'); } };`,
  'huks': `export default {
  HuksTag: { HUKS_TAG_ALGORITHM: 1, HUKS_TAG_KEY_SIZE: 2, HUKS_TAG_PURPOSE: 3 },
  HuksKeyAlg: { HUKS_ALG_AES: 20 }, HuksKeySize: { HUKS_AES_KEY_SIZE_256: 256 },
  HuksKeyPurpose: { HUKS_KEY_PURPOSE_ENCRYPT: 1, HUKS_KEY_PURPOSE_DECRYPT: 2 },
  generateKeyItem(alias) { return sdk().huksGenerate(alias); },
  deleteKeyItem(alias) { sdk().huksDeleted.push(alias); return Promise.resolve(); }
};`,
  'util': `export default { Base64Helper: class { decodeSync(text) { return new Uint8Array(Buffer.from(text, 'base64')); } } };`,
  'systemParameterEnhance': `export default { getSync(key) { sdk().paramKeys.push(key); return sdk().getSync(key); } };`,
  'screenLockFileManager': `const api = { queryAppKeyState() { return sdk().queryAppKeyState(); } };
export default new Proxy(api, { get(target, name) { return sdk().noKeyQuery && name === 'queryAppKeyState' ? undefined : target[name]; } });`,
  'cryptoFramework': `import { createHash } from 'node:crypto';
export default { createMd(name) { const hash = createHash(name.toLowerCase()); return {
  updateSync(input) { hash.update(input.data); }, digestSync() { return { data: new Uint8Array(hash.digest()) }; }
}; } };`
}
const modules = {
  '@ohos.abilityAccessCtrl': 'abilityAccessCtrl',
  '@ohos.bundle.bundleManager': 'bundleManager',
  '@ohos.bundle.installer': 'installer',
  '@ohos.file.storageStatistics': 'storageStatistics',
  '@ohos.fileshare': 'fileshare',
  '@ohos.privacyManager': 'privacyManager',
  '@ohos.security.huks': 'huks',
  '@ohos.util': 'util',
  '@ohos.systemParameterEnhance': 'systemParameterEnhance',
  '@ohos.ability.screenLockFileManager': 'screenLockFileManager',
  '@ohos.security.cryptoFramework': 'cryptoFramework'
}

function prepare(source) {
  return source.replace(/\r\n/g, '\n')
    .replace(/^import type [^\n]*\n/gm, '')
    .replace(/from '(@[^']+)'/g, (original, name) => {
      if (name === '@kit.PerformanceAnalysisKit') return "from './hilog-sdk.mjs'"
      return modules[name] ? `from './${modules[name]}-sdk.mjs'` : original
    })
    .replace(/from '(\.{1,2}\/[^']+)'/g, (original, path) => {
      if (path.endsWith('.mjs')) return original
      return `from './${path.split('/').at(-1)}.ts'`
    })
}

const dir = mkdtempSync(join(tmpdir(), 'system-gate-'))
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
  for (const [from, to] of files) {
    writeFileSync(join(dir, to), prepare(readFileSync(resolve(root, from), 'utf8')))
  }
  writeFileSync(join(dir, 'main.ts'), `
import assert from 'node:assert/strict';
import { runSystemGateChecks } from './SystemGate.test.ts';
import { SdkGateProbes } from './SystemGate.ts';
import { SdkBundleSource } from './BundleCensus.ts';
import { SdkEl5Query, SdkParamReader } from './PosturePort.ts';

function reject(code) { const err = new Error('sdk ' + code); err.code = code; return Promise.reject(err); }
function thrown(code) { const err = new Error('sdk ' + code); err.code = code; throw err; }
function fresh() {
  globalThis.__sdk = {
    granted: [], listFlags: [], infoFlags: [], uninstalled: [], paramKeys: [], huksDeleted: [], noKeyQuery: false,
    getAllBundleInfo: () => Promise.resolve([]), getBundleInfo: () => reject(17700001),
    uninstall: () => reject(17700001), getBundleStats: () => Promise.resolve({ cacheSize: 0 }),
    huksGenerate: () => Promise.resolve(), getSync: () => thrown(14700101), queryAppKeyState: () => 0
  };
  globalThis.__hilog = [];
  return globalThis.__sdk;
}

fresh();
await runSystemGateChecks();

const probes = new SdkGateProbes();
let sdk = fresh();
assert.equal((await probes.uninstall()).status, 'ready', '包不存在说明权限校验已通过，uninstall 为 ready');
assert.deepEqual(sdk.uninstalled, ['com.jinyinhu.securitycenter.gate.absent'], '探测只卸载一个不存在的包名');
sdk.uninstall = () => reject(201);
let gate = await probes.uninstall();
assert.equal(gate.status, 'unsupported');
assert.equal(gate.reason, 'uninstall:201');
sdk.uninstall = () => reject(202);
assert.equal((await probes.uninstall()).status, 'unsupported', '非系统应用调用被拒');
sdk.uninstall = () => reject(17700020);
assert.equal((await probes.uninstall()).status, 'ready', '只缺 UNINSTALL_BUNDLE 时不得判 unsupported');

sdk = fresh();
assert.equal((await probes.bundles()).status, 'ready');
assert.deepEqual(sdk.listFlags, [0]);
sdk.getAllBundleInfo = () => reject(201);
gate = await probes.bundles();
assert.equal(gate.status, 'unsupported', 'GET_INSTALLED_BUNDLE_LIST 未授予时 bundles() 是 unsupported');
assert.equal(gate.reason, 'getAllBundleInfo:201');

sdk = fresh();
assert.equal((await probes.grants()).status, 'unsupported');
assert.equal((await probes.revoke()).status, 'unsupported', '没写进 ACL 时 revoke() 保持 unsupported');
sdk.granted = ['ohos.permission.GET_SENSITIVE_PERMISSIONS', 'ohos.permission.REVOKE_SENSITIVE_PERMISSIONS',
  'ohos.permission.PERMISSION_USED_STATS', 'ohos.permission.REMOVE_CACHE_FILES'];
for (const name of ['grants', 'revoke', 'usedStats', 'clearCache']) {
  assert.equal((await probes[name]()).status, 'ready', name + ' 在已授予时为 ready');
}
assert.equal((await probes.persistFileGrant()).status, 'unsupported', '没有 FILE_ACCESS_PERSIST 时不能记住目录');
assert.equal((await probes.cacheStats()).status, 'ready');
sdk.getBundleStats = () => reject(201);
assert.equal((await probes.cacheStats()).status, 'unsupported');
assert.equal((await probes.posture()).status, 'unsupported', '本轮不实现态势服务');
assert.equal((await probes.huks()).status, 'ready');
assert.deepEqual(sdk.huksDeleted, ['jyh.center.gate.probe'], 'huks 探测用完即删');
sdk.huksGenerate = () => reject(12000001);
assert.equal((await probes.huks()).status, 'unsupported');

sdk = fresh();
const pem = '-----BEGIN CERTIFICATE-----\\n' + Buffer.from('cert-bytes').toString('base64') + '\\n-----END CERTIFICATE-----\\n';
sdk.getAllBundleInfo = () => Promise.resolve([
  { name: 'com.example.a', versionName: '2.1', versionCode: 21, reqPermissionDetails: [{ name: 'ohos.permission.CAMERA' }],
    signatureInfo: { fingerprint: 'AB:CD', certificate: pem }, appInfo: { installSource: 'pre-installed' } },
  { name: 'com.example.b', versionName: '1', versionCode: 1, reqPermissionDetails: [],
    signatureInfo: { fingerprint: '' }, appInfo: {} }
]);
const source = new SdkBundleSource();
const raws = await source.listAll();
assert.equal(sdk.listFlags.length, 1);
assert.ok((sdk.listFlags[0] & 0x80) !== 0, '列出时必须带 GET_BUNDLE_INFO_WITH_SIGNATURE_INFO');
assert.ok((sdk.listFlags[0] & 0x10) !== 0, '列出时要带声明权限');
assert.ok((sdk.listFlags[0] & 0x01) !== 0, '列出时要带 ApplicationInfo 以读安装来源');
assert.equal(raws[0].fingerprint, 'AB:CD');
assert.equal(Buffer.from(raws[0].certificate).toString(), 'cert-bytes', 'PEM 证书要解成证书字节');
assert.deepEqual(raws[0].permissions, ['ohos.permission.CAMERA']);
assert.equal(raws[0].hasInstallSource, true);
assert.equal(raws[0].installSource, 'pre-installed');
assert.equal(raws[1].hasInstallSource, false, '运行时没有 installSource 字段要如实标出');
assert.equal(raws[1].certificate.length, 0);
sdk.getBundleInfo = () => Promise.resolve({ signatureInfo: { fingerprint: 'EF' } });
assert.equal((await source.signatureOf('com.example.b')).fingerprint, 'EF');
assert.deepEqual(sdk.infoFlags, [0x80], '补证书按包名带签名标志');

sdk = fresh();
const params = new SdkParamReader();
let read = params.read('persist.jyh.pure_mode');
assert.equal(read.outcome, 'missing', '14700101 是参数不存在');
sdk.getSync = () => thrown(14700103);
read = params.read('persist.jyh.pure_mode');
assert.equal(read.outcome, 'failed');
assert.equal(read.reason, '14700103');
sdk.getSync = (key) => key === 'persist.jyh.pure_mode' ? '1' : thrown(14700101);
read = params.read('persist.jyh.pure_mode');
assert.equal(read.outcome, 'value');
assert.equal(read.value, '1');

const el5 = new SdkEl5Query();
assert.equal(el5.query().outcome, 'present', '查询接口有答复，服务在');
sdk.queryAppKeyState = () => thrown(801);
assert.equal(el5.query().outcome, 'absent', '系统答复没有该能力，服务不在');
sdk.queryAppKeyState = () => thrown(29300002);
assert.equal(el5.query().outcome, 'failed');
sdk.noKeyQuery = true;
assert.equal(el5.query().outcome, 'no-interface', '没有查询接口才是 unsupported');

process.stdout.write('SystemGate, BundleCensus and PosturePort checks passed\\n');
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
