import { spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../../..')
const ported = 'entry/src/main/ets/system/AccessPort.ets'
const files = [
  ['entry/src/main/ets/center/CenterTypes.ets', 'CenterTypes.ts'],
  ['entry/src/main/ets/center/CenterLimits.ets', 'CenterLimits.ts'],
  ['entry/src/main/ets/center/CenterError.ets', 'CenterError.ts'],
  ['entry/src/main/ets/center/SensitiveCatalog.ets', 'SensitiveCatalog.ts'],
  ['entry/src/main/ets/system/SystemGate.ets', 'SystemGate.ts'],
  ['entry/src/main/ets/system/AccessPort.ets', 'AccessPort.ts'],
  ['entry/src/test/AccessPort.test.ets', 'AccessPort.test.ts']
]

const problems = []
const source = readFileSync(resolve(root, ported), 'utf8')
if (!source.includes('const DOMAIN: number = 0x4A59') || !source.includes("const TAG: string = 'Center'")) {
  problems.push(`${ported} 的 hilog 域必须是 0x4A59，标签 Center`)
}
if (source.includes('getHapTokenID')) {
  problems.push('tokenId 只来自 ApplicationInfo.accessTokenId，不调用 getHapTokenID')
}
if (!source.includes('accessTokenId')) {
  problems.push('tokenId 必须读 ApplicationInfo.accessTokenId')
}
const revokeCalls = source.match(/revokeUserGrantedPermission\([^)]*\)/g) || []
if (revokeCalls.length !== 1 || !revokeCalls[0].includes('PERMISSION_USER_FIXED')) {
  problems.push('撤权调用点的第三个参数必须写成 PERMISSION_USER_FIXED')
}
if (revokeCalls.some((call) => /PERMISSION_USER_SET|,\s*0\s*\)/.test(call))) {
  problems.push('撤权不得传 0 或 PERMISSION_USER_SET')
}
if (!source.includes('export const PERMISSION_USER_FIXED: number = 1 << 1')) {
  problems.push('PERMISSION_USER_FIXED 必须是 1 << 1')
}
if (/from '\.\.\/(pages|task|feature)\//.test(source)) {
  problems.push(`${ported} 系统端口不得 import 页面、任务或功能模块`)
}
for (const banned of ['已安全', '云查杀已开启', '已防护', '已拦截', '人工智能引擎已防护']) {
  if (source.includes(banned)) {
    problems.push(`${ported} 出现了禁用文案「${banned}」`)
  }
}
if (problems.length > 0) {
  process.stderr.write(problems.join('\n') + '\n')
  process.exit(1)
}

const mocks = {
  'abilityAccessCtrl': `export default {
  GrantStatus: { PERMISSION_GRANTED: 0, PERMISSION_DENIED: -1 },
  createAtManager() { return {
    checkAccessTokenSync() { return 0; },
    getHapTokenID() { throw new Error('不得调用 getHapTokenID'); },
    getPermissionsStatus(token, list) { sdk().calls.push(['status', token, list.slice()]); return sdk().status(token, list); },
    getPermissionFlags(token, name) { sdk().calls.push(['flags', token, name]); return sdk().flags(token, name); },
    revokeUserGrantedPermission(token, name, flags) { sdk().calls.push(['revoke', token, name, flags]); return Promise.resolve(); }
  }; }
};`,
  'bundleManager': `export default {
  BundleFlag: { GET_BUNDLE_INFO_DEFAULT: 0, GET_BUNDLE_INFO_WITH_APPLICATION: 1,
    GET_BUNDLE_INFO_WITH_REQUESTED_PERMISSION: 0x10, GET_BUNDLE_INFO_WITH_SIGNATURE_INFO: 0x80 },
  getBundleInfo(name, flags) { sdk().calls.push(['info', name, flags]); return sdk().getBundleInfo(name, flags); }
};`,
  'privacyManager': `export default {
  PermissionUsageFlag: { FLAG_PERMISSION_USAGE_SUMMARY: 0, FLAG_PERMISSION_USAGE_DETAIL: 1 },
  getPermissionUsedRecord(request) { sdk().calls.push(['used', request]); return sdk().used(request); }
};`,
  'installer': `export default {};`,
  'storageStatistics': `export default {};`,
  'fileshare': `export default {};`,
  'huks': `export default {};`
}
const modules = {
  '@ohos.abilityAccessCtrl': 'abilityAccessCtrl',
  '@ohos.bundle.bundleManager': 'bundleManager',
  '@ohos.privacyManager': 'privacyManager',
  '@ohos.bundle.installer': 'installer',
  '@ohos.file.storageStatistics': 'storageStatistics',
  '@ohos.fileshare': 'fileshare',
  '@ohos.security.huks': 'huks'
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

const dir = mkdtempSync(join(tmpdir(), 'access-port-'))
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
import { runAccessPortChecks } from './AccessPort.test.ts';
import { AccessPort, SdkAccessSource } from './AccessPort.ts';
import { gateOf } from './SystemGate.ts';

function reject(code) { const err = new Error('sdk ' + code); err.code = code; return Promise.reject(err); }
function fresh() {
  globalThis.__sdk = {
    calls: [],
    getBundleInfo: () => reject(17700001),
    status: (token, list) => Promise.resolve(list.map(() => 0)),
    flags: () => Promise.resolve(0),
    used: () => Promise.resolve({ bundleRecords: [] })
  };
  globalThis.__hilog = [];
  return globalThis.__sdk;
}

fresh();
await runAccessPortChecks();

const sdkSource = new SdkAccessSource();
let sdk = fresh();
sdk.getBundleInfo = () => Promise.resolve({ name: 'com.example.a',
  appInfo: { accessTokenId: 537, label: '示例' },
  reqPermissionDetails: [{ name: 'ohos.permission.CAMERA' }, { name: 'ohos.permission.INTERNET' }] });
let raw = await sdkSource.bundleOf('com.example.a');
assert.equal(raw.tokenId, 537, 'tokenId 来自 ApplicationInfo.accessTokenId');
assert.equal(raw.label, '示例');
assert.deepEqual(raw.permissions, ['ohos.permission.CAMERA', 'ohos.permission.INTERNET']);
assert.equal(sdk.calls[0][0], 'info');
assert.ok((sdk.calls[0][2] & 0x01) !== 0, '读 tokenId 要带 GET_BUNDLE_INFO_WITH_APPLICATION');
assert.ok((sdk.calls[0][2] & 0x10) !== 0, '读声明权限要带 GET_BUNDLE_INFO_WITH_REQUESTED_PERMISSION');

sdk.getBundleInfo = () => Promise.resolve({ name: 'com.example.b', appInfo: { label: '$string:app_name' } });
raw = await sdkSource.bundleOf('com.example.b');
assert.equal(raw.tokenId, 0, 'accessTokenId 字段不存在时 tokenId=0');
assert.equal(raw.label, '', '资源引用不当作应用名');

sdk = fresh();
sdk.getBundleInfo = () => Promise.resolve({ name: 'com.example.b', appInfo: {}, reqPermissionDetails: [] });
const gate = {
  grants: () => gateOf('grants', 'ready', ''), revoke: () => gateOf('revoke', 'ready', ''),
  usedStats: () => gateOf('usedStats', 'ready', ''), refuse() { throw new Error('不应被拒'); }
};
const port = new AccessPort(gate, gate, sdkSource, () => 1800000000000);
const facts = await port.facts([{ bundleName: 'com.example.b', declaredPermissions: ['ohos.permission.CAMERA'], source: 'unknown' }]);
assert.equal(facts[0].tokenId, 0);
assert.equal(facts[0].grant, 'unknown');
assert.deepEqual(sdk.calls.map((c) => c[0]), ['info'], 'tokenId 读不到时不调用授权接口');
await assert.rejects(port.revoke(0, 'ohos.permission.CAMERA'));
assert.deepEqual(sdk.calls.map((c) => c[0]), ['info'], 'tokenId 为 0 时不调用 revokeUserGrantedPermission');

sdk = fresh();
sdk.status = (token, list) => Promise.resolve(list.map(() => 0));
sdk.flags = () => Promise.resolve(1 << 7);
assert.deepEqual(await sdkSource.statusOf(537, ['ohos.permission.CAMERA']), [0]);
assert.equal(await sdkSource.flagsOf(537, 'ohos.permission.CAMERA'), 1 << 7);
await sdkSource.revoke(537, 'ohos.permission.CAMERA');
assert.deepEqual(sdk.calls, [
  ['status', 537, ['ohos.permission.CAMERA']],
  ['flags', 537, 'ohos.permission.CAMERA'],
  ['revoke', 537, 'ohos.permission.CAMERA', 2]
], '三个接口都用同一个 tokenId；撤权第三个参数是 PERMISSION_USER_FIXED（1 << 1）');

sdk = fresh();
sdk.used = () => Promise.resolve({ bundleRecords: [
  { bundleName: 'com.example.a', permissionRecords: [
    { permissionName: 'ohos.permission.CAMERA', lastAccessTime: 30, accessRecords: [{ timestamp: 10 }, { timestamp: 20 }] },
    { permissionName: 'ohos.permission.MICROPHONE', lastAccessTime: 40, accessRecords: [] },
    { permissionName: 'ohos.permission.LOCATION', lastAccessTime: 0 }
  ] }
] });
const uses = await sdkSource.usedSince(5, 50);
assert.equal(sdk.calls[0][1].beginTime, 5);
assert.equal(sdk.calls[0][1].endTime, 50);
assert.equal(sdk.calls[0][1].flag, 1, '取明细记录');
assert.deepEqual(uses.map((u) => [u.bundleName, u.permission, u.at]), [
  ['com.example.a', 'ohos.permission.CAMERA', 10],
  ['com.example.a', 'ohos.permission.CAMERA', 20],
  ['com.example.a', 'ohos.permission.MICROPHONE', 40]
], '有明细用明细时间，没有明细才用 lastAccessTime，没有使用过的不造记录');

process.stdout.write('AccessPort checks passed\\n');
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
