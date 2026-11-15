import { spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../../..')
const ported = 'entry/src/main/ets/cloud/ReputationClient.ets'
const files = [
  ['entry/src/main/ets/center/CenterTypes.ets', 'CenterTypes.ts'],
  ['entry/src/main/ets/center/CenterLimits.ets', 'CenterLimits.ts'],
  ['entry/src/main/ets/cloud/ResponseCheck.ets', 'ResponseCheck.ts'],
  ['entry/src/main/ets/cloud/ReputationClient.ets', 'ReputationClient.ts'],
  ['entry/src/test/ReputationClient.test.ets', 'ReputationClient.test.ts']
]

const problems = []
const source = readFileSync(resolve(root, ported), 'utf8')
const code = source.replace(/\/\*[\s\S]*?\*\/|\/\/.*$/gm, '')
if (!source.includes('const DOMAIN: number = 0x4A59') || !source.includes("const TAG: string = 'Center'")) {
  problems.push(`${ported} 的 hilog 域必须是 0x4A59，标签 Center`)
}
if (/\bDate\b|systemDateTime|systemTime/.test(code)) {
  problems.push('nonce 和防重放不用设备时钟')
}
if (!code.includes('cloudTimeoutMs')) {
  problems.push('超时用 cloudTimeoutMs')
}
if (/from '\.\.\/(pages|task|feature)\//.test(source)) {
  problems.push(`${ported} 不得 import 页面、任务或功能模块`)
}
if (/\bnonce\s*=\s*this\.|private\s+nonce|static\s+nonce/.test(code)) {
  problems.push('禁止进程内单槽 nonce')
}
for (const banned of ['已安全', '云查杀已开启', '已防护', '已拦截', '人工智能引擎已防护', '未配置云公钥', '云响应未通过校验']) {
  if (source.includes(banned)) {
    problems.push(`${ported} 出现了禁用文案「${banned}」`)
  }
}
if (problems.length > 0) {
  process.stderr.write(problems.join('\n') + '\n')
  process.exit(1)
}

const mocks = {
  'crypto': `import { createPublicKey, randomBytes, verify } from 'node:crypto';
export default {
  createRandom() { return { generateRandomSync(n) { (globalThis.__random ??= []).push(n); return { data: new Uint8Array(randomBytes(n)) }; } }; },
  createAsyKeyGenerator(alg) {
    if (alg !== 'ECC256') throw new Error('unexpected key alg ' + alg);
    return { convertKeySync(pub, pri) {
      if (pri !== null) throw new Error('only public key');
      return { pubKey: createPublicKey({ key: Buffer.from(pub.data), format: 'der', type: 'spki' }) };
    } };
  },
  createVerify(alg) {
    if (alg !== 'ECC256|SHA256') throw new Error('unexpected verify alg ' + alg);
    let key = null;
    return {
      initSync(k) { key = k; },
      verifySync(input, sig) { return verify('sha256', Buffer.from(input.data), key, Buffer.from(sig.data)); }
    };
  }
};`,
  'util': `export default {
  Base64Helper: class { decodeSync(text) { return new Uint8Array(Buffer.from(text, 'base64')); } }
};`,
  'http': `export default {
  RequestMethod: { POST: 'POST' },
  HttpDataType: { STRING: 0 },
  createHttp() {
    const client = { destroyed: 0, request(url, options) {
      sdk().requests.push({ url, options });
      return sdk().respond(url, options);
    }, destroy() { client.destroyed++; } };
    sdk().clients.push(client);
    return client;
  }
};`
}
const modules = {
  '@ohos.security.cryptoFramework': 'crypto',
  '@ohos.util': 'util',
  '@ohos.net.http': 'http'
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

const dir = mkdtempSync(join(tmpdir(), 'reputation-client-'))
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
import { generateKeyPairSync, sign } from 'node:crypto';
import { runReputationClientChecks } from './ReputationClient.test.ts';
import { HttpCloudTransport, INVALID, ReputationClient, SystemTimer } from './ReputationClient.ts';

globalThis.__sdk = { requests: [], clients: [], respond: () => Promise.reject(new Error('no network')) };
await runReputationClientChecks();

const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const pem = publicKey.export({ type: 'spki', format: 'pem' });
const config = { endpoint: () => 'https://reputation.example/', publicKey: () => pem };
let signWith = privateKey;
const server = (url, body) => {
  const request = JSON.parse(body);
  const items = request.items.map((k) => ({ ...k, level: 'risk', reason: '演示', evidence: 'demo' }));
  const text = request.nonce + '\\n2026.11.15\\n' +
    items.map((i) => [i.bundleName, i.versionCode, i.certSha256, i.sha256, i.level, i.reason, i.evidence].join('|')).join('\\n');
  const signature = sign('sha256', Buffer.from(text, 'utf8'), signWith).toString('base64');
  return { responseCode: 200, result: JSON.stringify({ alg: 'SHA256withECDSA', kid: 'primary', nonce: request.nonce,
    version: '2026.11.15', items, signature }) };
};
globalThis.__sdk = { requests: [], clients: [], respond: (url, options) => Promise.resolve(server(url, options.extraData)) };
const client = new ReputationClient(config, new HttpCloudTransport(), () => false);
const keys = [{ bundleName: 'com.example.risk', versionCode: 3, certSha256: 'ab'.repeat(32), sha256: '' }];
let views = await client.query(keys, {});
assert.equal(views[0].state, 'reached', '真实 ECDSA P-256 签名经默认验签通过');
assert.equal(views[0].level, 'risk');
assert.equal(views[0].reason, '演示');
const req = globalThis.__sdk.requests[0];
assert.equal(req.url, 'https://reputation.example/reputation/query', '服务地址去掉结尾斜杠后拼接路径');
assert.equal(req.options.method, 'POST');
assert.equal(req.options.header['Content-Type'], 'application/json');
assert.equal(req.options.connectTimeout, 5000, '连接超时用 cloudTimeoutMs');
assert.equal(req.options.readTimeout, 5000, '读取超时用 cloudTimeoutMs');
assert.equal(req.options.usingCache, false);
assert.match(JSON.parse(req.options.extraData).nonce, /^[0-9a-f]{32}$/);
assert.deepEqual(globalThis.__random, [16], '默认 nonce 取 16 字节安全随机数');
assert.equal(globalThis.__sdk.clients[0].destroyed, 1, '请求结束后释放 http 对象，只释放一次');

await client.query(keys, {});
assert.notEqual(JSON.parse(globalThis.__sdk.requests[1].options.extraData).nonce, JSON.parse(req.options.extraData).nonce);

signWith = generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey;
views = await client.query(keys, {});
assert.equal(views[0].state, 'offline', '别的私钥签的响应整批拒绝');
assert.equal(views[0].reason, INVALID);

const broken = new ReputationClient({ endpoint: () => 'https://reputation.example', publicKey: () => 'not a key' },
  new HttpCloudTransport(), () => false);
signWith = privateKey;
views = await broken.query(keys, {});
assert.equal(views[0].state, 'offline', '公钥读不出时不产生云端结论');
assert.equal(views[0].reason, INVALID);

globalThis.__sdk = { requests: [], clients: [], respond: () => new Promise(() => {}) };
const call = new HttpCloudTransport().post('https://reputation.example/reputation/query', '{}', 5000);
call.abort();
call.abort();
assert.equal(globalThis.__sdk.clients[0].destroyed, 1, '中止时释放 http 对象一次');

const timer = new SystemTimer();
let fired = false;
const handle = timer.start(1, () => { fired = true; });
timer.stop(handle);
await new Promise((r) => setTimeout(r, 10));
assert.equal(fired, false, 'stop 之后计时器不再触发');

process.stdout.write('ReputationClient checks passed\\n');
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
