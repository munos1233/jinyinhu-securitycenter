import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { spawnSync } from 'node:child_process'
import { closeSync, ftruncateSync, mkdtempSync, openSync, readFileSync, readSync,
  realpathSync, rmSync, writeFileSync, writeSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { crc32 } from 'node:zlib'

// Optional host stress run. Kept separate from the small default check suite.
const root = resolve(dirname(fileURLToPath(import.meta.url)), '../../..')
const tempIndex = process.argv.indexOf('--temp-dir')
assert(tempIndex < 0 || process.argv[tempIndex + 1], '--temp-dir requires an existing directory')
const temporaryRoot = tempIndex < 0 ? tmpdir() : resolve(process.argv[tempIndex + 1])
const directory = mkdtempSync(join(temporaryRoot, 'hap-reader-stress-'))
const MiB = 1024 * 1024
const limit = 200 * MiB
const bundleName = 'com.test.stress'
const config = Buffer.from(JSON.stringify({ app: { bundleName, versionName: '1.0', versionCode: 1 },
  module: { requestPermissions: [{ name: 'ohos.permission.CAMERA' }] } }))

function localHeader(name, length, checksum) {
  const header = Buffer.alloc(30)
  header.writeUInt32LE(0x04034b50, 0)
  header.writeUInt16LE(20, 4)
  header.writeUInt16LE(0x800, 6)
  header.writeUInt32LE(checksum, 14)
  header.writeUInt32LE(length, 18)
  header.writeUInt32LE(length, 22)
  header.writeUInt16LE(name.length, 26)
  return Buffer.concat([header, name])
}

function centralHeader(name, length, checksum, offset) {
  const header = Buffer.alloc(46)
  header.writeUInt32LE(0x02014b50, 0)
  header.writeUInt16LE(20, 4)
  header.writeUInt16LE(20, 6)
  header.writeUInt16LE(0x800, 8)
  header.writeUInt32LE(checksum, 16)
  header.writeUInt32LE(length, 20)
  header.writeUInt32LE(length, 24)
  header.writeUInt16LE(name.length, 28)
  header.writeUInt32LE(offset, 42)
  return Buffer.concat([header, name])
}

function zeroCrc(length) {
  const chunk = Buffer.alloc(MiB)
  let checksum = 0
  for (let at = 0; at < length; at += chunk.length) {
    checksum = crc32(chunk.subarray(0, Math.min(chunk.length, length - at)), checksum)
  }
  return checksum
}

function writeAt(fd, bytes, position) {
  let written = 0
  while (written < bytes.length) {
    const count = writeSync(fd, bytes, written, bytes.length - written, position + written)
    assert(count > 0, 'fixture write must advance')
    written += count
  }
}

function archive(name, size) {
  const resourceName = Buffer.from('resource.bin')
  const configName = Buffer.from('module.json')
  const resourceLength = size - (30 + resourceName.length) - (30 + configName.length) - config.length -
    (46 + resourceName.length) - (46 + configName.length) - 22
  const checksum = zeroCrc(resourceLength)
  const resourceHeader = localHeader(resourceName, resourceLength, checksum)
  const configOffset = resourceHeader.length + resourceLength
  const moduleHeader = localHeader(configName, config.length, crc32(config))
  const centralOffset = configOffset + moduleHeader.length + config.length
  const central = Buffer.concat([centralHeader(resourceName, resourceLength, checksum, 0),
    centralHeader(configName, config.length, crc32(config), configOffset)])
  const ending = Buffer.alloc(22)
  ending.writeUInt32LE(0x06054b50, 0)
  ending.writeUInt16LE(2, 8)
  ending.writeUInt16LE(2, 10)
  ending.writeUInt32LE(central.length, 12)
  ending.writeUInt32LE(centralOffset, 16)
  const path = join(directory, name + '.hap')
  const fd = openSync(path, 'w+')
  const digest = createHash('sha256')
  try {
    // The zero-filled resource may occupy a sparse extent. Every test still
    // reads all its logical bytes through actual fs.readSync calls.
    ftruncateSync(fd, size)
    writeAt(fd, resourceHeader, 0)
    writeAt(fd, moduleHeader, configOffset)
    writeAt(fd, config, configOffset + moduleHeader.length)
    writeAt(fd, central, centralOffset)
    writeAt(fd, ending, centralOffset + central.length)
    const buffer = Buffer.alloc(MiB)
    for (let at = 0; at < size;) {
      const count = readSync(fd, buffer, 0, Math.min(buffer.length, size - at), at)
      assert(count > 0)
      digest.update(buffer.subarray(0, count))
      at += count
    }
  } finally {
    closeSync(fd)
  }
  return { name, path, size, sha256: digest.digest('hex') }
}

const files = ['center/CenterTypes', 'center/CenterLimits', 'engine/Decide', 'engine/RulePack',
  'engine/LocalRuleEngine', 'engine/Lookalike', 'engine/Heuristic', 'engine/BundleFinger',
  'engine/HapReader', 'engine/HapSignature']

try {
  const archives = [archive('near-limit', limit - MiB), archive('exact-limit', limit), archive('over-limit', limit + 1)]
  writeFileSync(join(directory, 'fs-sdk.mjs'), `
import fs from 'node:fs';
export const metrics = { bytes: 0, reads: 0, peak: {} };
export function sample() {
  const memory = process.memoryUsage();
  for (const key of ['rss', 'heapUsed', 'external', 'arrayBuffers']) {
    metrics.peak[key] = Math.max(metrics.peak[key] || 0, memory[key]);
  }
}
export function reset() { metrics.bytes = 0; metrics.reads = 0; metrics.peak = {}; sample(); }
export default {
  statSync(fd) { return fs.fstatSync(fd); },
  readSync(fd, buffer, options) {
    const count = fs.readSync(fd, new Uint8Array(buffer), 0, options.length, options.offset);
    metrics.bytes += count; metrics.reads++; sample(); return count;
  }
};
`)
  writeFileSync(join(directory, 'crypto-sdk.mjs'), `
import { createHash } from 'node:crypto';
import { sample } from './fs-sdk.mjs';
export default { createMd(name) { const hash = createHash(name.toLowerCase()); return {
  updateSync(input) { hash.update(input.data); sample(); },
  digestSync() { sample(); return { data: new Uint8Array(hash.digest()) }; }
}; } };
`)
  writeFileSync(join(directory, 'hilog-sdk.mjs'), 'export const hilog = { warn(){}, info(){}, error(){} };\n')
  for (const file of files) {
    const source = readFileSync(resolve(root, 'entry/src/main/ets', file + '.ets'), 'utf8')
      .replaceAll("from '@ohos.file.fs'", "from './fs-sdk.mjs'")
      .replaceAll("from '@ohos.security.cryptoFramework'", "from './crypto-sdk.mjs'")
      .replaceAll("from '@kit.PerformanceAnalysisKit'", "from './hilog-sdk.mjs'")
      .replace(/from '(\.{1,2}\/[^']+)'/g, (original, path) => path.endsWith('.mjs')
        ? original : `from './${path.split('/').at(-1)}.ts'`)
    writeFileSync(join(directory, file.split('/').at(-1) + '.ts'), source)
  }
  writeFileSync(join(directory, 'stress.ts'), `
import assert from 'node:assert/strict';
import { openSync, closeSync } from 'node:fs';
import { performance } from 'node:perf_hooks';
import { HapReader } from './HapReader.ts';
import { hapReadMax, hashChunk } from './CenterLimits.ts';
import { metrics, reset, sample } from './fs-sdk.mjs';
const fixture = JSON.parse(process.argv[2]);
const mode = process.argv[3];
const runs = [];
global.gc?.();
for (let index = 0; index < (mode === 'repeat' ? 3 : 1); index++) {
  reset();
  const before = process.memoryUsage();
  const start = performance.now();
  const fd = openSync(fixture.path, 'r');
  let cancelled = false;
  const stopped = () => {
    cancelled = mode === 'cancel-hash' ? metrics.bytes >= 4 * hashChunk :
      mode === 'cancel-snapshot' ? metrics.bytes >= fixture.size + 3 * hashChunk : false;
    return cancelled;
  };
  let result;
  try { result = new HapReader().read(fd, stopped); } finally { closeSync(fd); }
  const elapsedMs = performance.now() - start;
  sample();
  assert.equal(result.size, fixture.size);
  assert.equal(result.certSha256, '');
  assert.equal(result.certAlgo, 'none');
  if (mode === 'cancel-hash') {
    assert(cancelled); assert.equal(result.sha256, ''); assert.equal(result.bundleName, '');
    assert.equal(metrics.bytes, 4 * hashChunk);
  } else if (mode === 'cancel-snapshot') {
    assert(cancelled); assert.equal(result.sha256, fixture.sha256); assert.equal(result.bundleName, '');
    assert.equal(metrics.bytes, fixture.size + 3 * hashChunk);
  } else {
    assert.equal(result.sha256, fixture.sha256);
    if (fixture.size > hapReadMax) {
      assert.equal(result.bundleName, ''); assert.deepEqual(result.declaredPermissions, []);
      assert.equal(metrics.bytes, fixture.size);
    } else {
      assert.equal(result.bundleName, '${bundleName}'); assert.equal(result.versionCode, 1);
      assert.deepEqual(result.declaredPermissions, ['ohos.permission.CAMERA']);
      assert.equal(metrics.bytes, fixture.size * 2);
    }
  }
  runs.push({ index, elapsedMs, readBytes: metrics.bytes, readCalls: metrics.reads,
    before, peak: { ...metrics.peak }, after: process.memoryUsage(), cancelled });
}
await new Promise(resolve => setImmediate(resolve));
global.gc?.();
await new Promise(resolve => setImmediate(resolve));
global.gc?.();
process.stdout.write(JSON.stringify({ fixture: fixture.name, size: fixture.size, mode, runs,
  afterGc: process.memoryUsage(), processMaxRssBytes: process.resourceUsage().maxRSS * 1024 }));
`)
  const cases = [[archives[0], 'normal'], [archives[1], 'normal'], [archives[2], 'normal'],
    [archives[1], 'repeat'], [archives[1], 'cancel-hash'], [archives[1], 'cancel-snapshot']]
  const results = cases.map(([fixture, mode]) => {
    const child = spawnSync(process.execPath, ['--expose-gc', '--experimental-strip-types',
      join(directory, 'stress.ts'), JSON.stringify(fixture), mode], { encoding: 'utf8', timeout: 120000 })
    assert.equal(child.status, 0, child.stderr || child.error?.message || child.stdout)
    return JSON.parse(child.stdout)
  })
  const report = { node: process.version, platform: process.platform, architecture: process.arch,
    memoryUnits: 'bytes', fixtureType: 'unsigned ZIP HAP with a zero-filled STORED resource and valid module.json',
    note: 'Host measurements with actual file reads. Repeat scans run without forced GC between scans. Peak samples are taken at real I/O and hash operations.',
    results }
  const reportIndex = process.argv.indexOf('--report')
  if (reportIndex >= 0) {
    assert(process.argv[reportIndex + 1], '--report requires a path')
    writeFileSync(resolve(process.argv[reportIndex + 1]), JSON.stringify(report, null, 2) + '\n')
  }
  process.stdout.write(JSON.stringify(report, null, 2) + '\n')
} finally {
  const owned = realpathSync(directory)
  assert(owned.startsWith(realpathSync(temporaryRoot) + sep) && owned.split(sep).at(-1).startsWith('hap-reader-stress-'))
  rmSync(owned, { recursive: true, force: true })
}
