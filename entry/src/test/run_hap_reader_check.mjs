import { createHash, generateKeyPairSync, sign, X509Certificate } from 'node:crypto'
import { spawnSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { constants, deflateRawSync } from 'node:zlib'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../../..')
const directory = mkdtempSync(join(tmpdir(), 'hap-reader-'))
const virtualRoot = '/user/hap-check'
const sourceUrl = 'https://media.githubusercontent.com/media/openharmony/applications_hap/fd2c78258466076118c8a9bf1a97fdbcec06a5c8/ScreenShot.hap'
const sourceSha256 = '8b6f7795e02fb9c495dd7136316083a90c3f90abe36612d1982babbe3a419806'
const withOfficialHap = process.argv.includes('--with-official-hap')

function lengthBytes(length) {
  if (length < 128) return Buffer.from([length])
  const hex = length.toString(16).padStart(Math.ceil(length.toString(16).length / 2) * 2, '0')
  const bytes = Buffer.from(hex, 'hex')
  return Buffer.concat([Buffer.from([128 + bytes.length]), bytes])
}

function value(tag, ...parts) {
  const content = Buffer.concat(parts)
  return Buffer.concat([Buffer.from([tag]), lengthBytes(content.length), content])
}

const sequence = (...parts) => value(0x30, ...parts)
const set = (...parts) => value(0x31, ...parts)
const oid = (hex) => value(6, Buffer.from(hex, 'hex'))
function integer(number) {
  let hex = number.toString(16)
  hex = hex.padStart(Math.ceil(hex.length / 2) * 2, '0')
  const bytes = Buffer.from(hex, 'hex')
  return value(2, bytes[0] & 128 ? Buffer.concat([Buffer.from([0]), bytes]) : bytes)
}

function certificate(commonName, serial) {
  const keys = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
  const name = sequence(set(sequence(oid('550403'), value(12, Buffer.from(commonName)))))
  const algorithm = sequence(oid('2a8648ce3d040302'))
  const publicKey = keys.publicKey.export({ type: 'spki', format: 'der' })
  const ski = createHash('sha1').update(publicKey).digest()
  const tbs = sequence(value(0xa0, integer(2)), integer(serial), algorithm, name,
    sequence(value(23, Buffer.from('260101000000Z')), value(23, Buffer.from('460101000000Z'))),
    name, publicKey, value(0xa3, sequence(sequence(oid('551d0e'), value(4, value(4, ski))))))
  const der = sequence(tbs, algorithm, value(3, Buffer.from([0]), sign('sha256', tbs, keys.privateKey)))
  new X509Certificate(der)
  return { keys, name, serial, ski, der }
}

const signer = certificate('HAP fixture signer', 42)
const other = certificate('Other certificate first', 43)
const certificateHash = createHash('sha256').update(signer.der).digest('hex')

function cms({ ski = false, ber = false, wrongSigner = false } = {}) {
  const constructed = (tag, ...parts) => ber
    ? Buffer.concat([Buffer.from([tag, 0x80]), ...parts, Buffer.from([0, 0])])
    : value(tag, ...parts)
  const content = Buffer.from('HAP fixture signed payload')
  const digest = sequence(oid('608648016503040201'))
  const sid = ski ? value(0x80, signer.ski) : sequence(signer.name, integer(wrongSigner ? 99 : signer.serial))
  const info = sequence(integer(ski ? 3 : 1), sid, digest, sequence(oid('2a8648ce3d040302')),
    value(4, sign('sha256', content, signer.keys.privateKey)))
  const signedData = constructed(0x30, integer(ski ? 3 : 1), set(digest),
    sequence(oid('2a864886f70d010701'), value(0xa0, value(4, content))),
    constructed(0xa0, other.der, signer.der), set(info))
  return constructed(0x30, oid('2a864886f70d010702'), constructed(0xa0, signedData))
}

function crc32(bytes) {
  let crc = -1
  for (const byte of bytes) {
    crc ^= byte
    for (let i = 0; i < 8; i++) crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0)
  }
  return (crc ^ -1) >>> 0
}

const signature = (content = cms()) => ({ type: 0x20000000, data: content })
function signingBlock(blocks, version) {
  if (!blocks.length) return Buffer.alloc(0)
  let offset = blocks.length * 12
  const table = blocks.map((block) => {
    const header = Buffer.alloc(12)
    header.writeUInt32LE(block.type, 0)
    header.writeUInt32LE(block.data.length, 4)
    header.writeUInt32LE(offset, 8)
    offset += block.data.length
    return header
  })
  const footer = Buffer.alloc(32)
  footer.writeUInt32LE(blocks.length, 0)
  footer.writeBigUInt64LE(BigInt(offset + 32), 4)
  footer.write(version < 3 ? 'HAP Sig Block 42' : '<hap sign block>', 12, 'ascii')
  footer.writeUInt32LE(version, 28)
  return Buffer.concat([...table, ...blocks.map((block) => block.data), footer])
}

function zip(entries, { blocks = [signature()], version = 3, comment = '' } = {}) {
  const locals = []
  const central = []
  let offset = 0
  for (const entry of entries) {
    const name = Buffer.from(entry.name)
    const bytes = Buffer.isBuffer(entry.data) ? entry.data : Buffer.from(entry.data)
    const method = entry.method ?? 8
    const compressed = method === 0 ? bytes : deflateRawSync(bytes, entry.options)
    const flags = entry.flags ?? 0x800
    const local = Buffer.alloc(30)
    local.writeUInt32LE(0x04034b50, 0)
    local.writeUInt16LE(20, 4)
    local.writeUInt16LE(flags, 6)
    local.writeUInt16LE(method, 8)
    local.writeUInt32LE(crc32(bytes), 14)
    local.writeUInt32LE(compressed.length, 18)
    local.writeUInt32LE(bytes.length, 22)
    local.writeUInt16LE(name.length, 26)
    const header = Buffer.alloc(46)
    header.writeUInt32LE(0x02014b50, 0)
    header.writeUInt16LE(20, 4)
    header.writeUInt16LE(20, 6)
    header.writeUInt16LE(flags, 8)
    header.writeUInt16LE(method, 10)
    header.writeUInt32LE(entry.badCrc ? (crc32(bytes) ^ 1) >>> 0 : crc32(bytes), 16)
    header.writeUInt32LE(compressed.length, 20)
    header.writeUInt32LE(entry.declaredSize ?? bytes.length, 24)
    header.writeUInt16LE(name.length, 28)
    header.writeUInt32LE(offset, 42)
    locals.push(local, name, compressed)
    central.push(header, name)
    offset += local.length + name.length + compressed.length
  }
  const block = signingBlock(blocks, version)
  const directory = Buffer.concat(central)
  const ending = Buffer.alloc(22)
  ending.writeUInt32LE(0x06054b50, 0)
  ending.writeUInt16LE(entries.length, 8)
  ending.writeUInt16LE(entries.length, 10)
  ending.writeUInt32LE(directory.length, 12)
  ending.writeUInt32LE(offset + block.length, 16)
  ending.writeUInt16LE(Buffer.byteLength(comment), 20)
  return Buffer.concat([...locals, block, directory, ending, Buffer.from(comment)])
}

function configuration(bundleName = 'com.test.fixture', padding = '') {
  return JSON.stringify({ app: { bundleName, versionName: '1.2.3', versionCode: 123 },
    module: { requestPermissions: [{ name: 'ohos.permission.CAMERA' }, { name: 'ohos.permission.CAMERA' },
      { name: 'ohos.permission.LOCATION_IN_BACKGROUND' }] }, padding })
}

function legacyConfiguration(bundleName = 'com.test.fixture', padding = '') {
  return JSON.stringify({ app: { bundleName, version: { name: '1.2.3', code: 123 } },
    module: { reqPermissions: [{ name: 'ohos.permission.CAMERA' },
      { name: 'ohos.permission.LOCATION_IN_BACKGROUND' }] }, padding })
}

const fixtures = []
function fixture(name, bytes, { packageName = 'com.test.fixture', cert = certificateHash,
  packageVersion = '1.2.3', code = 123, permissions = ['ohos.permission.CAMERA', 'ohos.permission.LOCATION_IN_BACKGROUND'] } = {}) {
  const path = `${virtualRoot}/fixtures/${name}.hap`
  writeFileSync(join(directory, 'fixtures', `${name}.hap`), bytes)
  fixtures.push({ name, path, bundleName: packageName, version: packageName ? packageVersion : '',
    versionCode: packageName ? code : 0, certSha256: cert, sha256: createHash('sha256').update(bytes).digest('hex'),
    declaredPermissions: packageName ? permissions : [] })
  return bytes
}

const files = [
  ['entry/src/main/ets/center/CenterTypes.ets', 'CenterTypes.ts'],
  ['entry/src/main/ets/center/CenterLimits.ets', 'CenterLimits.ts'],
  ['entry/src/main/ets/center/CenterError.ets', 'CenterError.ts'],
  ['entry/src/main/ets/engine/Decide.ets', 'Decide.ts'],
  ['entry/src/main/ets/engine/LocalRuleEngine.ets', 'LocalRuleEngine.ts'],
  ['entry/src/main/ets/engine/Lookalike.ets', 'Lookalike.ts'],
  ['entry/src/main/ets/engine/Heuristic.ets', 'Heuristic.ts'],
  ['entry/src/main/ets/engine/BundleFinger.ets', 'BundleFinger.ts'],
  ['entry/src/main/ets/engine/HapReader.ets', 'HapReader.ts'],
  ['entry/src/main/ets/engine/InstallerScan.ets', 'InstallerScan.ts'],
  ['entry/src/main/ets/feature/clean/Exclude.ets', 'Exclude.ts'],
  ['entry/src/main/ets/system/FileOpen.ets', 'FileOpen.ts'],
  ['entry/src/test/HapReader.test.ets', 'HapReader.test.ts']
]

try {
  mkdirSync(join(directory, 'fixtures'))
  mkdirSync(join(directory, 'installers'))
  const ordinary = [{ name: 'module.json', data: configuration() }]
  fixture('stored', zip([{ ...ordinary[0], method: 0 }]))
  fixture('raw-stored-block', zip([{ ...ordinary[0], options: { level: 0 } }]))
  fixture('fixed-huffman', zip([{ ...ordinary[0], options: { strategy: constants.Z_FIXED } }]))
  fixture('dynamic-huffman', zip([{ name: 'module.json', data: configuration('com.test.fixture', 'é中文🙂'.repeat(300)) }]))
  fixture('config-after-200', zip([...Array.from({ length: 200 }, (_, i) => ({ name: `unrelated/${i}`, data: 'ignored' })), ...ordinary]))
  fixture('invalid-resource-name-before-config-201', zip([{ name: Buffer.from([0xff]), data: 'legacy name', flags: 0 },
    ...Array.from({ length: 199 }, (_, i) => ({ name: `resource/${i}`, data: 'ignored' })), ...ordinary]))
  fixture('fa-stored', zip([{ name: 'config.json', data: legacyConfiguration(), method: 0 }]))
  fixture('fa-deflated', zip([{ name: 'config.json', data: legacyConfiguration() }]))
  fixture('fa-after-200', zip([...Array.from({ length: 200 }, (_, i) => ({ name: `fa/${i}`, data: 'ignored' })),
    { name: 'config.json', data: legacyConfiguration() }]))
  fixture('fa-oversized-config', zip([{ name: 'config.json', data: legacyConfiguration('com.test.fixture',
    'x'.repeat(2 * 1024 * 1024)) }]), { packageName: '' })
  fixture('fa-exact-entry-cap', zip([{ name: 'config.json', data: legacyConfiguration('com.test.fixture',
    'x'.repeat(2 * 1024 * 1024 - Buffer.byteLength(legacyConfiguration()))) }]))
  fixture('stage-exact-entry-cap', zip([{ name: 'module.json', data: configuration('com.test.fixture',
    'x'.repeat(2 * 1024 * 1024 - Buffer.byteLength(configuration()))) }]))
  fixture('fa-crc-mismatch', zip([{ name: 'config.json', data: legacyConfiguration(), badCrc: true }]), { packageName: '' })
  fixture('stage-priority-over-fa', zip([{ name: 'config.json', data: legacyConfiguration('com.legacy.ignored') },
    ...ordinary]))
  fixture('skip-invalid-names', zip([{ name: '../module.json', data: configuration('com.bad') },
    { name: '/module.json', data: configuration('com.bad') }, ...ordinary]))
  fixture('broken-then-valid-config', zip([{ name: 'module.json', data: '{broken' }, ...ordinary]))
  fixture('old-signature-magic', zip(ordinary, { version: 2, comment: 'ZIP comment with PK markers' }))
  fixture('ski-signer', zip(ordinary, { blocks: [signature(cms({ ski: true }))] }))
  fixture('ber-signed-data', zip(ordinary, { blocks: [signature(cms({ ber: true }))] }))
  fixture('unknown-signature-block', zip(ordinary, { blocks: [{ type: 0x12345678, data: Buffer.from('ignored') }, signature()] }))
  fixture('unmatched-signer', zip(ordinary, { blocks: [signature(cms({ wrongSigner: true }))] }), { cert: '' })
  fixture('duplicate-signature-block', zip(ordinary, { blocks: [signature(), signature()] }), { cert: '' })
  fixture('bad-asn-length', zip(ordinary, { blocks: [signature(Buffer.from([0x30, 0x82, 0xff, 0xff, 0]))] }), { cert: '' })
  fixture('no-signature', zip(ordinary, { blocks: [] }), { cert: '' })
  fixture('invalid-config', zip([{ name: 'module.json', data: '{}' }]), { packageName: '' })
  fixture('invalid-config-utf8', zip([{ name: 'module.json', data: Buffer.from([0xc0, 0xaf]) }]), { packageName: '' })
  fixture('crc-mismatch', zip([{ ...ordinary[0], badCrc: true }]), { packageName: '' })
  fixture('encrypted-config', zip([{ ...ordinary[0], flags: 0x801 }]), { packageName: '' })
  fixture('stored-size-mismatch', zip([{ ...ordinary[0], method: 0, declaredSize: 1 }]), { packageName: '' })
  fixture('deflate-output-cap', zip([{ ...ordinary[0], declaredSize: 1 }]), { packageName: '' })
  fixture('oversized-config', zip([{ name: 'module.json', data: configuration('com.test.fixture', 'x'.repeat(2 * 1024 * 1024)) }]), { packageName: '' })
  fixture('truncated-zip', Buffer.from('PK truncated archive'), { packageName: '', cert: '' })
  fixture('empty-hap', Buffer.alloc(0), { packageName: '', cert: '' })
  for (let i = 0; i < 24; i++) {
    const padding = Array.from({ length: 50 + i * 31 }, (_, j) => String.fromCodePoint(32 + ((j * 43 + i * 71) % 90))).join('')
    fixture(`deflate-variety-${i}`, zip([{ name: 'module.json', data: configuration('com.test.fixture', padding),
      options: { level: i % 10 } }]))
  }
  if (withOfficialHap) {
    const response = await fetch(sourceUrl, { signal: AbortSignal.timeout(30000) })
    if (!response.ok) throw new Error(`official HAP download failed: ${response.status}`)
    const official = Buffer.from(await response.arrayBuffer())
    if (official.length !== 96577 || createHash('sha256').update(official).digest('hex') !== sourceSha256) {
      throw new Error('pinned official HAP size or SHA-256 mismatch')
    }
    fixture('official-screenshot', official, { packageName: 'com.ohos.screenshot', packageVersion: '1.0.0', code: 1000000,
      cert: '8e93863fc32ee238060bf69a9b37e2608fffb21f93c862dd511cbac9f30024b5', permissions: [
        'ohos.permission.MEDIA_LOCATION', 'ohos.permission.GET_BUNDLE_INFO_PRIVILEGED', 'ohos.permission.CAPTURE_SCREEN',
        'ohos.permission.START_ABILITIES_FROM_BACKGROUND', 'ohos.permission.WRITE_IMAGEVIDEO'] })
  }
  writeFileSync(join(directory, 'installers', 'a-installed.hap'), zip([{ name: 'module.json', data: configuration('com.test.installed') }]))
  writeFileSync(join(directory, 'installers', 'b-residue.hap'), zip([{ name: 'module.json', data: configuration('com.test.removed') }]))
  writeFileSync(join(directory, 'installers', 'blocked.hap'), zip(ordinary))
  writeFileSync(join(directory, 'installers', 'broken.hap'), Buffer.from('broken'))
  writeFileSync(join(directory, 'installers', 'ignored.zip'), zip(ordinary))
  symlinkSync(join(directory, 'fixtures'), join(directory, 'installers', 'outside'), 'junction')
  writeFileSync(join(directory, 'cancel.bin'), Buffer.alloc(3 * 1024 * 1024 + 1, 0x5a))
  writeFileSync(join(directory, 'fixtures.json'), JSON.stringify(fixtures))
  writeFileSync(join(directory, 'fs-sdk.mjs'), `
import fs from 'node:fs';
import { join } from 'node:path';
const root = ${JSON.stringify(directory)};
const prefix = ${JSON.stringify(virtualRoot)};
function native(path) { return typeof path === 'string' && path.startsWith(prefix) ? join(root, path.slice(prefix.length)) : path; }
export default {
  OpenMode: { READ_ONLY: 0 },
  statSync(path) { return typeof path === 'number' ? fs.fstatSync(path) : fs.statSync(native(path)); },
  lstatSync(path) { return fs.lstatSync(native(path)); },
  listFileSync(path) { return fs.readdirSync(native(path)); },
  openSync(path) { return {fd: fs.openSync(native(path), 'r'), path}; },
  closeSync(fd) { fs.closeSync(typeof fd === 'number' ? fd : fd.fd); },
  readSync(fd, buffer, options) { return fs.readSync(fd, new Uint8Array(buffer), 0, options.length, options.offset); }
};
`)
  writeFileSync(join(directory, 'crypto-sdk.mjs'), `
import { createHash } from 'node:crypto';
export default { createMd(name) { const hash = createHash(name.toLowerCase()); return {
  updateSync(input) { hash.update(input.data); }, digestSync() { return { data: new Uint8Array(hash.digest()) }; }
}; }};
`)
  writeFileSync(join(directory, 'hilog-sdk.mjs'), 'export const hilog = {info(){},warn(){},error(){}};\n')
  for (const [from, to] of files) {
    const source = readFileSync(resolve(root, from), 'utf8').replaceAll('\r\n', '\n')
      .replaceAll("from '@ohos.file.fs'", "from './fs-sdk.mjs'")
      .replaceAll("from '@ohos.security.cryptoFramework'", "from './crypto-sdk.mjs'")
      .replaceAll("from '@kit.PerformanceAnalysisKit'", "from './hilog-sdk.mjs'")
      .replace(/from '(\.{1,2}\/[^']+)'/g, (original, path) => {
        if (path.endsWith('.mjs')) return original
        return `from './${path.split('/').at(-1)}.ts'`
      })
    writeFileSync(join(directory, to), source)
  }
  writeFileSync(join(directory, 'main.ts'), `
import { readFileSync } from 'node:fs';
import { runHapReaderChecks } from './HapReader.test.ts';
const fixtures = JSON.parse(readFileSync(new URL('./fixtures.json', import.meta.url), 'utf8'));
runHapReaderChecks(fixtures, '${virtualRoot}/installers', '${virtualRoot}/cancel.bin');
process.stdout.write('HapReader, BundleFinger and InstallerScan checks passed (' + fixtures.length + ' archives${withOfficialHap ? ', including pinned official ScreenShot.hap' : ', offline fixtures'})\\n');
`)
  const result = spawnSync(process.execPath, ['--experimental-strip-types', join(directory, 'main.ts')], { encoding: 'utf8' })
  process.stdout.write(result.stdout || '')
  process.stderr.write(result.stderr || '')
  if (result.status !== 0) process.exitCode = result.status === null ? 1 : result.status
} finally {
  rmSync(directory, { recursive: true, force: true })
}
