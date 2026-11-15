import { createHash, createPublicKey, generateKeyPairSync, sign, verify, constants as cryptoConstants, X509Certificate } from 'node:crypto'
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

function certificate(commonName, serial, { family = 'ECC', namedCurve = 'prime256v1',
  modulusLength = 2048, digestName = 'sha256' } = {}) {
  const keys = family === 'ECC'
    ? generateKeyPairSync('ec', { namedCurve })
    : generateKeyPairSync('rsa', { modulusLength })
  const name = sequence(set(sequence(oid('550403'), value(12, Buffer.from(commonName)))))
  const algorithm = sequence(oid(signatureOid(family, digestName)))
  const publicKey = keys.publicKey.export({ type: 'spki', format: 'der' })
  const ski = createHash('sha1').update(publicKey).digest()
  const tbs = sequence(value(0xa0, integer(2)), integer(serial), algorithm, name,
    sequence(value(23, Buffer.from('260101000000Z')), value(23, Buffer.from('460101000000Z'))),
    name, publicKey, value(0xa3, sequence(sequence(oid('551d0e'), value(4, value(4, ski))))))
  const der = sequence(tbs, algorithm, value(3, Buffer.from([0]), sign(digestName, tbs, keys.privateKey)))
  new X509Certificate(der)
  return { keys, name, serial, ski, der, family }
}

function digestIndex(digestName) {
  const index = ['sha256', 'sha384', 'sha512'].indexOf(digestName)
  if (index < 0) throw new Error(`unsupported fixture digest ${digestName}`)
  return index
}

function signatureOid(family, digestName) {
  return family === 'ECC'
    ? ['2a8648ce3d040302', '2a8648ce3d040303', '2a8648ce3d040304'][digestIndex(digestName)]
    : ['2a864886f70d01010b', '2a864886f70d01010c', '2a864886f70d01010d'][digestIndex(digestName)]
}

const signer = certificate('HAP fixture signer', 42)
const other = certificate('Other certificate first', 43)
const certificateHash = createHash('sha256').update(signer.der).digest('hex')

function hashIdentifier(digestName) {
  const suffix = digestName === 'sha1' ? '2b0e03021a' :
    ['608648016503040201', '608648016503040202', '608648016503040203'][digestIndex(digestName)]
  return sequence(oid(suffix), value(5))
}

function pssIdentifier(pss, digestName) {
  if (pss.nullParameters) return sequence(oid('2a864886f70d01010a'), value(5))
  if (pss.missingParameters) return sequence(oid('2a864886f70d01010a'))
  const fields = []
  if (!pss.omitHash) fields.push(value(0xa0, hashIdentifier(pss.hashName ?? digestName)))
  if (!pss.omitMgf) fields.push(value(0xa1, sequence(oid(pss.mgfOid ?? '2a864886f70d010108'),
    hashIdentifier(pss.mgfHash ?? digestName))))
  if (!pss.omitSalt) {
    const salt = pss.negativeSalt ? value(2, Buffer.from([0xff])) :
      integer(pss.saltLength ?? [32, 48, 64][digestIndex(digestName)])
    fields.push(value(0xa2, salt))
  }
  if (pss.trailer !== undefined) fields.push(value(0xa3, integer(pss.trailer)))
  if (pss.duplicateHash) fields.splice(1, 0, fields[0])
  if (pss.reverseParameters) fields.reverse()
  return sequence(oid('2a864886f70d01010a'), sequence(...fields))
}

function cms({ ski = false, ber = false, wrongSigner = false, attributes = false,
  wrongAttrDigest = false, wrongContentType = false, multipleSigners = false,
  identity = signer, digestName = 'sha256', pss = null } = {}, content = null) {
  const template = content === null
  content ??= Buffer.from('Unbound payload')
  const constructed = (tag, ...parts) => ber
    ? Buffer.concat([Buffer.from([tag, 0x80]), ...parts, Buffer.from([0, 0])])
    : value(tag, ...parts)
  const digest = sequence(oid(['608648016503040201', '608648016503040202',
    '608648016503040203'][digestIndex(digestName)]))
  const sid = ski ? value(0x80, identity.ski) : sequence(identity.name, integer(wrongSigner ? 99 : identity.serial))
  const attrs = [
    sequence(oid('2a864886f70d010903'), set(oid(wrongContentType ? '2a864886f70d010702' : '2a864886f70d010701'))),
    sequence(oid('2a864886f70d010904'), set(value(4, createHash(digestName).update(wrongAttrDigest ? Buffer.from('wrong digest') : content).digest())))
  ].sort(Buffer.compare)
  const signedContent = attributes ? set(...attrs) : content
  const signatureAlgorithm = pss && !pss.pkcs1Identifier ? pssIdentifier(pss, digestName) :
    sequence(oid(signatureOid(identity.family, digestName)))
  const signKey = pss ? { key: identity.keys.privateKey,
    padding: pss.pkcs1Signature ? cryptoConstants.RSA_PKCS1_PADDING : cryptoConstants.RSA_PKCS1_PSS_PADDING,
    saltLength: pss.actualSaltLength ?? pss.saltLength ??
      (pss.omitSalt ? 20 : [32, 48, 64][digestIndex(digestName)]) } : identity.keys.privateKey
  const info = sequence(integer(ski ? 3 : 1), sid, digest,
    ...(attributes ? [value(0xa0, ...attrs)] : []), signatureAlgorithm,
    value(4, sign(digestName, signedContent, signKey)))
  const signedData = constructed(0x30, integer(ski ? 3 : 1), set(digest),
    sequence(oid('2a864886f70d010701'), value(0xa0, value(4, content))),
    constructed(0xa0, other.der, identity.der), set(...(multipleSigners ? [info, info] : [info])))
  const bytes = constructed(0x30, oid('2a864886f70d010702'), constructed(0xa0, signedData))
  if (template) bytes.hapTemplate = { ski, ber, wrongSigner, attributes, wrongAttrDigest, wrongContentType, multipleSigners, identity, digestName, pss }
  return bytes
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
  const directory = Buffer.concat(central)
  const ending = Buffer.alloc(22)
  ending.writeUInt32LE(0x06054b50, 0)
  ending.writeUInt16LE(entries.length, 8)
  ending.writeUInt16LE(entries.length, 10)
  ending.writeUInt32LE(directory.length, 12)
  ending.writeUInt32LE(offset, 16)
  ending.writeUInt16LE(Buffer.byteLength(comment), 20)
  const commentBytes = Buffer.from(comment)
  const signatureTemplate = blocks.find(item => item.type === 0x20000000 && item.data.hapTemplate)?.data.hapTemplate
  const digestName = signatureTemplate?.digestName ?? 'sha256'
  const digestLength = [32, 48, 64][digestIndex(digestName)]
  const digestBase = (signatureTemplate?.identity.family ?? 'ECC') === 'ECC' ? 0x201 :
    signatureTemplate?.pss && !signatureTemplate.pss.hapPkcs1 ? 0x101 : 0x104
  const digestAlgorithm = digestBase + digestIndex(digestName)
  const chunks = []
  for (const section of [Buffer.concat(locals), directory, Buffer.concat([ending, commentBytes])]) {
    for (let at = 0; at < section.length; at += 1024 * 1024) {
      const part = section.subarray(at, at + 1024 * 1024)
      const prefix = Buffer.alloc(5)
      prefix[0] = 0xa5
      prefix.writeUInt32LE(part.length, 1)
      chunks.push(createHash(digestName).update(prefix).update(part).digest())
    }
  }
  const prefix = Buffer.alloc(5)
  prefix[0] = 0x5a
  prefix.writeUInt32LE(chunks.length, 1)
  const hash = createHash(digestName).update(prefix).update(Buffer.concat(chunks))
  for (const item of blocks) if (item.type !== 0x20000000) hash.update(item.data)
  const content = Buffer.alloc(20 + digestLength)
  content.writeUInt32LE(2, 0)
  content.writeUInt32LE(1, 4)
  content.writeUInt32LE(8 + digestLength, 8)
  content.writeUInt32LE(digestAlgorithm, 12)
  content.writeUInt32LE(digestLength, 16)
  hash.digest().copy(content, 20)
  const bound = blocks.map(item => ({ type: item.type,
    data: item.data.hapTemplate ? cms(item.data.hapTemplate, content) : item.data }))
  const block = signingBlock(bound, version)
  ending.writeUInt32LE(offset + block.length, 16)
  return Buffer.concat([...locals, block, directory, ending, commentBytes])
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
  ['entry/src/main/ets/engine/RulePack.ets', 'RulePack.ts'],
  ['entry/src/main/ets/engine/LocalRuleEngine.ets', 'LocalRuleEngine.ts'],
  ['entry/src/main/ets/engine/Lookalike.ets', 'Lookalike.ts'],
  ['entry/src/main/ets/engine/Heuristic.ets', 'Heuristic.ts'],
  ['entry/src/main/ets/engine/BundleFinger.ets', 'BundleFinger.ts'],
  ['entry/src/main/ets/engine/HapReader.ets', 'HapReader.ts'],
  ['entry/src/main/ets/engine/HapSignature.ets', 'HapSignature.ts'],
  ['entry/src/main/ets/engine/InstallerScan.ets', 'InstallerScan.ts'],
  ['entry/src/main/ets/feature/clean/Exclude.ets', 'Exclude.ts'],
  ['entry/src/main/ets/system/FileOpen.ets', 'FileOpen.ts'],
  ['entry/src/test/HapReader.test.ets', 'HapReader.test.ts']
]

try {
  mkdirSync(join(directory, 'fixtures'))
  mkdirSync(join(directory, 'installers'))
  const ordinary = [{ name: 'module.json', data: configuration() }]
  const signed = zip(ordinary)
  // Mutate the actual CMS signature of a HAP whose content digest is valid.
  const tamperedSignature = Buffer.from(signed)
  const centralOffset = signed.readUInt32LE(signed.length - 6)
  tamperedSignature[centralOffset - 33] ^= 1
  fixture('tampered-signature', tamperedSignature, { cert: '' })
  const tamperedContent = Buffer.from(signed)
  tamperedContent[0x05] ^= 1 // local-header bytes not interpreted as configuration
  fixture('tampered-content', tamperedContent, { cert: '' })
  const unboundCms = Buffer.from(cms())
  fixture('unbound-cms', zip(ordinary, { blocks: [signature(unboundCms)] }), { cert: '' })
  fixture('signed-attributes', zip(ordinary, { blocks: [signature(cms({ attributes: true }))] }))
  fixture('wrong-attribute-digest', zip(ordinary, { blocks: [signature(cms({ attributes: true,
    wrongAttrDigest: true }))] }), { cert: '' })
  fixture('wrong-content-type', zip(ordinary, { blocks: [signature(cms({ attributes: true,
    wrongContentType: true }))] }), { cert: '' })
  fixture('multiple-signers', zip(ordinary, { blocks: [signature(cms({ multipleSigners: true }))] }), { cert: '' })
  fixture('wide-asn-container', zip(ordinary, { blocks: [signature(sequence(...Array.from({ length: 4097 }, () => value(5))))] }), { cert: '' })

  const algorithmCases = [
    { name: 'ecc256-sha256', family: 'ECC', namedCurve: 'prime256v1', digestName: 'sha256' },
    { name: 'ecc384-sha384', family: 'ECC', namedCurve: 'secp384r1', digestName: 'sha384' },
    { name: 'ecc521-sha512', family: 'ECC', namedCurve: 'secp521r1', digestName: 'sha512' },
    { name: 'rsa2048-sha256', family: 'RSA', modulusLength: 2048, digestName: 'sha256' },
    { name: 'rsa3072-sha384', family: 'RSA', modulusLength: 3072, digestName: 'sha384' },
    { name: 'rsa4096-sha512', family: 'RSA', modulusLength: 4096, digestName: 'sha512' }
  ]
  for (const [index, test] of algorithmCases.entries()) {
    const identity = certificate(`HAP ${test.name}`, 100 + index, test)
    const cert = createHash('sha256').update(identity.der).digest('hex')
    const bytes = zip([{ name: 'module.json', data: configuration('com.algorithm.fixture') }], {
      blocks: [signature(cms({ identity, digestName: test.digestName, attributes: true }))]
    })
    fixture(test.name, bytes, { packageName: 'com.algorithm.fixture', cert })
    const badSignature = Buffer.from(bytes)
    const central = bytes.readUInt32LE(bytes.length - 6)
    badSignature[central - 33] ^= 1
    fixture(`${test.name}-tampered-signature`, badSignature, { packageName: 'com.algorithm.fixture', cert: '' })
    const badContent = Buffer.from(bytes)
    badContent[5] ^= 1
    fixture(`${test.name}-tampered-content`, badContent, { packageName: 'com.algorithm.fixture', cert: '' })
  }
  const pssIdentity = certificate('RSA-PSS HAP signer', 201, { family: 'RSA', modulusLength: 2048 })
  const pssCert = createHash('sha256').update(pssIdentity.der).digest('hex')
  const pssCases = [
    { name: 'pss-sha256', digestName: 'sha256', pss: {}, accepted: true },
    { name: 'pss-sha384', digestName: 'sha384', pss: {}, accepted: true },
    { name: 'pss-sha512', digestName: 'sha512', pss: {}, accepted: true },
    { name: 'pss-zero-salt', pss: { saltLength: 0 }, accepted: true },
    { name: 'pss-default-salt', pss: { omitSalt: true }, accepted: true },
    { name: 'pss-maximum-salt', pss: { saltLength: 222 }, accepted: true },
    { name: 'pss-explicit-trailer', pss: { trailer: 1 }, accepted: true },
    { name: 'pss-no-attributes', pss: {}, accepted: true, attributes: false },
    { name: 'pss-salt-mismatch', pss: { saltLength: 20, actualSaltLength: 32 }, accepted: false },
    { name: 'pss-negative-salt', pss: { negativeSalt: true, actualSaltLength: 32 }, accepted: false },
    { name: 'pss-excessive-salt', pss: { saltLength: 223, actualSaltLength: 32 }, accepted: false },
    { name: 'pss-sha1-hash', pss: { hashName: 'sha1' }, accepted: false },
    { name: 'pss-sha384-hash-mismatch', pss: { hashName: 'sha384' }, accepted: false },
    { name: 'pss-missing-hash', pss: { omitHash: true }, accepted: false },
    { name: 'pss-missing-mgf', pss: { omitMgf: true }, accepted: false },
    { name: 'pss-mgf-hash-mismatch', pss: { mgfHash: 'sha384' }, accepted: false },
    { name: 'pss-wrong-mgf', pss: { mgfOid: '2a864886f70d010101' }, accepted: false },
    { name: 'pss-wrong-trailer', pss: { trailer: 2 }, accepted: false },
    { name: 'pss-duplicate-parameters', pss: { duplicateHash: true }, accepted: false },
    { name: 'pss-unordered-parameters', pss: { reverseParameters: true }, accepted: false },
    { name: 'pss-null-parameters', pss: { nullParameters: true }, accepted: false },
    { name: 'pss-missing-parameters', pss: { missingParameters: true }, accepted: false },
    { name: 'pss-hap-pkcs1-cms', pss: { pkcs1Identifier: true, pkcs1Signature: true }, accepted: false },
    { name: 'pkcs1-hap-pss-cms', pss: { hapPkcs1: true }, accepted: false },
    { name: 'pss-padding-mismatch', pss: { pkcs1Signature: true }, accepted: false }
  ]
  for (const test of pssCases) {
    const bytes = zip([{ name: 'module.json', data: configuration('com.algorithm.fixture') }], {
      blocks: [signature(cms({ identity: pssIdentity, digestName: test.digestName ?? 'sha256',
        attributes: test.attributes ?? true, pss: test.pss }))]
    })
    fixture(test.name, bytes, { packageName: 'com.algorithm.fixture', cert: test.accepted ? pssCert : '' })
    if (test.accepted) {
      const changed = Buffer.from(bytes)
      const central = changed.readUInt32LE(changed.length - 6)
      changed[central - 33] ^= 1
      fixture(test.name + '-tampered-signature', changed, { packageName: 'com.algorithm.fixture', cert: '' })
      const changedContent = Buffer.from(bytes)
      changedContent[5] ^= 1
      fixture(test.name + '-tampered-content', changedContent, { packageName: 'com.algorithm.fixture', cert: '' })
    }
  }
  // A stored resource forces the first ZIP region across the 1 MiB digest boundary.
  const largeSigned = zip([
    { name: 'module.json', data: configuration('com.algorithm.fixture') },
    { name: 'resources/padding.bin', data: Buffer.alloc(1024 * 1024 + 1337, 0x5a), method: 0 }
  ])
  fixture('multiple-digest-chunks', largeSigned, { packageName: 'com.algorithm.fixture' })
  const badSecondChunk = Buffer.from(largeSigned)
  badSecondChunk[1024 * 1024 + 100] ^= 1
  fixture('multiple-digest-chunks-tampered', badSecondChunk, { packageName: 'com.algorithm.fixture', cert: '' })

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
  fixture('unknown-signature-block', zip(ordinary, { blocks: [{ type: 0x12345678, data: Buffer.from('ignored') }, signature()] }), { cert: '' })
  fixture('known-optional-block', zip(ordinary, { blocks: [{ type: 0x20000002, data: Buffer.from('bound optional data') }, signature()] }))
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
    const officialOptions = { packageName: 'com.ohos.screenshot', packageVersion: '1.0.0', code: 1000000,
      cert: '8e93863fc32ee238060bf69a9b37e2608fffb21f93c862dd511cbac9f30024b5', permissions: [
        'ohos.permission.MEDIA_LOCATION', 'ohos.permission.GET_BUNDLE_INFO_PRIVILEGED', 'ohos.permission.CAPTURE_SCREEN',
        'ohos.permission.START_ABILITIES_FROM_BACKGROUND', 'ohos.permission.WRITE_IMAGEVIDEO'] }
    fixture('official-screenshot', official, officialOptions)
    const central = official.readUInt32LE(official.length - 6)
    const start = central - Number(official.readBigUInt64LE(central - 28))
    const positions = [5, central + 4]
    for (let index = 0; index < official.readUInt32LE(central - 32); index++) {
      const at = start + index * 12
      positions.push(start + official.readUInt32LE(at + 8) + official.readUInt32LE(at + 4) - 1)
    }
    for (const [index, position] of positions.entries()) {
      const changed = Buffer.from(official)
      changed[position] ^= 1
      fixture(`official-tampered-${index}`, changed, { ...officialOptions, cert: '' })
    }
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
import { createHash, createPublicKey, verify, constants } from 'node:crypto';
let verifyAvailable = true;
export function setVerifyAvailable(value) { verifyAvailable = value; }
export default {
  SignSpecItem: { PSS_SALT_LEN_NUM: 103 },
  createMd(name) { const hash = createHash(name.toLowerCase()); return {
    updateSync(input) { hash.update(input.data); }, digestSync() { return { data: new Uint8Array(hash.digest()) }; }
  }; },
  createAsyKeyGenerator(name) { return { convertKeySync(pub) {
    return { pubKey: createPublicKey({ key: Buffer.from(pub.data), format: 'der', type: 'spki' }) };
  } }; },
  createVerify(name) {
    if (!verifyAvailable) throw new Error('verification unavailable');
    let key; let saltLength;
    return {
      initSync(pub) { key = pub; },
      setVerifySpec(item, value) { if (item !== 103) throw new Error('unexpected verify parameter'); saltLength = value; },
      verifySync(data, signature) {
        const hash = name.match(/SHA(?:256|384|512)/)[0].toLowerCase();
        const isPss = name.includes('|PSS|');
        if (isPss && saltLength === undefined) throw new Error('PSS salt length was not set');
        if (isPss && !name.endsWith('|MGF1_' + hash.toUpperCase())) throw new Error('PSS MGF1 was not set explicitly');
        const publicKey = isPss ? { key, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength } : key;
        return verify(hash, data.data, publicKey, signature.data);
      }
    };
  }
};
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
import assert from 'node:assert/strict';
import { readFileSync, openSync, closeSync } from 'node:fs';
import { HapReader } from './HapReader.ts';
import { verifiedHapCertificate } from './HapSignature.ts';
import { setVerifyAvailable } from './crypto-sdk.mjs';
import { runHapReaderChecks } from './HapReader.test.ts';
const fixtures = JSON.parse(readFileSync(new URL('./fixtures.json', import.meta.url), 'utf8'));
runHapReaderChecks(fixtures, '${virtualRoot}/installers', '${virtualRoot}/cancel.bin');
const storedPath = new URL('./fixtures/stored.hap', import.meta.url);
const stored = readFileSync(storedPath);
const ending = stored.length - 22;
const central = stored.readUInt32LE(ending + 16);
let calls = 0;
assert.equal(verifiedHapCertificate(stored, central, ending, () => ++calls > 25).length, 0);
assert.equal(calls, 26);
setVerifyAvailable(false);
const fd = openSync(storedPath, 'r');
try {
  const unavailable = new HapReader().read(fd);
  assert.equal(unavailable.certSha256, '');
  assert.equal(unavailable.certAlgo, 'none');
  assert.equal(unavailable.bundleName, 'com.test.fixture');
  assert.equal(unavailable.sha256.length, 64);
} finally { closeSync(fd); setVerifyAvailable(true); }
assert(verifiedHapCertificate(stored, central, ending, () => false).length > 0);

process.stdout.write('HapReader, BundleFinger and InstallerScan checks passed (' + fixtures.length + ' archives${withOfficialHap ? ', including pinned official ScreenShot.hap' : ', offline fixtures'})\\n');
`)
  const result = spawnSync(process.execPath, ['--experimental-strip-types', join(directory, 'main.ts')], { encoding: 'utf8' })
  process.stdout.write(result.stdout || '')
  process.stderr.write(result.stderr || '')
  if (result.status !== 0) process.exitCode = result.status === null ? 1 : result.status
} finally {
  rmSync(directory, { recursive: true, force: true })
}
