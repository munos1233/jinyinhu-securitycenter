import cryptoFramework from '@ohos.security.cryptoFramework'
import { hapEntryMax, hapReadMax } from '../center/CenterLimits'

const SIGNED_DATA: string = '2a864886f70d010702'
const DATA: string = '2a864886f70d010701'
const CONTENT_TYPE: string = '2a864886f70d010903'
const MESSAGE_DIGEST: string = '2a864886f70d010904'
const RSA_PSS: string = '2a864886f70d01010a'
const MGF1: string = '2a864886f70d010108'
const SHA1: string = '2b0e03021a'
const SIGNATURE_BLOCK: number = 0x20000000
const CHUNK_SIZE: number = 1048576
const MAX_ASN_NODES: number = 16384
const MAX_ASN_CHILDREN: number = 4096

class ParseBudget {
  private nodes: number = 0
  private stopped: () => boolean

  constructor(stopped: () => boolean) {
    this.stopped = stopped
  }

  take(): void {
    this.nodes++
    require(this.nodes <= MAX_ASN_NODES && !this.stopped())
  }
}

class Node {
  tag: number = 0
  start: number = 0
  content: number = 0
  contentEnd: number = 0
  end: number = 0
  indefinite: boolean = false
}

class Block {
  type: number = 0
  offset: number = 0
  length: number = 0
}

class Algorithm {
  digest: string = ''
  digestOid: string = ''
  signatureOid: string = ''
  family: string = ''
  digestLength: number = 0
  padding: string = ''
}

class CmsSignature {
  certificate: Uint8Array = new Uint8Array(0)
  content: Uint8Array = new Uint8Array(0)
  signed: Uint8Array = new Uint8Array(0)
  signature: Uint8Array = new Uint8Array(0)
  algorithm: Algorithm = new Algorithm()
  keyAlgorithm: string = ''
  publicKey: Uint8Array = new Uint8Array(0)
  saltLength: number = 20
}

// The input is the same immutable, size-bounded snapshot used to parse metadata.
// The signature binds certificate identity to these bytes. Trust remains a rule-pack decision.
export function verifiedHapCertificate(bytes: Uint8Array, central: number, eocd: number,
  stopped: () => boolean): Uint8Array {
  let empty = new Uint8Array(0)
  try {
    if (stopped() || bytes.length > hapReadMax || central < 32 || eocd < central ||
      eocd + 22 > bytes.length || le32(bytes, eocd) !== 0x06054b50 ||
      le32(bytes, eocd + 16) !== central || le32(bytes, eocd + 12) + central !== eocd ||
      eocd + 22 + le16(bytes, eocd + 20) !== bytes.length) {
      return empty
    }
    let footer = central - 32
    let count = le32(bytes, footer)
    let size = le32(bytes, footer + 4) + le32(bytes, footer + 8) * 4294967296
    let version = le32(bytes, footer + 28)
    let magic = version === 2 ? 'HAP Sig Block 42' : '<hap sign block>'
    if ((version !== 2 && version !== 3) || count < 1 || count > 10 ||
      size > central || size < 32 + count * 12 ||
      !asciiEquals(bytes.subarray(footer + 12, footer + 28), magic)) {
      return empty
    }
    let start = central - size
    let blocks = readBlocks(bytes, start, size, count)
    let signature: Block | null = null
    for (let block of blocks) {
      if (block.type === SIGNATURE_BLOCK) {
        signature = block
      }
    }
    if (signature === null) {
      return empty
    }
    let cms = parseCms(bytes.slice(signature.offset, signature.offset + signature.length), new ParseBudget(stopped))
    if (stopped() || !same(cms.content.subarray(20), hapDigest(bytes, start, central, eocd,
      blocks, cms.algorithm, stopped))) {
      return empty
    }
    let keys = cryptoFramework.createAsyKeyGenerator(cms.keyAlgorithm)
      .convertKeySync({ data: cms.publicKey }, null)
    let mode = cms.keyAlgorithm + (cms.algorithm.family === 'RSA' ? '|' + cms.algorithm.padding + '|' : '|') +
      cms.algorithm.digest
    if (cms.algorithm.padding === 'PSS') {
      mode += '|MGF1_' + cms.algorithm.digest
    }
    let verify = cryptoFramework.createVerify(mode)
    verify.initSync(keys.pubKey)
    if (cms.algorithm.padding === 'PSS') {
      verify.setVerifySpec(cryptoFramework.SignSpecItem.PSS_SALT_LEN_NUM, cms.saltLength)
    }
    return !stopped() && verify.verifySync({ data: cms.signed }, { data: cms.signature }) && !stopped()
      ? cms.certificate : empty
  } catch (err) {
    // Malformed, unsupported and cryptographically invalid inputs provide no identity.
    return empty
  }
}

function readBlocks(bytes: Uint8Array, start: number, size: number, count: number): Block[] {
  let blocks: Block[] = []
  let seen = new Set<number>()
  for (let i = 0; i < count; i++) {
    let at = start + i * 12
    let block = new Block()
    block.type = le32(bytes, at)
    block.length = le32(bytes, at + 4)
    block.offset = start + le32(bytes, at + 8)
    if (block.type < SIGNATURE_BLOCK || block.type > 0x20000005 || seen.has(block.type) ||
      block.length === 0 || block.length > hapEntryMax || block.offset < start + count * 12 ||
      block.offset + block.length > start + size - 32) {
      throw new Error('invalid HAP signing block')
    }
    seen.add(block.type)
    blocks.push(block)
  }
  let ordered = blocks.slice().sort((a: Block, b: Block): number => a.offset - b.offset)
  let cursor = start + count * 12
  for (let block of ordered) {
    if (block.offset !== cursor) {
      throw new Error('overlapping or incomplete HAP signing blocks')
    }
    cursor += block.length
  }
  if (cursor !== start + size - 32) {
    throw new Error('unaccounted HAP signing bytes')
  }
  return blocks
}

// appverify 78d4b2c, hap_signing_block_utils.cpp VerifyHapIntegrity and
// hap_verify_openssl_utils.cpp GetDigest. Each ZIP region starts its own 1 MiB chunks.
function hapDigest(bytes: Uint8Array, start: number, central: number, eocd: number,
  blocks: Block[], algorithm: Algorithm, stopped: () => boolean): Uint8Array {
  let ending = bytes.slice(eocd)
  putLe32(ending, 16, start)
  let regions: Uint8Array[] = [bytes.subarray(0, start), bytes.subarray(central, eocd), ending]
  let count = 0
  for (let region of regions) {
    count += Math.ceil(region.length / CHUNK_SIZE)
  }
  let chunks = new Uint8Array(5 + count * algorithm.digestLength)
  chunks[0] = 0x5a
  putLe32(chunks, 1, count)
  let position = 5
  for (let region of regions) {
    for (let offset = 0; offset < region.length; offset += CHUNK_SIZE) {
      if (stopped()) {
        throw new Error('HAP signature verification cancelled')
      }
      let part = region.subarray(offset, Math.min(offset + CHUNK_SIZE, region.length))
      let prefix = new Uint8Array(5)
      prefix[0] = 0xa5
      putLe32(prefix, 1, part.length)
      chunks.set(hash(algorithm.digest, [prefix, part]), position)
      position += algorithm.digestLength
    }
  }
  let finalParts: Uint8Array[] = [chunks]
  for (let block of blocks) {
    if (block.type !== SIGNATURE_BLOCK) {
      finalParts.push(bytes.subarray(block.offset, block.offset + block.length))
    }
  }
  return hash(algorithm.digest, finalParts)
}

function parseCms(bytes: Uint8Array, budget: ParseBudget): CmsSignature {
  let result = new CmsSignature()
  let root = node(bytes, 0, bytes.length, 0, budget)
  require(root.tag === 0x30 && root.end === bytes.length)
  let contentInfo = children(bytes, root, budget)
  require(contentInfo.length === 2 && oid(bytes, contentInfo[0]) === SIGNED_DATA && contentInfo[1].tag === 0xa0)
  let wrapper = children(bytes, contentInfo[1], budget)
  require(wrapper.length === 1 && wrapper[0].tag === 0x30)
  let signedData = children(bytes, wrapper[0], budget)
  require(signedData.length === 5 && signedData[0].tag === 2 && signedData[1].tag === 0x31 &&
    signedData[2].tag === 0x30 && signedData[3].tag === 0xa0 && signedData[4].tag === 0x31)
  let encapsulated = children(bytes, signedData[2], budget)
  require(encapsulated.length === 2 && oid(bytes, encapsulated[0]) === DATA && encapsulated[1].tag === 0xa0)
  let octets = children(bytes, encapsulated[1], budget)
  require(octets.length === 1 && octets[0].tag === 4 && !octets[0].indefinite)
  result.content = bytes.slice(octets[0].content, octets[0].contentEnd)
  require(result.content.length >= 20 && le32(result.content, 4) === 1)
  result.algorithm = algorithmFor(le32(result.content, 12))
  require(le32(result.content, 8) === 8 + result.algorithm.digestLength &&
    le32(result.content, 16) === result.algorithm.digestLength &&
    result.content.length === 20 + result.algorithm.digestLength)
  let digests = children(bytes, signedData[1], budget)
  require(digests.length === 1 && algorithmOid(bytes, digests[0], budget) === result.algorithm.digestOid)
  let signers = children(bytes, signedData[4], budget)
  require(signers.length === 1 && signers[0].tag === 0x30)
  let signer = children(bytes, signers[0], budget)
  require((signer.length === 5 || signer.length === 6) && signer[0].tag === 2 &&
    algorithmOid(bytes, signer[2], budget) === result.algorithm.digestOid)
  let hasAttributes = signer[3].tag === 0xa0
  require(signer.length === (hasAttributes ? 6 : 5))
  let signatureIndex = hasAttributes ? 4 : 3
  if (result.algorithm.padding === 'PSS') {
    result.saltLength = pssSaltLength(bytes, signer[signatureIndex], result.algorithm, budget)
  } else {
    let signatureOid = algorithmOid(bytes, signer[signatureIndex], budget)
    require(signatureOid === result.algorithm.signatureOid ||
      (result.algorithm.family === 'RSA' && signatureOid === '2a864886f70d010101'))
  }
  require(signer[signatureIndex + 1].tag === 4)
  result.signature = bytes.slice(signer[signatureIndex + 1].content, signer[signatureIndex + 1].contentEnd)
  result.signed = hasAttributes ? signedAttributes(bytes, signer[3], result.content, result.algorithm, budget) : result.content
  let selected: Node | null = null
  for (let certificate of children(bytes, signedData[3], budget)) {
    require(certificate.tag === 0x30)
    if (matchesSigner(bytes, certificate, signer[1], budget)) {
      require(selected === null)
      selected = certificate
    }
  }
  require(selected !== null)
  if (selected === null) {
    throw new Error('missing HAP signer certificate')
  }
  assertDer(bytes, selected, 0, budget)
  result.certificate = bytes.slice(selected.start, selected.end)
  let certificateFields = children(bytes, selected, budget)
  require(certificateFields.length === 3 && certificateFields[0].tag === 0x30)
  let tbs = children(bytes, certificateFields[0], budget)
  let serial = tbs[0].tag === 0xa0 ? 1 : 0
  let publicKey = tbs[serial + 5]
  require(publicKey.tag === 0x30)
  result.publicKey = bytes.slice(publicKey.start, publicKey.end)
  result.keyAlgorithm = keyAlgorithm(bytes, publicKey, result.algorithm.family, budget)
  if (result.algorithm.padding === 'PSS') {
    let modulusBytes = Number.parseInt(result.keyAlgorithm.substring(3), 10) / 8
    // EMSA-PSS uses emBits = modulusBits - 1. All supported RSA moduli are byte-aligned.
    require(result.saltLength <= modulusBytes - result.algorithm.digestLength - 2)
  }
  return result
}

function algorithmFor(id: number): Algorithm {
  let result = new Algorithm()
  let index = 0
  if (id >= 0x201 && id <= 0x203) {
    result.family = 'ECC'
    index = id - 0x201
  } else if (id >= 0x101 && id <= 0x103) {
    result.family = 'RSA'
    result.padding = 'PSS'
    index = id - 0x101
  } else if (id >= 0x104 && id <= 0x106) {
    result.family = 'RSA'
    result.padding = 'PKCS1'
    index = id - 0x104
  } else {
    throw new Error('unsupported HAP signature algorithm')
  }
  result.digest = ['SHA256', 'SHA384', 'SHA512'][index]
  result.digestLength = [32, 48, 64][index]
  result.digestOid = ['608648016503040201', '608648016503040202', '608648016503040203'][index]
  result.signatureOid = result.family === 'ECC'
    ? ['2a8648ce3d040302', '2a8648ce3d040303', '2a8648ce3d040304'][index]
    : result.padding === 'PSS' ? RSA_PSS
      : ['2a864886f70d01010b', '2a864886f70d01010c', '2a864886f70d01010d'][index]
  return result
}

function pssSaltLength(bytes: Uint8Array, identifier: Node, algorithm: Algorithm, budget: ParseBudget): number {
  require(identifier.tag === 0x30)
  assertDer(bytes, identifier, 0, budget)
  let fields = children(bytes, identifier, budget)
  require(fields.length === 2 && oid(bytes, fields[0]) === RSA_PSS && fields[1].tag === 0x30)
  let digestOid = SHA1
  let maskDigestOid = SHA1
  let saltLength = 20
  let previousTag = 0x9f
  for (let parameter of children(bytes, fields[1], budget)) {
    // RSASSA-PSS-params is a SEQUENCE of ordered, explicitly tagged optional fields.
    require(parameter.tag >= 0xa0 && parameter.tag <= 0xa3 && parameter.tag > previousTag)
    previousTag = parameter.tag
    let values = children(bytes, parameter, budget)
    require(values.length === 1)
    if (parameter.tag === 0xa0) {
      digestOid = algorithmOid(bytes, values[0], budget)
    } else if (parameter.tag === 0xa1) {
      require(values[0].tag === 0x30)
      let mask = children(bytes, values[0], budget)
      require(mask.length === 2 && oid(bytes, mask[0]) === MGF1)
      maskDigestOid = algorithmOid(bytes, mask[1], budget)
    } else if (parameter.tag === 0xa2) {
      saltLength = smallInteger(bytes, values[0])
    } else {
      require(smallInteger(bytes, values[0]) === 1)
    }
  }
  // This implementation supports MGF1 with the HAP/CMS digest. Unsupported
  // parameter combinations must not silently fall back to backend defaults.
  require(digestOid === algorithm.digestOid && maskDigestOid === algorithm.digestOid)
  return saltLength
}

function smallInteger(bytes: Uint8Array, value: Node): number {
  let encoded = integer(bytes, value)
  require(encoded.length <= 2)
  let result = 0
  for (let octet of encoded) {
    result = result * 256 + octet
  }
  // No supported key can encode a PSS salt longer than its 512-byte modulus.
  require(result <= 512)
  return result
}

function keyAlgorithm(bytes: Uint8Array, spki: Node, family: string, budget: ParseBudget): string {
  let fields = children(bytes, spki, budget)
  require(fields.length === 2 && fields[0].tag === 0x30 && fields[1].tag === 3 &&
    bytes[fields[1].content] === 0)
  let identifier = children(bytes, fields[0], budget)
  if (family === 'ECC') {
    require(identifier.length === 2 && oid(bytes, identifier[0]) === '2a8648ce3d0201')
    let curve = oid(bytes, identifier[1])
    if (curve === '2a8648ce3d030107') {
      return 'ECC256'
    }
    if (curve === '2b81040022') {
      return 'ECC384'
    }
    require(curve === '2b81040023')
    return 'ECC521'
  }
  require(oid(bytes, identifier[0]) === '2a864886f70d010101')
  let key = node(bytes, fields[1].content + 1, fields[1].contentEnd, 0, budget)
  require(key.tag === 0x30 && key.end === fields[1].contentEnd)
  let integers = children(bytes, key, budget)
  require(integers.length === 2 && integers[0].tag === 2 && integers[1].tag === 2)
  let modulus = integer(bytes, integers[0])
  let bits = (modulus.length - 1) * 8
  for (let value = modulus[0]; value > 0; value >>>= 1) {
    bits++
  }
  require(bits === 2048 || bits === 3072 || bits === 4096)
  return 'RSA' + bits.toString()
}

function signedAttributes(bytes: Uint8Array, attributes: Node, content: Uint8Array,
  algorithm: Algorithm, budget: ParseBudget): Uint8Array {
  assertDer(bytes, attributes, 0, budget)
  let seen = new Set<string>()
  let previous = new Uint8Array(0)
  for (let attribute of children(bytes, attributes, budget)) {
    let encoding = bytes.subarray(attribute.start, attribute.end)
    require(previous.length === 0 || compare(previous, encoding) < 0)
    previous = encoding
    require(attribute.tag === 0x30)
    let fields = children(bytes, attribute, budget)
    require(fields.length === 2 && fields[1].tag === 0x31)
    let type = oid(bytes, fields[0])
    require(!seen.has(type))
    seen.add(type)
    let values = children(bytes, fields[1], budget)
    if (type === MESSAGE_DIGEST) {
      require(values.length === 1 && values[0].tag === 4 &&
        same(bytes.subarray(values[0].content, values[0].contentEnd), hash(algorithm.digest, [content])))
    } else if (type === CONTENT_TYPE) {
      require(values.length === 1 && oid(bytes, values[0]) === DATA)
    }
  }
  require(seen.has(MESSAGE_DIGEST) && seen.has(CONTENT_TYPE))
  let result = bytes.slice(attributes.start, attributes.end)
  result[0] = 0x31
  return result
}

function matchesSigner(bytes: Uint8Array, certificate: Node, sid: Node, budget: ParseBudget): boolean {
  let fields = children(bytes, certificate, budget)
  require(fields.length === 3 && fields[0].tag === 0x30)
  let tbs = children(bytes, fields[0], budget)
  let serial = tbs.length > 0 && tbs[0].tag === 0xa0 ? 1 : 0
  require(tbs.length > serial + 5 && tbs[serial].tag === 2)
  if (sid.tag === 0x30) {
    let issuerSerial = children(bytes, sid, budget)
    return issuerSerial.length === 2 && issuerSerial[1].tag === 2 &&
      same(bytes.subarray(tbs[serial + 2].start, tbs[serial + 2].end),
        bytes.subarray(issuerSerial[0].start, issuerSerial[0].end)) &&
      same(integer(bytes, tbs[serial]), integer(bytes, issuerSerial[1]))
  }
  if (sid.tag === 0x80) {
    for (let field of tbs) {
      if (field.tag !== 0xa3) {
        continue
      }
      let wrapper = children(bytes, field, budget)
      require(wrapper.length === 1 && wrapper[0].tag === 0x30)
      for (let extension of children(bytes, wrapper[0], budget)) {
        let values = children(bytes, extension, budget)
        if (values.length >= 2 && oid(bytes, values[0]) === '551d0e') {
          let octets = values[values.length - 1]
          let key = node(bytes, octets.content, octets.contentEnd, 0, budget)
          return octets.tag === 4 && key.tag === 4 && key.end === octets.contentEnd &&
            same(bytes.subarray(key.content, key.contentEnd), bytes.subarray(sid.content, sid.contentEnd))
        }
      }
    }
  }
  return false
}

function node(bytes: Uint8Array, start: number, limit: number, depth: number, budget: ParseBudget): Node {
  budget.take()
  require(depth <= 24 && start >= 0 && start + 2 <= limit && limit <= bytes.length)
  let result = new Node()
  result.start = start
  result.tag = bytes[start++]
  require((result.tag & 31) !== 31 && result.tag !== 0)
  let length = bytes[start++]
  if (length === 0x80) {
    require((result.tag & 0x20) !== 0)
    result.indefinite = true
    result.content = start
    while (start + 2 <= limit && (bytes[start] !== 0 || bytes[start + 1] !== 0)) {
      start = node(bytes, start, limit, depth + 1, budget).end
    }
    require(start + 2 <= limit)
    result.contentEnd = start
    result.end = start + 2
    return result
  }
  if (length > 0x80) {
    let count = length & 0x7f
    require(count <= 4 && start + count <= limit && bytes[start] !== 0)
    length = 0
    for (let i = 0; i < count; i++) {
      length = length * 256 + bytes[start++]
    }
    require(length >= 128)
  }
  result.content = start
  result.contentEnd = start + length
  result.end = result.contentEnd
  require(result.end <= limit)
  return result
}

function children(bytes: Uint8Array, parent: Node, budget: ParseBudget): Node[] {
  require((parent.tag & 0x20) !== 0)
  let result: Node[] = []
  for (let at = parent.content; at < parent.contentEnd;) {
    require(result.length < MAX_ASN_CHILDREN)
    let child = node(bytes, at, parent.contentEnd, 0, budget)
    result.push(child)
    at = child.end
  }
  return result
}

function assertDer(bytes: Uint8Array, value: Node, depth: number, budget: ParseBudget): void {
  require(depth <= 24 && !value.indefinite)
  if ((value.tag & 0x20) !== 0) {
    for (let child of children(bytes, value, budget)) {
      assertDer(bytes, child, depth + 1, budget)
    }
  }
}

function algorithmOid(bytes: Uint8Array, value: Node, budget: ParseBudget): string {
  require(value.tag === 0x30)
  let parts = children(bytes, value, budget)
  require(parts.length === 1 || (parts.length === 2 && parts[1].tag === 5 &&
    parts[1].content === parts[1].contentEnd))
  return oid(bytes, parts[0])
}

function oid(bytes: Uint8Array, value: Node): string {
  require(value.tag === 6 && value.content < value.contentEnd)
  let result = ''
  for (let i = value.content; i < value.contentEnd; i++) {
    result += bytes[i].toString(16).padStart(2, '0')
  }
  return result
}

function integer(bytes: Uint8Array, value: Node): Uint8Array {
  require(value.tag === 2 && value.content < value.contentEnd && (bytes[value.content] & 0x80) === 0)
  let start = value.content
  if (bytes[start] === 0 && start + 1 < value.contentEnd) {
    require((bytes[start + 1] & 0x80) !== 0)
    start++
  }
  return bytes.subarray(start, value.contentEnd)
}

function hash(name: string, parts: Uint8Array[]): Uint8Array {
  let digest = cryptoFramework.createMd(name)
  for (let part of parts) {
    digest.updateSync({ data: part })
  }
  return digest.digestSync().data
}

function compare(a: Uint8Array, b: Uint8Array): number {
  for (let i = 0; i < Math.min(a.length, b.length); i++) {
    if (a[i] !== b[i]) {
      return a[i] - b[i]
    }
  }
  return a.length - b.length
}

function same(a: Uint8Array, b: Uint8Array): boolean {
  return compare(a, b) === 0
}

function asciiEquals(bytes: Uint8Array, text: string): boolean {
  if (bytes.length !== text.length) {
    return false
  }
  for (let i = 0; i < bytes.length; i++) {
    if (bytes[i] !== text.charCodeAt(i)) {
      return false
    }
  }
  return true
}

function le16(bytes: Uint8Array, at: number): number {
  require(at >= 0 && at + 2 <= bytes.length)
  return bytes[at] + bytes[at + 1] * 256
}

function le32(bytes: Uint8Array, at: number): number {
  return le16(bytes, at) + le16(bytes, at + 2) * 65536
}

function putLe32(bytes: Uint8Array, at: number, value: number): void {
  require(at >= 0 && at + 4 <= bytes.length && value >= 0 && value <= 0xffffffff)
  for (let i = 0; i < 4; i++) {
    bytes[at + i] = value % 256
    value = Math.floor(value / 256)
  }
}

function require(value: boolean): void {
  if (!value) {
    throw new Error('invalid HAP signature')
  }
}
