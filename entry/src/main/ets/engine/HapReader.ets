import fs from '@ohos.file.fs'
import cryptoFramework from '@ohos.security.cryptoFramework'
import { hilog } from '@kit.PerformanceAnalysisKit'
import type { CertAlgo, HapMeta } from '../center/CenterTypes'
import { hashChunk, hapReadMax, hapEntryMax } from '../center/CenterLimits'
import { BundleFinger, digestHex } from './BundleFinger'

const DOMAIN: number = 0x4A59
const TAG: string = 'Center'
const EOCD: number = 0x06054b50
const CENTRAL: number = 0x02014b50
const LOCAL: number = 0x04034b50
const SIGNED_DATA_OID: string = '2a864886f70d010702'
// The official HAP v2/v3 parser uses HapSigningBlockUtils::MAX_BLOCK_COUNT = 10.
const MAX_SIGNING_BLOCKS: number = 10

export class HapReadResult implements HapMeta {
  bundleName: string = ''
  version: string = ''
  versionCode: number = 0
  declaredPermissions: string[] = []
  certSha256: string = ''
  certAlgo: CertAlgo = 'none'
  sha256: string = ''
  size: number = 0
}

export interface HapIo {
  size(fd: number): number
  readAt(fd: number, offset: number, length: number): Uint8Array
  hash(fd: number, size: number, stopped: () => boolean): string
}

export class FsHapIo implements HapIo {
  size(fd: number): number {
    return fs.statSync(fd).size
  }

  readAt(fd: number, offset: number, length: number): Uint8Array {
    let buffer = new ArrayBuffer(length)
    let done = 0
    while (done < length) {
      let part = new ArrayBuffer(length - done)
      let read = fs.readSync(fd, part, { offset: offset + done, length: part.byteLength })
      if (read <= 0) {
        throw new Error('short HAP read')
      }
      new Uint8Array(buffer).set(new Uint8Array(part, 0, read), done)
      done += read
    }
    return new Uint8Array(buffer)
  }

  // Synchronous I/O for a Worker caller. The hash loop checks cancellation per chunk.
  hash(fd: number, size: number, stopped: () => boolean): string {
    let digest = cryptoFramework.createMd('SHA256')
    for (let offset = 0; offset < size; offset += hashChunk) {
      if (stopped()) {
        return ''
      }
      digest.updateSync({ data: this.readAt(fd, offset, Math.min(hashChunk, size - offset)) })
    }
    return stopped() ? '' : digestHex(digest.digestSync().data)
  }
}

class ZipEntry {
  name: string = ''
  method: number = 0
  flags: number = 0
  crc: number = 0
  compressed: number = 0
  unpacked: number = 0
  offset: number = 0
}

interface HapApp {
  bundleName: string
  versionCode: number
  versionName: string
  version: LegacyVersion
}

interface LegacyVersion {
  code: number
  name: string
}

interface HapPermission {
  name: string
}

interface HapModule {
  requestPermissions: HapPermission[]
  reqPermissions: HapPermission[]
}

interface HapConfig {
  app: HapApp
  module: HapModule
}

export class HapReader {
  private io: HapIo

  constructor(io: HapIo = new FsHapIo()) {
    this.io = io
  }

  read(fd: number, stopped: () => boolean = () => false): HapMeta {
    let result = new HapReadResult()
    try {
      result.size = this.io.size(fd)
      if (!Number.isSafeInteger(result.size) || result.size < 0) {
        result.size = 0
        return result
      }
      try {
        result.sha256 = this.io.hash(fd, result.size, stopped)
      } catch (err) {
        hilog.warn(DOMAIN, TAG, 'HAP hash unavailable')
      }
      if (result.size > hapReadMax || stopped()) {
        return result
      }
      let tailOffset = Math.max(0, result.size - 65557)
      let tail = this.io.readAt(fd, tailOffset, result.size - tailOffset)
      let eocd = findEocd(tail)
      let centralSize = u32(tail, eocd + 12)
      let centralOffset = u32(tail, eocd + 16)
      if (u16(tail, eocd + 4) !== 0 || u16(tail, eocd + 6) !== 0 ||
        u16(tail, eocd + 8) !== u16(tail, eocd + 10) ||
        centralOffset + centralSize !== tailOffset + eocd) {
        return result
      }
      try {
        this.readConfig(fd, centralOffset, centralSize, 'module.json', result, stopped)
        if (result.bundleName.length === 0 && !stopped()) {
          this.readConfig(fd, centralOffset, centralSize, 'config.json', result, stopped)
        }
      } catch (err) {
        hilog.warn(DOMAIN, TAG, 'HAP configuration unavailable')
      }
      if (!stopped()) {
        this.readCertificate(fd, centralOffset, result)
      }
    } catch (err) {
      hilog.warn(DOMAIN, TAG, 'HAP metadata unavailable')
    }
    return result
  }

  private readConfig(fd: number, central: number, length: number, configName: string, result: HapReadResult,
    stopped: () => boolean): void {
    let end = central + length
    for (let cursor = central; cursor < end && !stopped();) {
      if (end - cursor < 46) {
        return
      }
      let header = this.io.readAt(fd, cursor, 46)
      if (u32(header, 0) !== CENTRAL) {
        return
      }
      let nameLength = u16(header, 28)
      let next = cursor + 46 + nameLength + u16(header, 30) + u16(header, 32)
      if (next > end) {
        return
      }
      let nameBytes = this.io.readAt(fd, cursor + 46, nameLength)
      cursor = next
      let name = ''
      try {
        name = utf8(nameBytes)
      } catch (err) {
        continue
      }
      if (name.indexOf('..') >= 0 || name.startsWith('/') || name !== configName) {
        continue
      }
      let entry = new ZipEntry()
      entry.name = name
      entry.method = u16(header, 10)
      entry.flags = u16(header, 8)
      entry.crc = u32(header, 16)
      entry.compressed = u32(header, 20)
      entry.unpacked = u32(header, 24)
      entry.offset = u32(header, 42)
      try {
        let data = this.readEntry(fd, entry, central, stopped)
        if (data !== null && applyConfig(data, configName === 'config.json', result)) {
          return
        }
      } catch (err) {
        // A damaged configuration must not discard the file hash or another valid entry.
      }
    }
  }

  private readEntry(fd: number, entry: ZipEntry, central: number,
    stopped: () => boolean): Uint8Array | null {
    if ((entry.flags & 1) !== 0 || entry.unpacked > hapEntryMax ||
      entry.compressed > hapReadMax || (entry.method === 0 && entry.compressed !== entry.unpacked) ||
      entry.offset + 30 > central ||
      (entry.method !== 0 && entry.method !== 8)) {
      return null
    }
    let header = this.io.readAt(fd, entry.offset, 30)
    if (u32(header, 0) !== LOCAL || u16(header, 8) !== entry.method ||
      u16(header, 6) !== entry.flags) {
      return null
    }
    let nameLength = u16(header, 26)
    let dataOffset = entry.offset + 30 + nameLength + u16(header, 28)
    if (dataOffset + entry.compressed > central ||
      utf8(this.io.readAt(fd, entry.offset + 30, nameLength)) !== entry.name) {
      return null
    }
    let data = entry.method === 0 ? this.io.readAt(fd, dataOffset, entry.compressed) :
      inflateRaw(this.io, fd, dataOffset, entry.compressed, entry.unpacked, stopped)
    if (data.length !== entry.unpacked || data.length > hapEntryMax || crc32(data) !== entry.crc) {
      return null
    }
    return data
  }

  private readCertificate(fd: number, central: number, result: HapReadResult): void {
    if (central < 32) {
      return
    }
    let footer = this.io.readAt(fd, central - 32, 32)
    let count = u32(footer, 0)
    let size = u32(footer, 4) + u32(footer, 8) * 4294967296
    let version = u32(footer, 28)
    let magic = utf8(footer.subarray(12, 28))
    if (count === 0 || count > MAX_SIGNING_BLOCKS || size < 32 + count * 12 || size > central ||
      magic !== (version < 3 ? 'HAP Sig Block 42' : '<hap sign block>')) {
      return
    }
    let start = central - size
    let table = this.io.readAt(fd, start, count * 12)
    let certificate = new Uint8Array(0)
    let found = false
    for (let i = 0; i < count; i++) {
      let at = i * 12
      let type = u32(table, at)
      let length = u32(table, at + 4)
      let offset = u32(table, at + 8)
      if (offset < table.length || offset + length > size - 32) {
        return
      }
      if (type === 0x20000000) {
        if (found || length > hapEntryMax) {
          return
        }
        found = true
        certificate = signerCertificate(this.io.readAt(fd, start + offset, length))
      }
    }
    let fingerprint = BundleFinger.read('', certificate)
    result.certSha256 = fingerprint.certSha256
    result.certAlgo = fingerprint.certAlgo
  }
}

function applyConfig(bytes: Uint8Array, legacy: boolean, result: HapReadResult): boolean {
  let config = JSON.parse(utf8(bytes)) as HapConfig
  if (config === null || typeof config !== 'object' || config instanceof Array ||
    config.app === null || typeof config.app !== 'object' || config.app instanceof Array ||
    typeof config.app.bundleName !== 'string' || config.app.bundleName.length === 0) {
    return false
  }
  result.bundleName = config.app.bundleName
  let versionName = config.app.versionName
  let versionCode = config.app.versionCode
  if (legacy && config.app.version !== null && typeof config.app.version === 'object') {
    versionName = config.app.version.name
    versionCode = config.app.version.code
  }
  if (typeof versionName === 'string') {
    result.version = versionName
  }
  if (typeof versionCode === 'number' && Number.isSafeInteger(versionCode) && versionCode >= 0) {
    result.versionCode = versionCode
  }
  if (config.module !== null && typeof config.module === 'object') {
    let permissions = legacy ? config.module.reqPermissions : config.module.requestPermissions
    if (!(permissions instanceof Array)) {
      return true
    }
    let names = new Set<string>()
    for (let permission of permissions) {
      if (permission !== null && typeof permission === 'object' && typeof permission.name === 'string' &&
        permission.name.length > 0 && !names.has(permission.name)) {
        names.add(permission.name)
        result.declaredPermissions.push(permission.name)
      }
    }
  }
  return true
}

function findEocd(bytes: Uint8Array): number {
  for (let at = bytes.length - 22; at >= 0; at--) {
    if (u32(bytes, at) === EOCD && at + 22 + u16(bytes, at + 20) === bytes.length) {
      return at
    }
  }
  throw new Error('missing EOCD')
}

function u16(bytes: Uint8Array, at: number): number {
  if (at < 0 || at + 2 > bytes.length) {
    throw new Error('HAP offset out of bounds')
  }
  return bytes[at] + bytes[at + 1] * 256
}

function u32(bytes: Uint8Array, at: number): number {
  return u16(bytes, at) + u16(bytes, at + 2) * 65536
}

function utf8(bytes: Uint8Array): string {
  let text = ''
  for (let i = 0; i < bytes.length;) {
    let first = bytes[i++]
    let count = first < 0x80 ? 0 : first >= 0xc2 && first <= 0xdf ? 1 :
      first >= 0xe0 && first <= 0xef ? 2 : first >= 0xf0 && first <= 0xf4 ? 3 : -1
    if (count < 0 || i + count > bytes.length) {
      throw new Error('invalid UTF-8')
    }
    let code = first & (count === 0 ? 0x7f : (1 << (6 - count)) - 1)
    for (let j = 0; j < count; j++) {
      let next = bytes[i++]
      if ((next & 0xc0) !== 0x80) {
        throw new Error('invalid UTF-8 continuation')
      }
      code = code * 64 + (next & 0x3f)
    }
    if ((count === 1 && code < 0x80) || (count === 2 && code < 0x800) ||
      (count === 3 && code < 0x10000) || code > 0x10ffff || (code >= 0xd800 && code <= 0xdfff)) {
      throw new Error('invalid UTF-8 scalar')
    }
    text += String.fromCodePoint(code)
  }
  return text
}

function crc32(bytes: Uint8Array): number {
  let crc = -1
  for (let i = 0; i < bytes.length; i++) {
    crc ^= bytes[i]
    for (let bit = 0; bit < 8; bit++) {
      crc = (crc >>> 1) ^ ((crc & 1) === 0 ? 0 : 0xedb88320)
    }
  }
  return (crc ^ -1) >>> 0
}

class BitReader {
  private io: HapIo
  private fd: number
  private offset: number
  private length: number
  private position: number = 0
  private cached: Uint8Array = new Uint8Array(0)
  private cachedOffset: number = 0

  constructor(io: HapIo, fd: number, offset: number, length: number) {
    this.io = io
    this.fd = fd
    this.offset = offset
    this.length = length
  }

  read(count: number): number {
    if (this.position + count > this.length * 8) {
      throw new Error('truncated DEFLATE')
    }
    let value = 0
    for (let i = 0; i < count; i++) {
      value += ((this.byteAt(this.position >>> 3) >>> (this.position & 7)) & 1) * (1 << i)
      this.position++
    }
    return value
  }

  align(): void {
    this.position = Math.ceil(this.position / 8) * 8
  }

  private byteAt(index: number): number {
    if (index < this.cachedOffset || index >= this.cachedOffset + this.cached.length) {
      this.cachedOffset = index
      this.cached = this.io.readAt(this.fd, this.offset + index, Math.min(hashChunk, this.length - index))
    }
    return this.cached[index - this.cachedOffset]
  }
}

class Huffman {
  private values: Map<number, number> = new Map<number, number>()
  private maximum: number = 0

  constructor(lengths: number[]) {
    let counts: number[] = new Array<number>(16).fill(0)
    for (let length of lengths) {
      if (length < 0 || length > 15) {
        throw new Error('invalid Huffman length')
      }
      counts[length]++
      this.maximum = Math.max(this.maximum, length)
    }
    let remaining = 1
    let next: number[] = new Array<number>(16).fill(0)
    for (let length = 1; length <= 15; length++) {
      remaining = remaining * 2 - counts[length]
      if (remaining < 0) {
        throw new Error('oversubscribed Huffman tree')
      }
      next[length] = (next[length - 1] + (length === 1 ? 0 : counts[length - 1])) * 2
    }
    for (let symbol = 0; symbol < lengths.length; symbol++) {
      let length = lengths[symbol]
      if (length > 0) {
        this.values.set((1 << length) + next[length]++, symbol)
      }
    }
  }

  read(input: BitReader): number {
    let code = 0
    for (let length = 1; length <= this.maximum; length++) {
      code = code * 2 + input.read(1)
      let symbol = this.values.get((1 << length) + code)
      if (symbol !== undefined) {
        return symbol
      }
    }
    throw new Error('invalid Huffman code')
  }
}

const LENGTH_BASE: number[] = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
  35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258]
const LENGTH_BITS: number[] = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
  3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0]
const DISTANCE_BASE: number[] = [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193,
  257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577]
const DISTANCE_BITS: number[] = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6,
  7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13]

function trees(input: BitReader, fixed: boolean): Huffman[] {
  if (fixed) {
    let lengths: number[] = []
    for (let symbol = 0; symbol < 288; symbol++) {
      lengths.push(symbol <= 143 ? 8 : symbol <= 255 ? 9 : symbol <= 279 ? 7 : 8)
    }
    return [new Huffman(lengths), new Huffman(new Array<number>(32).fill(5))]
  }
  let literals = input.read(5) + 257
  let distances = input.read(5) + 1
  let codes = input.read(4) + 4
  if (literals > 286 || distances > 32) {
    throw new Error('invalid DEFLATE alphabet')
  }
  let order: number[] = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15]
  let lengths = new Array<number>(19).fill(0)
  for (let i = 0; i < codes; i++) {
    lengths[order[i]] = input.read(3)
  }
  let codeTree = new Huffman(lengths)
  let decoded: number[] = []
  while (decoded.length < literals + distances) {
    let symbol = codeTree.read(input)
    if (symbol < 16) {
      decoded.push(symbol)
    } else {
      if (symbol === 16 && decoded.length === 0) {
        throw new Error('missing repeated Huffman length')
      }
      let value = symbol === 16 ? decoded[decoded.length - 1] : 0
      let repeat = symbol === 16 ? input.read(2) + 3 : symbol === 17 ? input.read(3) + 3 : input.read(7) + 11
      if (decoded.length + repeat > literals + distances) {
        throw new Error('too many Huffman lengths')
      }
      for (let i = 0; i < repeat; i++) {
        decoded.push(value)
      }
    }
  }
  if (decoded[256] === 0) {
    throw new Error('missing DEFLATE end code')
  }
  return [new Huffman(decoded.slice(0, literals)), new Huffman(decoded.slice(literals))]
}

function inflateRaw(io: HapIo, fd: number, offset: number, length: number,
  expected: number, stopped: () => boolean): Uint8Array {
  if (expected > hapEntryMax) {
    throw new Error('DEFLATE output limit')
  }
  let input = new BitReader(io, fd, offset, length)
  let output = new Uint8Array(expected)
  let used = 0
  let final = false
  while (!final) {
    if (stopped()) {
      throw new Error('DEFLATE cancelled')
    }
    final = input.read(1) === 1
    let type = input.read(2)
    if (type === 0) {
      input.align()
      let length = input.read(16)
      if ((length ^ 0xffff) !== input.read(16) || used + length > output.length) {
        throw new Error('invalid stored DEFLATE block')
      }
      for (let i = 0; i < length; i++) {
        output[used++] = input.read(8)
      }
    } else {
      if (type === 3) {
        throw new Error('reserved DEFLATE block')
      }
      let alphabet = trees(input, type === 1)
      for (;;) {
        if ((used & 4095) === 0 && stopped()) {
          throw new Error('DEFLATE cancelled')
        }
        let symbol = alphabet[0].read(input)
        if (symbol === 256) {
          break
        }
        if (symbol < 256) {
          if (used >= output.length) {
            throw new Error('DEFLATE output limit')
          }
          output[used++] = symbol
        } else {
          let lengthIndex = symbol - 257
          if (lengthIndex >= LENGTH_BASE.length) {
            throw new Error('invalid DEFLATE length')
          }
          let length = LENGTH_BASE[lengthIndex] + input.read(LENGTH_BITS[lengthIndex])
          let distanceCode = alphabet[1].read(input)
          if (distanceCode >= DISTANCE_BASE.length) {
            throw new Error('invalid DEFLATE distance')
          }
          let distance = DISTANCE_BASE[distanceCode] + input.read(DISTANCE_BITS[distanceCode])
          if (distance > used || used + length > output.length) {
            throw new Error('DEFLATE output limit or backward distance')
          }
          for (let i = 0; i < length; i++) {
            output[used] = output[used - distance]
            used++
          }
        }
      }
    }
  }
  if (used !== expected) {
    throw new Error('DEFLATE size mismatch')
  }
  return output
}

class AsnNode {
  tag: number = 0
  start: number = 0
  content: number = 0
  contentEnd: number = 0
  end: number = 0
}

function asnNode(bytes: Uint8Array, start: number, limit: number, depth: number): AsnNode {
  if (depth > 24 || start + 2 > limit || limit > bytes.length) {
    throw new Error('invalid ASN.1 bounds')
  }
  let node = new AsnNode()
  node.start = start
  node.tag = bytes[start++]
  if ((node.tag & 31) === 31) {
    throw new Error('unsupported ASN.1 tag')
  }
  let length = bytes[start++]
  if (length === 0x80) {
    if ((node.tag & 0x20) === 0) {
      throw new Error('primitive indefinite ASN.1 length')
    }
    node.content = start
    while (start + 2 <= limit && (bytes[start] !== 0 || bytes[start + 1] !== 0)) {
      start = asnNode(bytes, start, limit, depth + 1).end
    }
    if (start + 2 > limit) {
      throw new Error('unterminated ASN.1 value')
    }
    node.contentEnd = start
    node.end = start + 2
    return node
  }
  if (length > 0x80) {
    let count = length & 0x7f
    if (count > 4 || start + count > limit) {
      throw new Error('invalid ASN.1 length')
    }
    length = 0
    for (let i = 0; i < count; i++) {
      length = length * 256 + bytes[start++]
    }
  }
  node.content = start
  node.contentEnd = start + length
  node.end = node.contentEnd
  if (node.end > limit) {
    throw new Error('ASN.1 length exceeds input')
  }
  return node
}

function children(bytes: Uint8Array, parent: AsnNode): AsnNode[] {
  let nodes: AsnNode[] = []
  for (let at = parent.content; at < parent.contentEnd;) {
    let node = asnNode(bytes, at, parent.contentEnd, 0)
    nodes.push(node)
    at = node.end
  }
  return nodes
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false
  }
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) {
      return false
    }
  }
  return true
}

function integerBytes(bytes: Uint8Array, node: AsnNode): Uint8Array {
  let start = node.content
  while (start + 1 < node.contentEnd && bytes[start] === 0) {
    start++
  }
  return bytes.subarray(start, node.contentEnd)
}

function matchesSigner(bytes: Uint8Array, certificate: AsnNode, sid: AsnNode): boolean {
  let certFields = children(bytes, certificate)
  if (certFields.length !== 3 || certFields[0].tag !== 0x30) {
    return false
  }
  let tbs = children(bytes, certFields[0])
  let serial = tbs.length > 0 && tbs[0].tag === 0xa0 ? 1 : 0
  if (tbs.length <= serial + 5 || tbs[serial].tag !== 2) {
    return false
  }
  if (sid.tag === 0x30) {
    let issuerSerial = children(bytes, sid)
    return issuerSerial.length === 2 && issuerSerial[1].tag === 2 &&
      sameBytes(bytes.subarray(tbs[serial + 2].start, tbs[serial + 2].end),
        bytes.subarray(issuerSerial[0].start, issuerSerial[0].end)) &&
      sameBytes(integerBytes(bytes, tbs[serial]), integerBytes(bytes, issuerSerial[1]))
  }
  if (sid.tag === 0x80) {
    for (let field of tbs) {
      if (field.tag !== 0xa3) {
        continue
      }
      let wrapper = children(bytes, field)
      if (wrapper.length !== 1 || wrapper[0].tag !== 0x30) {
        return false
      }
      for (let extension of children(bytes, wrapper[0])) {
        let values = children(bytes, extension)
        if (values.length >= 2 && values[0].tag === 6 &&
          digestHex(bytes.subarray(values[0].content, values[0].contentEnd)) === '551d0e') {
          let octets = values[values.length - 1]
          let key = asnNode(bytes, octets.content, octets.contentEnd, 0)
          return octets.tag === 4 && key.tag === 4 && key.end === octets.contentEnd &&
            sameBytes(bytes.subarray(key.content, key.contentEnd), bytes.subarray(sid.content, sid.contentEnd))
        }
      }
    }
  }
  return false
}

function signerCertificate(bytes: Uint8Array): Uint8Array {
  let empty = new Uint8Array(0)
  let root = asnNode(bytes, 0, bytes.length, 0)
  if (root.tag !== 0x30 || root.end !== bytes.length) {
    return empty
  }
  let content = children(bytes, root)
  if (content.length !== 2 || content[0].tag !== 6 || content[1].tag !== 0xa0 ||
    digestHex(bytes.subarray(content[0].content, content[0].contentEnd)) !== SIGNED_DATA_OID) {
    return empty
  }
  let wrapper = children(bytes, content[1])
  if (wrapper.length !== 1 || wrapper[0].tag !== 0x30) {
    return empty
  }
  let signed = children(bytes, wrapper[0])
  if (signed.length < 4 || signed[0].tag !== 2 || signed[1].tag !== 0x31 || signed[2].tag !== 0x30) {
    return empty
  }
  let certificates: AsnNode[] = []
  for (let i = 3; i < signed.length - 1; i++) {
    if (signed[i].tag === 0xa0) {
      certificates = children(bytes, signed[i])
    }
  }
  let signerSet = signed[signed.length - 1]
  if (signerSet.tag !== 0x31) {
    return empty
  }
  let signers = children(bytes, signerSet)
  if (signers.length === 0 || signers[0].tag !== 0x30) {
    return empty
  }
  let signer = children(bytes, signers[0])
  if (signer.length < 5 || signer[0].tag !== 2) {
    return empty
  }
  for (let certificate of certificates) {
    if (certificate.tag === 0x30 && matchesSigner(bytes, certificate, signer[1])) {
      return bytes.slice(certificate.start, certificate.end)
    }
  }
  return empty
}
