import fs from '@ohos.file.fs';
import { hilog } from '@kit.PerformanceAnalysisKit';
import { nowIso } from '../center/Clock';
import { CenterError } from '../center/CenterError';
import { quarantineQuota } from '../center/CenterLimits';
import type { FileGrant, QuarantineEntry } from '../center/CenterTypes';
import { FileOpen, OpenedFile } from '../system/FileOpen';
import type { CenterFiles } from './Writer';
import { Writer } from './Writer';

const DOMAIN: number = 0x4A59
const TAG: string = 'Center'
const KEY_ALIAS: string = 'jinyinhu.center.quarantine'
const KEY_BITS: number = 256
const MANIFEST: string = 'center/quarantine/manifest.json'
const BLOB_DIR: string = 'center/quarantine/blobs/'
const TEMP_DIR: string = 'center/quarantine/tmp/'

export interface CipherText {
  iv: string
  tag: string
  bytes: Uint8Array
}

export interface QuarantineCipher {
  encrypt(alias: string, bits: number, plain: Uint8Array): CipherText | null
  decrypt(alias: string, bits: number, bytes: Uint8Array, iv: string, tag: string): Uint8Array | null
}

export interface ByteStore {
  read(path: string): Uint8Array | null
  readFd(fd: number): Uint8Array | null
  write(path: string, data: Uint8Array): boolean
  remove(path: string): boolean
}

export function bytePath(root: string, path: string): string {
  if (path.length > 0 && path.charAt(0) === '/') {
    return path
  }
  if (root.length === 0) {
    return path
  }
  if (root.charAt(root.length - 1) === '/') {
    return root + path
  }
  return root + '/' + path
}

class Row implements QuarantineEntry {
  id: string = ''
  from: string = ''
  stored: string = ''
  sha256: string = ''
  size: number = 0
  iv: string = ''
  tag: string = ''
  reason: string = ''
  at: string = ''
  committed: boolean = false
}

export class FsByteStore implements ByteStore {
  root: string

  constructor(root: string) {
    this.root = root
  }

  read(path: string): Uint8Array | null {
    try {
      let file = fs.openSync(bytePath(this.root, path), fs.OpenMode.READ_ONLY)
      let bytes = readWhole(file.fd)
      fs.closeSync(file)
      return bytes
    } catch (err) {
      return null
    }
  }

  readFd(fd: number): Uint8Array | null {
    try {
      return readWhole(fd)
    } catch (err) {
      return null
    }
  }

  write(path: string, data: Uint8Array): boolean {
    try {
      let full = bytePath(this.root, path)
      let slash = full.lastIndexOf('/')
      if (slash > 0) {
        try {
          fs.mkdirSync(full.substring(0, slash), true)
        } catch (err) {
        }
      }
      let file = fs.openSync(full, fs.OpenMode.CREATE | fs.OpenMode.READ_WRITE | fs.OpenMode.TRUNC)
      fs.writeSync(file.fd, data.buffer)
      fs.closeSync(file)
      return true
    } catch (err) {
      return false
    }
  }

  remove(path: string): boolean {
    try {
      fs.unlinkSync(bytePath(this.root, path))
      return true
    } catch (err) {
      return false
    }
  }
}

function readWhole(fd: number): Uint8Array {
  let stat = fs.statSync(fd)
  if (stat.size <= 0) {
    return new Uint8Array(0)
  }
  let buffer = new ArrayBuffer(stat.size)
  fs.readSync(fd, buffer)
  return new Uint8Array(buffer)
}

export class Quarantine {
  private files: CenterFiles
  private bytes: ByteStore
  private opener: FileOpen
  private cipher: QuarantineCipher
  private ids: () => string

  constructor(files: CenterFiles, bytes: ByteStore, opener: FileOpen, cipher: QuarantineCipher,
    ids: () => string) {
    this.files = files
    this.bytes = bytes
    this.opener = opener
    this.cipher = cipher
    this.ids = ids
  }

  put(from: string, size: number, sha256: string, reason: string, root: string,
    huksReady: boolean): CenterError | QuarantineEntry {
    if (!huksReady) {
      return this.error('unsupported', 'huks')
    }
    let quota = Writer.exclusive(() => {
      return this.quotaState(size)
    })
    if (quota === 2) {
      return this.error('io', MANIFEST)
    }
    if (quota === 1) {
      return this.error('quota', '')
    }
    let grants: FileGrant[] = []
    let opened = this.opener.open(from, root, false, grants)
    if (opened instanceof CenterError) {
      return opened
    }
    let held = opened
    let id = this.ids()
    let temp = TEMP_DIR + id
    let blob = BLOB_DIR + id
    try {
      let plain = this.readOpened(held, from)
      if (plain === null) {
        return this.error('io', from)
      }
      if (!this.bytes.write(temp, plain)) {
        this.bytes.remove(temp)
        return this.error('io', from)
      }
      let copied = this.bytes.read(temp)
      if (copied === null) {
        this.bytes.remove(temp)
        return this.error('io', from)
      }
      let digest = sha256Hex(copied)
      if (sha256.length > 0 && sha256 !== digest) {
        this.bytes.remove(temp)
        return this.error('io', from)
      }
      let seal = this.cipher.encrypt(KEY_ALIAS, KEY_BITS, copied)
      if (seal === null || !this.bytes.write(blob, seal.bytes)) {
        this.bytes.remove(blob)
        this.bytes.remove(temp)
        return this.error('io', blob)
      }
      let counted = copied.length > size ? copied.length : size
      if (counted > size) {
        let again = Writer.exclusive(() => {
          return this.quotaState(counted)
        })
        if (again !== 0) {
          this.bytes.remove(blob)
          this.bytes.remove(temp)
          return again === 1 ? this.error('quota', '') : this.error('io', MANIFEST)
        }
      }
      this.bytes.remove(temp)
      let iv = seal.iv
      let tag = seal.tag
      let saved = Writer.exclusive(() => {
        return this.appendUncommitted(id, from, digest, counted, iv, tag, reason)
      })
      if (saved === null) {
        this.bytes.remove(blob)
        return this.error('io', MANIFEST)
      }
      let source = held.path.length > 0 ? held.path : from
      if (!this.bytes.remove(source)) {
        return saved
      }
      let committed = Writer.exclusive(() => {
        return this.markCommitted(id)
      })
      if (committed === null) {
        return this.error('io', MANIFEST)
      }
      return committed
    } finally {
      this.opener.release(held)
      this.bytes.remove(temp)
    }
  }

  restore(id: string, root: string, choose: string): CenterError | null {
    let found = Writer.exclusive(() => {
      return this.find(id)
    })
    if (found === null) {
      return this.error('io', id)
    }
    let temp = TEMP_DIR + 'restore-' + id
    try {
      let cipherBytes = this.bytes.read(BLOB_DIR + found.stored)
      if (cipherBytes === null) {
        return this.error('io', found.stored)
      }
      let plain = this.cipher.decrypt(KEY_ALIAS, KEY_BITS, cipherBytes, found.iv, found.tag)
      if (plain === null) {
        return this.error('io', found.stored)
      }
      if (!this.bytes.write(temp, plain)) {
        return this.error('io', temp)
      }
      let copied = this.bytes.read(temp)
      if (copied === null) {
        return this.error('io', temp)
      }
      if (sha256Hex(copied) !== found.sha256) {
        return this.error('io', found.sha256)
      }
      let dest = this.destination(found.from, root, choose)
      if (dest instanceof CenterError) {
        return dest
      }
      if (!this.bytes.write(dest, copied)) {
        this.bytes.remove(dest)
        return this.error('io', dest)
      }
      let removed = Writer.exclusive(() => {
        return this.removeEntry(id)
      })
      if (!removed) {
        this.bytes.remove(dest)
        return this.error('io', MANIFEST)
      }
      this.bytes.remove(BLOB_DIR + found.stored)
      return null
    } finally {
      this.bytes.remove(temp)
    }
  }

  private quotaState(size: number): number {
    let rows = this.readManifest()
    if (rows === null) {
      return 2
    }
    let used = 0
    for (let i = 0; i < rows.length; i++) {
      used += rows[i].size
    }
    if (used + size > quarantineQuota) {
      return 1
    }
    return 0
  }

  private appendUncommitted(id: string, from: string, digest: string, size: number, iv: string,
    tag: string, reason: string): Row | null {
    let rows = this.readManifest()
    if (rows === null) {
      return null
    }
    let row = new Row()
    row.id = id
    row.from = from
    row.stored = id
    row.sha256 = digest
    row.size = size
    row.iv = iv
    row.tag = tag
    row.reason = reason
    row.at = nowIso()
    row.committed = false
    rows.push(row)
    if (!this.replaceManifest(rows)) {
      return null
    }
    return row
  }

  private markCommitted(id: string): Row | null {
    let rows = this.readManifest()
    if (rows === null) {
      return null
    }
    let found: Row | null = null
    for (let i = 0; i < rows.length; i++) {
      if (rows[i].id === id) {
        rows[i].committed = true
        found = rows[i]
      }
    }
    if (found === null || !this.replaceManifest(rows)) {
      return null
    }
    return found
  }

  private find(id: string): Row | null {
    let rows = this.readManifest()
    if (rows === null) {
      return null
    }
    for (let i = 0; i < rows.length; i++) {
      if (rows[i].id === id) {
        return rows[i]
      }
    }
    return null
  }

  private removeEntry(id: string): boolean {
    let rows = this.readManifest()
    if (rows === null) {
      return false
    }
    let kept: Row[] = []
    for (let i = 0; i < rows.length; i++) {
      if (rows[i].id !== id) {
        kept.push(rows[i])
      }
    }
    return this.replaceManifest(kept)
  }

  private readOpened(opened: OpenedFile, from: string): Uint8Array | null {
    let viaFd = this.bytes.readFd(opened.fd)
    if (viaFd !== null) {
      return viaFd
    }
    if (opened.path.length > 0) {
      return this.bytes.read(opened.path)
    }
    return this.bytes.read(from)
  }

  private destination(from: string, root: string, choose: string): CenterError | string {
    let allowed = this.opener.accept(from, root)
    if (!(allowed instanceof CenterError)) {
      return allowed
    }
    if (choose.length === 0) {
      return allowed
    }
    return this.opener.accept(choose, root)
  }

  private readManifest(): Row[] | null {
    let text = Writer.readText(MANIFEST)
    if (text === null || text.length === 0) {
      return []
    }
    try {
      let parsed = JSON.parse(text) as Object[]
      if (!(parsed instanceof Array)) {
        return null
      }
      let rows: Row[] = []
      for (let i = 0; i < parsed.length; i++) {
        rows.push(rowFrom(parsed[i]))
      }
      return rows
    } catch (err) {
      return null
    }
  }

  private replaceManifest(rows: Row[]): boolean {
    Writer.replaceText(MANIFEST, JSON.stringify(rows))
    return Writer.readText(MANIFEST) !== null
  }

  private error(code: 'unsupported' | 'quota' | 'io', raw: string): CenterError {
    hilog.error(DOMAIN, TAG, code)
    return new CenterError(code, raw)
  }
}

function rowFrom(raw: Object): Row {
  let peek = raw as Row
  let row = new Row()
  row.id = typeof peek.id === 'string' ? peek.id : ''
  row.from = typeof peek.from === 'string' ? peek.from : ''
  row.stored = typeof peek.stored === 'string' ? peek.stored : ''
  row.sha256 = typeof peek.sha256 === 'string' ? peek.sha256 : ''
  row.size = typeof peek.size === 'number' ? peek.size : 0
  row.iv = typeof peek.iv === 'string' ? peek.iv : ''
  row.tag = typeof peek.tag === 'string' ? peek.tag : ''
  row.reason = typeof peek.reason === 'string' ? peek.reason : ''
  row.at = typeof peek.at === 'string' ? peek.at : ''
  row.committed = peek.committed === true
  return row
}

const K: number[] = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

function sha256Hex(data: Uint8Array): string {
  let h0 = 0x6a09e667
  let h1 = 0xbb67ae85
  let h2 = 0x3c6ef372
  let h3 = 0xa54ff53a
  let h4 = 0x510e527f
  let h5 = 0x9b05688c
  let h6 = 0x1f83d9ab
  let h7 = 0x5be0cd19
  let bitHi = Math.floor(data.length / 0x20000000)
  let bitLo = (data.length << 3) >>> 0
  let padded = data.length + 1
  while (padded % 64 !== 56) {
    padded++
  }
  let buf = new Uint8Array(padded + 8)
  for (let i = 0; i < data.length; i++) {
    buf[i] = data[i]
  }
  buf[data.length] = 0x80
  buf[buf.length - 8] = (bitHi >>> 24) & 0xff
  buf[buf.length - 7] = (bitHi >>> 16) & 0xff
  buf[buf.length - 6] = (bitHi >>> 8) & 0xff
  buf[buf.length - 5] = bitHi & 0xff
  buf[buf.length - 4] = (bitLo >>> 24) & 0xff
  buf[buf.length - 3] = (bitLo >>> 16) & 0xff
  buf[buf.length - 2] = (bitLo >>> 8) & 0xff
  buf[buf.length - 1] = bitLo & 0xff
  let w: number[] = []
  for (let i = 0; i < 64; i++) {
    w.push(0)
  }
  for (let block = 0; block < buf.length; block += 64) {
    for (let i = 0; i < 16; i++) {
      let at = block + i * 4
      w[i] = ((buf[at] << 24) | (buf[at + 1] << 16) | (buf[at + 2] << 8) | buf[at + 3]) >>> 0
    }
    for (let i = 16; i < 64; i++) {
      let s0 = (rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3)) >>> 0
      let s1 = (rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10)) >>> 0
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0
    }
    let a = h0
    let b = h1
    let c = h2
    let d = h3
    let e = h4
    let f = h5
    let g = h6
    let h = h7
    for (let i = 0; i < 64; i++) {
      let s1 = (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) >>> 0
      let ch = ((e & f) ^ ((~e) & g)) >>> 0
      let temp1 = (h + s1 + ch + K[i] + w[i]) >>> 0
      let s0 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) >>> 0
      let maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0
      let temp2 = (s0 + maj) >>> 0
      h = g
      g = f
      f = e
      e = (d + temp1) >>> 0
      d = c
      c = b
      b = a
      a = (temp1 + temp2) >>> 0
    }
    h0 = (h0 + a) >>> 0
    h1 = (h1 + b) >>> 0
    h2 = (h2 + c) >>> 0
    h3 = (h3 + d) >>> 0
    h4 = (h4 + e) >>> 0
    h5 = (h5 + f) >>> 0
    h6 = (h6 + g) >>> 0
    h7 = (h7 + h) >>> 0
  }
  return hex32(h0) + hex32(h1) + hex32(h2) + hex32(h3) + hex32(h4) + hex32(h5) + hex32(h6) + hex32(h7)
}

function rotr(value: number, bits: number): number {
  return (value >>> bits) | (value << (32 - bits))
}

function hex32(value: number): string {
  let digits = '0123456789abcdef'
  let out = ''
  for (let shift = 28; shift >= 0; shift -= 4) {
    out += digits.charAt((value >>> shift) & 0xf)
  }
  return out
}
