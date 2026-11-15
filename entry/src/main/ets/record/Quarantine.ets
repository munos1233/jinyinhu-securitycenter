import fs from '@ohos.file.fs';
import { hilog } from '@kit.PerformanceAnalysisKit';
import { nowIso } from '../center/Clock';
import { CenterError } from '../center/CenterError';
import { quarantineQuota } from '../center/CenterLimits';
import type { FileGrant, QuarantineEntry } from '../center/CenterTypes';
import { FileOpen } from '../system/FileOpen';
import { HashWorker } from '../engine/HashWorker';
import type { CenterFiles } from './Writer';
import { Writer } from './Writer';

const DOMAIN: number = 0x4A59
const TAG: string = 'Center'
const KEY_ALIAS: string = 'jinyinhu.center.quarantine'
const KEY_BITS: number = 256
const MANIFEST: string = 'center/quarantine/manifest.json'
const BLOB_DIR: string = 'center/quarantine/blobs/'

export interface CipherText {
  iv: string
  tag: string
  bytes: Uint8Array
}

export interface QuarantineCipher {
  encrypt(alias: string, bits: number, plain: Uint8Array): Promise<CipherText | null>
  decrypt(alias: string, bits: number, bytes: Uint8Array, iv: string, tag: string): Promise<Uint8Array | null>
  encryptStream(alias: string, bits: number, length: number, source: ChunkSource,
    sink: ChunkSink): Promise<StreamSeal | null>
  decryptStream(alias: string, bits: number, length: number, source: ChunkSource,
    sink: ChunkSink, iv: string, tag: string): Promise<string | null>
}

export interface ChunkSource { read(offset: number, length: number): Uint8Array | null }
export interface ChunkSink { write(bytes: Uint8Array): boolean }
export interface StreamSeal { iv: string; tag: string; sha256: string }

export interface ByteStore {
  read(path: string): Uint8Array | null
  readFd(fd: number): Uint8Array | null
  write(path: string, data: Uint8Array): boolean
  writeNew(path: string, data: Uint8Array): boolean
  remove(path: string): boolean
  removeOriginal(fd: number, path: string, digest: string): Promise<boolean>
  sizeFd(fd: number): number
  readChunkFd(fd: number, offset: number, length: number): Uint8Array | null
  openBlob(path: string): number
  writeBlob(fd: number, data: Uint8Array): boolean
  syncBlob(fd: number): void
  closeBlob(fd: number): void
  openReadBlob(path: string): number
  openAnonymous(id: string): number
  writeNewFromFd(path: string, sourceFd: number, length: number): boolean
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
  private blobs: Map<number, fs.File> = new Map<number, fs.File>()

  constructor(root: string) {
    this.root = root
  }

  read(path: string): Uint8Array | null {
    try {
      let file = fs.openSync(bytePath(this.root, path), fs.OpenMode.READ_ONLY)
      try {
        return readWhole(file.fd)
      } finally {
        fs.closeSync(file)
      }
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

  sizeFd(fd: number): number {
    try { return fs.statSync(fd).size } catch (err) { return -1 }
  }

  readChunkFd(fd: number, offset: number, length: number): Uint8Array | null {
    try {
      let buffer = new ArrayBuffer(length)
      let count = fs.readSync(fd, buffer, { offset: offset, length: length })
      if (count <= 0 || count > length) return null
      return new Uint8Array(buffer, 0, count)
    } catch (err) { return null }
  }

  openBlob(path: string): number {
    let full = bytePath(this.root, path)
    try {
      let slash = full.lastIndexOf('/')
      if (slash > 0) { try { fs.mkdirSync(full.substring(0, slash), true) } catch (ignored) { } }
      let file = fs.openSync(full, fs.OpenMode.CREATE | fs.OpenMode.WRITE_ONLY | fs.OpenMode.NOFOLLOW | 0o200)
      this.blobs.set(file.fd, file)
      return file.fd
    } catch (err) { return -1 }
  }

  writeBlob(fd: number, data: Uint8Array): boolean {
    try { return writeAll(fd, data) } catch (err) { return false }
  }

  syncBlob(fd: number): void { fs.fsyncSync(fd) }

  closeBlob(fd: number): void {
    let file = this.blobs.get(fd)
    if (file === undefined) throw new Error('unknown blob')
    try { fs.closeSync(file) } finally { this.blobs.delete(fd) }
  }

  openReadBlob(path: string): number {
    try {
      let file = fs.openSync(bytePath(this.root, path), fs.OpenMode.READ_ONLY | fs.OpenMode.NOFOLLOW)
      this.blobs.set(file.fd, file)
      return file.fd
    } catch (err) { return -1 }
  }

  /** The directory entry is removed before any plaintext is written. */
  openAnonymous(id: string): number {
    let full = bytePath(this.root, 'center/quarantine/tmp/' + id)
    let file: fs.File | null = null
    try {
      let slash = full.lastIndexOf('/')
      if (slash > 0) { try { fs.mkdirSync(full.substring(0, slash), true) } catch (ignored) { } }
      file = fs.openSync(full, fs.OpenMode.CREATE | fs.OpenMode.READ_WRITE | fs.OpenMode.NOFOLLOW | 0o200)
      fs.unlinkSync(full)
      this.blobs.set(file.fd, file)
      return file.fd
    } catch (err) {
      if (file !== null) { try { fs.closeSync(file) } catch (ignored) { } }
      return -1
    }
  }

  writeNewFromFd(path: string, sourceFd: number, length: number): boolean {
    let full = bytePath(this.root, path)
    let file: fs.File | null = null
    let ok = false
    let inode: bigint | null = null
    try {
      file = fs.openSync(full, fs.OpenMode.CREATE | fs.OpenMode.WRITE_ONLY | fs.OpenMode.NOFOLLOW | 0o200)
      inode = fs.statSync(file.fd).ino
      let offset = 0
      while (offset < length) {
        let data = this.readChunkFd(sourceFd, offset, Math.min(64 * 1024, length - offset))
        if (data === null || !writeAll(file.fd, data)) throw new Error('copy failed')
        offset += data.length
      }
      fs.fsyncSync(file.fd)
      ok = true
    } catch (err) {
      if (file !== null) {
        try {
          let opened = fs.statSync(file.fd)
          let current = fs.lstatSync(full)
          if (opened.ino === current.ino && current.isFile() && !current.isSymbolicLink()) fs.unlinkSync(full)
        } catch (ignored) { }
      }
    } finally {
      if (file !== null) { try { fs.closeSync(file) } catch (err) { ok = false } }
    }
    if (!ok && inode !== null) {
      try {
        let current = fs.lstatSync(full)
        if (current.ino === inode && current.isFile() && !current.isSymbolicLink()) fs.unlinkSync(full)
      } catch (ignored) { }
    }
    return ok
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
      try {
        if (!writeAll(file.fd, data)) return false
      } finally {
        fs.closeSync(file)
      }
      return true
    } catch (err) {
      return false
    }
  }

  /** O_EXCL prevents replacing an existing destination, including one created concurrently. */
  writeNew(path: string, data: Uint8Array): boolean {
    let full = bytePath(this.root, path)
    let created = false
    try {
      if (path.startsWith(BLOB_DIR)) {
        let slash = full.lastIndexOf('/')
        if (slash > 0) {
          try { fs.mkdirSync(full.substring(0, slash), true) } catch (ignored) { }
        }
      }
      // POSIX O_EXCL is 0o200. If the SDK rejects this flag, fail closed.
      let file = fs.openSync(full, fs.OpenMode.CREATE | fs.OpenMode.WRITE_ONLY | fs.OpenMode.NOFOLLOW | 0o200)
      created = true
      try {
        if (!writeAll(file.fd, data)) throw new Error('short write')
      } finally {
        fs.closeSync(file)
      }
      return true
    } catch (err) {
      if (created) {
        try { fs.unlinkSync(full) } catch (ignored) { }
      }
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

  async removeOriginal(fd: number, path: string, digest: string): Promise<boolean> {
    try {
      let opened = fs.statSync(fd)
      let current = fs.lstatSync(path)
      if (!opened.isFile() || !current.isFile() || current.isSymbolicLink() ||
        opened.ino !== current.ino || opened.size !== current.size) return false
      let result = await new HashWorker().hash(fd, new SharedArrayBuffer(4))
      if (result.sha256 !== digest || result.bytes !== opened.size) return false
      let last = fs.lstatSync(path)
      if (!last.isFile() || last.isSymbolicLink() || last.ino !== opened.ino || last.size !== opened.size) return false
      fs.unlinkSync(path)
      return true
    } catch (err) {
      return false
    }
  }
}

function writeAll(fd: number, data: Uint8Array): boolean {
  let offset = 0
  while (offset < data.length) {
    let end = Math.min(offset + 1024 * 1024, data.length)
    let buffer = data.buffer.slice(data.byteOffset + offset, data.byteOffset + end)
    if (fs.writeSync(fd, buffer) !== end - offset) return false
    offset = end
  }
  return true
}

function readWhole(fd: number): Uint8Array {
  let stat = fs.statSync(fd)
  if (stat.size < 0 || stat.size > quarantineQuota) throw new Error('file exceeds quarantine limit')
  if (stat.size === 0) {
    return new Uint8Array(0)
  }
  let bytes = new Uint8Array(stat.size)
  let offset = 0
  while (offset < bytes.length) {
    let length = Math.min(1024 * 1024, bytes.length - offset)
    let chunk = new ArrayBuffer(length)
    let count = fs.readSync(fd, chunk, { offset: offset, length: length })
    if (count <= 0 || count > length) throw new Error('short read')
    bytes.set(new Uint8Array(chunk, 0, count), offset)
    offset += count
  }
  if (fs.statSync(fd).size !== stat.size) throw new Error('file changed during read')
  return bytes
}

export class Quarantine {
  private files: CenterFiles
  private bytes: ByteStore
  private opener: FileOpen
  private cipher: QuarantineCipher
  private ids: () => string
  private pending: Promise<void> = Promise.resolve()

  constructor(files: CenterFiles, bytes: ByteStore, opener: FileOpen, cipher: QuarantineCipher,
    ids: () => string) {
    this.files = files
    this.bytes = bytes
    this.opener = opener
    this.cipher = cipher
    this.ids = ids
  }

  async put(from: string, size: number, sha256: string, reason: string, root: string,
    huksReady: boolean): Promise<CenterError | QuarantineEntry> {
    return await this.serialize(async (): Promise<CenterError | QuarantineEntry> =>
      await this.putOnce(from, size, sha256, reason, root, huksReady))
  }

  private async putOnce(from: string, size: number, sha256: string, reason: string, root: string,
    huksReady: boolean): Promise<CenterError | QuarantineEntry> {
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
    let id: string
    try { id = this.ids() } catch (err) { this.opener.release(held); return this.error('io', 'id') }
    if (!/^[0-9a-f]{32}$/.test(id)) {
      this.opener.release(held)
      return this.error('io', 'id')
    }
    let blob = BLOB_DIR + id
    try {
      let actualSize = this.bytes.sizeFd(held.fd)
      if (actualSize < 0 || actualSize > quarantineQuota) return this.error('quota', '')
      let counted = actualSize > size ? actualSize : size
      let again = Writer.exclusive(() => this.quotaState(counted))
      if (again !== 0) return again === 1 ? this.error('quota', '') : this.error('io', MANIFEST)
      let blobFd = this.bytes.openBlob(blob)
      if (blobFd < 0) return this.error('io', blob)
      let seal: StreamSeal | null = null
      let closed = false
      try {
        seal = await this.cipher.encryptStream(KEY_ALIAS, KEY_BITS, actualSize,
          new DescriptorSource(this.bytes, held.fd), new DescriptorSink(this.bytes, blobFd))
        if (seal !== null) this.bytes.syncBlob(blobFd)
        this.bytes.closeBlob(blobFd)
        closed = true
      } catch (err) {
        seal = null
      } finally {
        if (!closed) { try { this.bytes.closeBlob(blobFd) } catch (ignored) { } }
      }
      if (seal === null || (sha256.length > 0 && sha256 !== seal.sha256) ||
        this.bytes.sizeFd(held.fd) !== actualSize) {
        this.bytes.remove(blob)
        return this.error('io', blob)
      }
      let digest = seal.sha256
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
      if (!(await this.bytes.removeOriginal(held.fd, source, digest))) {
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
    }
  }

  async restore(id: string, root: string, choose: string): Promise<CenterError | null> {
    return await this.serialize(async (): Promise<CenterError | null> => await this.restoreOnce(id, root, choose))
  }

  private async restoreOnce(id: string, root: string, choose: string): Promise<CenterError | null> {
    let found = Writer.exclusive(() => {
      return this.find(id)
    })
    if (found === null) {
      return this.error('io', id)
    }
    if (!/^[0-9a-f]{32}$/.test(id) || found.stored !== id) return this.error('io', id)
    let encryptedFd = this.bytes.openReadBlob(BLOB_DIR + id)
    if (encryptedFd < 0) return this.error('io', found.stored)
    let temporaryFd = -1
    try {
      let length = this.bytes.sizeFd(encryptedFd)
      if (length < 0 || length > quarantineQuota) return this.error('io', found.stored)
      temporaryFd = this.bytes.openAnonymous(id)
      if (temporaryFd < 0) return this.error('io', id)
      let digest = await this.cipher.decryptStream(KEY_ALIAS, KEY_BITS, length,
        new DescriptorSource(this.bytes, encryptedFd), new DescriptorSink(this.bytes, temporaryFd), found.iv, found.tag)
      if (digest === null || digest !== found.sha256 || this.bytes.sizeFd(temporaryFd) !== length) {
        return this.error('io', found.sha256)
      }
      let dest = this.destination(found.from, root, choose)
      if (dest instanceof CenterError) {
        return dest
      }
      if (!this.bytes.writeNewFromFd(dest, temporaryFd, length)) {
        return this.error('io', dest)
      }
      let removed = Writer.exclusive(() => {
        return this.removeEntry(id)
      })
      if (!removed) {
        return this.error('io', MANIFEST)
      }
      this.bytes.remove(BLOB_DIR + found.stored)
      return null
    } catch (err) {
      return this.error('io', id)
    } finally {
      if (temporaryFd >= 0) { try { this.bytes.closeBlob(temporaryFd) } catch (ignored) { } }
      try { this.bytes.closeBlob(encryptedFd) } catch (ignored) { }
    }
  }

  list(): QuarantineEntry[] | null {
    return Writer.exclusive(() => {
      return this.readManifest()
    })
  }

  /** 去掉清单和密文。不删除 from 指向的原文件。 */
  async discard(id: string): Promise<CenterError | null> {
    return await this.serialize(async (): Promise<CenterError | null> => this.discardOnce(id))
  }

  private discardOnce(id: string): CenterError | null {
    let found = Writer.exclusive(() => {
      return this.find(id)
    })
    if (found === null) {
      return this.error('io', id)
    }
    if (!/^[0-9a-f]{32}$/.test(id) || found.stored !== id) return this.error('io', id)
    let removed = Writer.exclusive(() => {
      return this.removeEntry(id)
    })
    if (!removed) {
      return this.error('io', MANIFEST)
    }
    this.bytes.remove(BLOB_DIR + found.stored)
    return null
  }

  private async serialize<T>(work: () => Promise<T>): Promise<T> {
    let prior = this.pending
    let release: () => void = (): void => {}
    this.pending = new Promise<void>((resolve: () => void): void => { release = resolve })
    await prior
    try {
      return await work()
    } finally {
      release()
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

class DescriptorSource implements ChunkSource {
  private store: ByteStore
  private fd: number
  constructor(store: ByteStore, fd: number) { this.store = store; this.fd = fd }
  read(offset: number, length: number): Uint8Array | null { return this.store.readChunkFd(this.fd, offset, length) }
}

class DescriptorSink implements ChunkSink {
  private store: ByteStore
  private fd: number
  constructor(store: ByteStore, fd: number) { this.store = store; this.fd = fd }
  write(bytes: Uint8Array): boolean { return this.store.writeBlob(this.fd, bytes) }
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
