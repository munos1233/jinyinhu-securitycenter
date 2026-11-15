import { CenterError } from '../main/ets/center/CenterError'
import { quarantineQuota } from '../main/ets/center/CenterLimits'
import type { FileGrant, QuarantineEntry } from '../main/ets/center/CenterTypes'
import type { FileView } from '../main/ets/system/FileOpen'
import { FileOpen } from '../main/ets/system/FileOpen'
import type { ChunkSink, ChunkSource, CipherText, QuarantineCipher, StreamSeal } from '../main/ets/record/Quarantine'
import { bytePath, Quarantine } from '../main/ets/record/Quarantine'
import { StreamingSha256 } from '../main/ets/record/StreamingSha256'
import type { ByteStore } from '../main/ets/record/Quarantine'
import type { CenterFiles } from '../main/ets/record/Writer'
import { Writer } from '../main/ets/record/Writer'

const ID: string = '0123456789abcdef0123456789abcdef'
const FROM: string = '/storage/users/a.txt'
const ROOT: string = '/storage/users'
const MANIFEST: string = 'center/quarantine/manifest.json'
const ABC: string = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'

class MemoryFiles implements CenterFiles {
  values: Map<string, string> = new Map()
  trace: string[] = []

  read(path: string): string | null {
    if (!this.values.has(path)) {
      return null
    }
    let text = this.values.get(path)
    if (text === undefined) {
      return null
    }
    return text
  }

  write(path: string, text: string): void {
    if (path.indexOf('manifest.json') >= 0) {
      this.trace.push('manifest')
    }
    this.values.set(path, text)
  }

  rename(from: string, to: string): void {
    let text = this.read(from)
    if (text === null) {
      return
    }
    this.values.delete(from)
    this.values.set(to, text)
  }

  remove(path: string): void {
    this.values.delete(path)
  }
}

class MemoryBytes implements ByteStore {
  values: Map<string, Uint8Array> = new Map()
  reads: string[] = []
  failRemove: string = ''
  failWrite: string = ''
  failRead: string = ''
  failSync: boolean = false
  fdPath: () => string = (): string => ''
  lastRead: Uint8Array | null = null
  blobPath: string = ''
  readBlobPath: string = ''
  scratch: Uint8Array = new Uint8Array(0)
  trace: string[] = []

  readFd(fd: number): Uint8Array | null {
    let data = this.read(this.fdPath())
    this.lastRead = data === null ? null : data.slice()
    return data
  }

  sizeFd(fd: number): number {
    if (fd === 10) return this.scratch.length
    if (fd === 9) return (this.values.get(this.readBlobPath) ?? new Uint8Array(0)).length
    let data = this.values.get(this.fdPath())
    return data === undefined ? -1 : data.length
  }

  readChunkFd(fd: number, offset: number, length: number): Uint8Array | null {
    if (fd === 10) return this.scratch.slice(offset, offset + length)
    if (fd === 9) return (this.values.get(this.readBlobPath) ?? new Uint8Array(0)).slice(offset, offset + length)
    let data = this.read(this.fdPath())
    return data === null ? null : data.slice(offset, offset + length)
  }

  openBlob(path: string): number {
    if (!this.writeNew(path, new Uint8Array(0))) return -1
    this.blobPath = path
    return 8
  }

  writeBlob(fd: number, data: Uint8Array): boolean {
    if (fd === 10) {
      let combined = new Uint8Array(this.scratch.length + data.length)
      combined.set(this.scratch); combined.set(data, this.scratch.length); this.scratch = combined
      return true
    }
    if (this.blobPath === this.failWrite) return false
    let old = this.values.get(this.blobPath) ?? new Uint8Array(0)
    let combined = new Uint8Array(old.length + data.length)
    combined.set(old); combined.set(data, old.length)
    this.values.set(this.blobPath, combined)
    return true
  }

  closeBlob(fd: number): void {}
  syncBlob(fd: number): void { if (this.failSync) throw new Error('sync failed') }

  openReadBlob(path: string): number {
    if (!this.values.has(path)) return -1
    this.readBlobPath = path
    return 9
  }

  openAnonymous(id: string): number { this.scratch = new Uint8Array(0); return 10 }

  writeNewFromFd(path: string, sourceFd: number, length: number): boolean {
    if (this.scratch.length !== length) return false
    return this.writeNew(path, this.scratch)
  }

  read(path: string): Uint8Array | null {
    this.reads.push(path)
    if (path === this.failRead) return null
    if (!this.values.has(path)) {
      return null
    }
    let data = this.values.get(path)
    if (data === undefined) {
      return null
    }
    return data
  }

  write(path: string, data: Uint8Array): boolean {
    if (path.indexOf('/tmp/') >= 0) this.trace.push('temp')
    if (path === this.failWrite) {
      let partial = new Uint8Array(3)
      partial[0] = 1
      partial[1] = 2
      partial[2] = 3
      this.values.set(path, partial)
      return false
    }
    this.values.set(path, data)
    return true
  }

  writeNew(path: string, data: Uint8Array): boolean {
    if (this.values.has(path)) return false
    if (!this.write(path, data)) {
      this.values.delete(path)
      return false
    }
    return true
  }

  remove(path: string): boolean {
    if (path.indexOf('/tmp/') >= 0) {
      this.trace.push('temp')
    }
    if (path === this.failRemove) {
      return false
    }
    this.values.delete(path)
    return true
  }

  async removeOriginal(fd: number, path: string, digest: string): Promise<boolean> {
    let current = this.values.get(path)
    if (current === undefined) return false
    let hash = new StreamingSha256()
    hash.update(current)
    if (hash.finish() !== digest) return false
    return this.remove(path)
  }
}

class MapView implements FileView {
  real: Map<string, string | null> = new Map()
  opened: string[] = []
  closes: number = 0

  realpath(path: string): string | null {
    if (this.real.has(path)) {
      let value = this.real.get(path)
      if (value === undefined) {
        return null
      }
      return value
    }
    return path
  }

  open(path: string): number | null {
    this.opened.push(path)
    return 7
  }

  close(fd: number): void {
    this.closes++
  }

  pathOf(fd: number): string | null {
    return null
  }
}

class FakeCipher implements QuarantineCipher {
  alias: string = ''
  bits: number = 0
  fail: boolean = false

  async encryptStream(alias: string, bits: number, length: number, source: ChunkSource,
    sink: ChunkSink): Promise<StreamSeal | null> {
    let plain = length === 0 ? new Uint8Array(0) : source.read(0, length)
    if (plain === null || plain.length !== length) return null
    let digest = new StreamingSha256()
    digest.update(plain)
    let result = await this.encrypt(alias, bits, plain)
    if (result === null || !sink.write(result.bytes)) return null
    return { iv: result.iv, tag: result.tag, sha256: digest.finish() }
  }

  async decryptStream(alias: string, bits: number, length: number, source: ChunkSource,
    sink: ChunkSink, iv: string, tag: string): Promise<string | null> {
    let bytes = length === 0 ? new Uint8Array(0) : source.read(0, length)
    if (bytes === null || bytes.length !== length) return null
    let plain = await this.decrypt(alias, bits, bytes, iv, tag)
    if (plain === null || !sink.write(plain)) return null
    let digest = new StreamingSha256()
    digest.update(plain)
    return digest.finish()
  }

  async encrypt(alias: string, bits: number, plain: Uint8Array): Promise<CipherText | null> {
    this.alias = alias
    this.bits = bits
    if (this.fail) {
      return null
    }
    let out = new Uint8Array(plain.length)
    for (let i = 0; i < plain.length; i++) {
      out[i] = plain[i] ^ 0xa5
    }
    return textOf('aXY=', 'dGFn', out)
  }

  async decrypt(alias: string, bits: number, bytes: Uint8Array, iv: string, tag: string): Promise<Uint8Array | null> {
    this.alias = alias
    this.bits = bits
    if (this.fail || iv !== 'aXY=' || tag !== 'dGFn') {
      return null
    }
    let out = new Uint8Array(bytes.length)
    for (let i = 0; i < bytes.length; i++) {
      out[i] = bytes[i] ^ 0xa5
    }
    return out
  }
}

class CipherBag implements CipherText {
  iv: string = ''
  tag: string = ''
  bytes: Uint8Array = new Uint8Array(0)
}

function textOf(iv: string, tag: string, bytes: Uint8Array): CipherText {
  let row = new CipherBag()
  row.iv = iv
  row.tag = tag
  row.bytes = bytes
  return row
}

function fail(message: string): void {
  throw new Error(message)
}

function bytesOf(text: string): Uint8Array {
  let out = new Uint8Array(text.length)
  for (let i = 0; i < text.length; i++) {
    out[i] = text.charCodeAt(i)
  }
  return out
}

function same(left: Uint8Array | null, right: Uint8Array): boolean {
  if (left === null || left.length !== right.length) {
    return false
  }
  for (let i = 0; i < left.length; i++) {
    if (left[i] !== right[i]) {
      return false
    }
  }
  return true
}

function box(files: MemoryFiles, bytes: MemoryBytes, view: MapView, cipher: FakeCipher): Quarantine {
  Writer.bind(files)
  bytes.fdPath = (): string => view.opened.length === 0 ? '' : view.opened[view.opened.length - 1]
  return new Quarantine(files, bytes, new FileOpen(view), cipher, () => {
    return ID
  })
}

function rows(files: MemoryFiles): QuarantineEntry[] {
  let text = files.read(MANIFEST)
  if (text === null) {
    return []
  }
  return JSON.parse(text) as QuarantineEntry[]
}

export async function runQuarantineChecks(): Promise<void> {
  let rooted = bytePath('/data/storage/el2/base/files', 'center/quarantine/blobs/' + ID)
  if (rooted !== '/data/storage/el2/base/files/center/quarantine/blobs/' + ID ||
    bytePath('/data/storage/el2/base/files', FROM) !== FROM) {
    fail('隔离密文没有落在 filesDir，或用户文件被改写进沙箱')
  }
  let plain = bytesOf('abc')
  let files = new MemoryFiles()
  let bytes = new MemoryBytes()
  let view = new MapView()
  let cipher = new FakeCipher()
  bytes.values.set(FROM, plain)
  let box1 = box(files, bytes, view, cipher)
  if (Quarantine.prototype['clearAll'] !== undefined) {
    fail('提供了清空全部')
  }
  let blocked = await box1.put(FROM, 1, '', '安装包', ROOT, false)
  if (!(blocked instanceof CenterError) || blocked.code !== 'unsupported' ||
    blocked.message !== '当前系统不支持此功能' || files.read(MANIFEST) !== null ||
    bytes.reads.length !== 0 || view.opened.length !== 0) {
    fail('huks 未就绪时仍然写入了隔离区')
  }

  let full = await box1.put(FROM, quarantineQuota + 1, '', '安装包', ROOT, true)
  if (!(full instanceof CenterError) || full.code !== 'quota' || full.message !== '隔离区已满' ||
    bytes.reads.length !== 0 || view.opened.length !== 0 || files.read(MANIFEST) !== null) {
    fail('配额不足时写了文件')
  }

  view.opened = []
  bytes.reads = []
  let denied = await box1.put('/system/bin/sh', 3, '', '安装包', ROOT, true)
  if (!(denied instanceof CenterError) || denied.code !== 'rejected-system-path' ||
    view.opened.length !== 0 || bytes.reads.length !== 0 || bytes.values.has('/system/bin/sh')) {
    fail('系统路径被隔离或读取了')
  }
  let privateDenied = await box1.put('/data/app/readme', 3, '', '安装包', '/storage/media', true)
  if (!(privateDenied instanceof CenterError) || privateDenied.code !== 'rejected-system-path' ||
    bytes.reads.length !== 0) {
    fail('/data/app 没有跟 FileOpen 同一套拒绝')
  }
  view.real.set('/storage/users/link', '/dev/null')
  bytes.values.set('/storage/users/link', plain)
  let linked = await box1.put('/storage/users/link', 3, '', '安装包', ROOT, true)
  if (!(linked instanceof CenterError) || linked.code !== 'rejected-system-path' ||
    bytes.values.has('/storage/users/link') !== true) {
    fail('指向系统目录的符号链接被读取了')
  }

  bytes.reads = []
  let mismatch = await box1.put(FROM, plain.length, 'aa', '安装包', ROOT, true)
  if (!(mismatch instanceof CenterError) || mismatch.code !== 'io' || files.read(MANIFEST) !== null ||
    bytes.values.has(FROM) !== true || bytes.values.has('center/quarantine/tmp/' + ID) === true) {
    fail('哈希不一致时改了源文件或留下了明文')
  }

  cipher.fail = true
  let encryptFail = await box1.put(FROM, plain.length, '', '安装包', ROOT, true)
  cipher.fail = false
  if (!(encryptFail instanceof CenterError) || encryptFail.code !== 'io' || files.read(MANIFEST) !== null ||
    bytes.values.has('center/quarantine/blobs/' + ID) === true ||
    bytes.values.has('center/quarantine/tmp/' + ID) === true || bytes.values.has(FROM) !== true) {
    fail('加密失败留下了明文或清单')
  }

  bytes.failRemove = FROM
  let kept = await box1.put(FROM, plain.length, '', '安装包', ROOT, true)
  bytes.failRemove = ''
  if (kept instanceof CenterError || kept.committed || kept.sha256 !== ABC || kept.stored !== ID ||
    kept.id.length !== 32 || kept.id !== ID || kept.stored.indexOf('.') >= 0 || kept.iv !== 'aXY=' ||
    kept.tag !== 'dGFn' || cipher.alias !== 'jinyinhu.center.quarantine' || cipher.bits !== 256) {
    fail('删源失败时没有留下 committed=false，或空串哈希没有写入算出的值')
  }
  let listed = rows(files)
  let blob = bytes.values.get('center/quarantine/blobs/' + ID)
  if (listed.length !== 1 || listed[0].committed || bytes.values.has(FROM) !== true ||
    bytes.values.has('center/quarantine/tmp/' + ID) === true || same(blob === undefined ? null : blob, plain)) {
    fail('未完成条目删了源，或密文目录里有明文')
  }
  let existing = bytesOf('existing destination')
  bytes.values.set(FROM, existing)
  let refusesOverwrite = await box1.restore(ID, ROOT, '')
  if (!(refusesOverwrite instanceof CenterError) || !same(bytes.values.get(FROM) ?? null, existing) || rows(files).length !== 1) {
    fail('恢复不得覆盖已存在的目标，也不得删除隔离清单')
  }
  bytes.values.set(FROM, plain)

  bytes.values.delete('center/quarantine/blobs/' + ID)
  files.values.delete(MANIFEST)
  bytes.trace = []
  files.trace = bytes.trace
  view.closes = 0
  let done = await box1.put(FROM, plain.length, ABC, '安装包', ROOT, true)
  if (view.closes !== 1) {
    fail('隔离复制后没有关闭文件')
  }
  let manifestAt = bytes.trace.indexOf('manifest')
  if (bytes.trace.indexOf('temp') >= 0 || manifestAt < 0) {
    fail('隔离过程不应写入临时明文，并应写入清单')
  }
  if (done instanceof CenterError || !done.committed || done.sha256 !== ABC || bytes.values.has(FROM) === true) {
    fail('删源成功后没有把清单改成 committed=true')
  }
  bytes.reads = []
  let overflow = await box1.put('/storage/users/b.txt', quarantineQuota, '', '安装包', ROOT, true)
  if (!(overflow instanceof CenterError) || overflow.code !== 'quota' ||
    bytes.reads.indexOf('/storage/users/b.txt') >= 0) {
    fail('已有明文后再放入超额文件没有拒绝')
  }

  files.values.delete(MANIFEST)
  bytes.values.delete('center/quarantine/blobs/' + ID)
  bytes.values.set(FROM, plain)
  let restored = await box1.put(FROM, plain.length, '', '安装包', ROOT, true)
  if (restored instanceof CenterError) {
    fail('恢复前的隔离失败')
    return
  }
  let back = await box1.restore(ID, ROOT, '')
  if (back !== null || !same(bytes.values.get(FROM) === undefined ? null : bytes.values.get(FROM) as Uint8Array, plain) ||
    rows(files).length !== 0) {
    fail('恢复没有把明文写回原路径或没有从清单去掉')
  }

  bytes.values.set(FROM, plain)
  await box1.put(FROM, plain.length, '', '安装包', ROOT, true)
  let edited = rows(files)
  edited[0].sha256 = '00'
  files.write(MANIFEST, JSON.stringify(edited))
  let badHash = await box1.restore(ID, ROOT, '')
  if (!(badHash instanceof CenterError) || badHash.code !== 'io' || rows(files).length !== 1 ||
    bytes.values.has(FROM) === true) {
    fail('明文哈希不符时写回了文件或删了清单')
  }

  edited = rows(files)
  edited[0].sha256 = ABC
  edited[0].from = '/system/bin/sh'
  files.write(MANIFEST, JSON.stringify(edited))
  let badTarget = await box1.restore(ID, ROOT, '')
  if (!(badTarget instanceof CenterError) || badTarget.code !== 'rejected-system-path' ||
    bytes.values.has('/system/bin/sh') === true || rows(files).length !== 1) {
    fail('恢复目标被拒绝时仍然写了文件')
  }

  bytes.failWrite = '/storage/other/b.txt'
  let partial = await box1.restore(ID, '/storage/other', '/storage/other/b.txt')
  bytes.failWrite = ''
  if (!(partial instanceof CenterError) || rows(files)[0].from !== '/system/bin/sh' ||
    bytes.values.has('/storage/other/b.txt') === true) {
    fail('另选目录写失败时改了清单或留下了残缺文件')
  }

  let moved = await box1.restore(ID, '/storage/other', '/storage/other/b.txt')
  if (moved !== null || rows(files).length !== 0 ||
    !same(bytes.values.get('/storage/other/b.txt') === undefined ? null : bytes.values.get('/storage/other/b.txt') as Uint8Array, plain)) {
    fail('另选目录通过 FileOpen 后没有写回，或写回前就改了清单')
  }

  let files2 = new MemoryFiles()
  let bytes2 = new MemoryBytes()
  let view2 = new MapView()
  let cipher2 = new FakeCipher()
  bytes2.values.set(FROM, plain)
  bytes2.values.set('/storage/users/b.txt', plain)
  let box2 = box(files2, bytes2, view2, cipher2)
  bytes2.failRead = FROM
  let copyFail = await box2.put(FROM, plain.length, '', '安装包', ROOT, true)
  bytes2.failRead = ''
  if (!(copyFail instanceof CenterError) || copyFail.code !== 'io' || files2.read(MANIFEST) !== null ||
    bytes2.values.has('center/quarantine/tmp/' + ID) === true || bytes2.values.has(FROM) !== true) {
    fail('复制失败不是 io，或留下了临时明文和清单')
  }
  let first = await box2.put(FROM, quarantineQuota - 1, '', '安装包', ROOT, true)
  if (first instanceof CenterError || first.size !== quarantineQuota - 1) {
    fail('第一份不到配额的明文没有记入累计')
    return
  }
  bytes2.values.set(FROM, plain)
  bytes2.reads = []
  let second = await box2.put('/storage/users/b.txt', 2, '', '安装包', ROOT, true)
  if (!(second instanceof CenterError) || second.code !== 'quota' || second.message !== '隔离区已满' ||
    bytes2.reads.indexOf('/storage/users/b.txt') >= 0 || rows(files2).length !== 1) {
    fail('两份都不到配额、加在一起超过时没有拒绝')
  }

  let files3 = new MemoryFiles()
  let bytes3 = new MemoryBytes()
  let view3 = new MapView()
  let cipher3 = new FakeCipher()
  bytes3.values.set(FROM, plain)
  let box3 = box(files3, bytes3, view3, cipher3)
  let viaUri = await box3.put('file://' + FROM, plain.length, '', '安装包', ROOT, true)
  if (viaUri instanceof CenterError || !viaUri.committed || bytes3.values.has(FROM)) {
    fail('file:// 没有按解析出的路径完成隔离')
  }
  let backUri = await box3.restore(ID, ROOT, '')
  if (backUri !== null || !same(bytes3.values.get(FROM) === undefined ? null : bytes3.values.get(FROM) as Uint8Array, plain) ||
    rows(files3).length !== 0) {
    fail('源文件已经删除后没有写回原路径')
  }

  let files4 = new MemoryFiles()
  let bytes4 = new MemoryBytes()
  let view4 = new MapView()
  let cipher4 = new FakeCipher()
  bytes4.values.set(FROM, plain)
  let box4 = box(files4, bytes4, view4, cipher4)
  bytes4.failRemove = FROM
  let pending = await box4.put(FROM, plain.length, '', '安装包', ROOT, true)
  bytes4.failRemove = ''
  if (pending instanceof CenterError || pending.committed) {
    fail('删除测试前没有留下未完成条目')
    return
  }
  let shown = box4.list()
  if (shown === null || shown.length !== 1 || shown[0].committed || shown[0].from !== FROM) {
    fail('隔离区列表没有读出未完成条目')
  }
  let tampered = rows(files4)
  tampered[0].stored = '../../other-file'
  files4.write(MANIFEST, JSON.stringify(tampered))
  bytes4.values.set('center/quarantine/blobs/../../other-file', plain)
  let blockedDelete = await box4.discard(pending.id)
  if (!(blockedDelete instanceof CenterError) || rows(files4).length !== 1 ||
    !bytes4.values.has('center/quarantine/blobs/../../other-file')) {
    fail('损坏清单里的密文路径不得用于删除其他文件')
  }
  tampered[0].stored = pending.id
  files4.write(MANIFEST, JSON.stringify(tampered))
  let dropped = await box4.discard(pending.id)
  if (dropped !== null || rows(files4).length !== 0 || bytes4.values.has(FROM) !== true ||
    bytes4.values.has('center/quarantine/blobs/' + ID) === true) {
    fail('删除隔离项时删了原文件，或没有去掉清单和密文')
  }
  files4.write(MANIFEST, '{')
  if (box4.list() !== null) {
    fail('坏清单被显示成空的隔离区')
  }

  let files5 = new MemoryFiles()
  let bytes5 = new MemoryBytes()
  let view5 = new MapView()
  let cipher5 = new PausedCipher()
  bytes5.values.set(FROM, plain)
  bytes5.values.set('/storage/users/b.txt', plain)
  let box5 = box(files5, bytes5, view5, cipher5)
  let firstPending = box5.put(FROM, quarantineQuota - 1, '', '安装包', ROOT, true)
  await cipher5.started
  let secondPending = box5.put('/storage/users/b.txt', 2, '', '安装包', ROOT, true)
  cipher5.resume()
  let firstConcurrent = await firstPending
  let secondConcurrent = await secondPending
  if (firstConcurrent instanceof CenterError || !(secondConcurrent instanceof CenterError) ||
    secondConcurrent.code !== 'quota' || !bytes5.values.has('/storage/users/b.txt')) {
    fail('并发隔离必须串行计算配额，超额时保留源文件')
  }

  let files6 = new MemoryFiles()
  let bytes6 = new MemoryBytes()
  let view6 = new MapView()
  bytes6.values.set(FROM, plain)
  let changed = bytesOf('xyz')
  let cipher6 = new ChangingCipher(bytes6, changed)
  let box6 = box(files6, bytes6, view6, cipher6)
  let changedResult = await box6.put(FROM, plain.length, '', '安装包', ROOT, true)
  if (changedResult instanceof CenterError || changedResult.committed ||
    !same(bytes6.values.get(FROM) ?? null, changed)) {
    fail('加密期间源文件发生变化时必须保留新文件并标记未完成')
  }

  let files7 = new MemoryFiles()
  let bytes7 = new MemoryBytes()
  let view7 = new MapView()
  bytes7.values.set(FROM, plain)
  let previousBlob = bytesOf('existing encrypted data')
  bytes7.values.set('center/quarantine/blobs/' + ID, previousBlob)
  let box7 = box(files7, bytes7, view7, new FakeCipher())
  let collision = await box7.put(FROM, plain.length, '', '安装包', ROOT, true)
  if (!(collision instanceof CenterError) || !same(bytes7.values.get('center/quarantine/blobs/' + ID) ?? null, previousBlob) ||
    !bytes7.values.has(FROM) || files7.read(MANIFEST) !== null) {
    fail('密文文件名碰撞不得覆盖现有密文或删除源文件')
  }

  let files8 = new MemoryFiles()
  let bytes8 = new MemoryBytes()
  bytes8.values.set(FROM, plain)
  bytes8.failSync = true
  let box8 = box(files8, bytes8, new MapView(), new FakeCipher())
  let syncFailure = await box8.put(FROM, plain.length, '', '安装包', ROOT, true)
  if (!(syncFailure instanceof CenterError) || !bytes8.values.has(FROM) ||
    bytes8.values.has('center/quarantine/blobs/' + ID) || files8.read(MANIFEST) !== null) {
    fail('密文持久化失败不得删除源文件或写清单')
  }
}

class PausedCipher extends FakeCipher {
  resume: () => void = (): void => {}
  startedResolve: () => void = (): void => {}
  started: Promise<void> = new Promise<void>((resolve: () => void): void => { this.startedResolve = resolve })
  async encrypt(alias: string, bits: number, plain: Uint8Array): Promise<CipherText | null> {
    await new Promise<void>((resolve: () => void): void => { this.resume = resolve; this.startedResolve() })
    return await super.encrypt(alias, bits, plain)
  }
}

class ChangingCipher extends FakeCipher {
  private bytes: MemoryBytes
  private replacement: Uint8Array
  constructor(bytes: MemoryBytes, replacement: Uint8Array) {
    super()
    this.bytes = bytes
    this.replacement = replacement
  }
  async encrypt(alias: string, bits: number, plain: Uint8Array): Promise<CipherText | null> {
    let result = await super.encrypt(alias, bits, plain)
    this.bytes.values.set(FROM, this.replacement)
    return result
  }
}
