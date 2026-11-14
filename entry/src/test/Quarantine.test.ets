import { CenterError } from '../main/ets/center/CenterError'
import { quarantineQuota } from '../main/ets/center/CenterLimits'
import type { FileGrant, QuarantineEntry } from '../main/ets/center/CenterTypes'
import type { FileView } from '../main/ets/system/FileOpen'
import { FileOpen } from '../main/ets/system/FileOpen'
import type { ByteStore, CipherText, QuarantineCipher } from '../main/ets/record/Quarantine'
import { Quarantine } from '../main/ets/record/Quarantine'
import type { CenterFiles } from '../main/ets/record/Writer'
import { Writer } from '../main/ets/record/Writer'

const ID: string = '0123456789abcdef0123456789abcdef'
const FROM: string = '/storage/users/a.txt'
const ROOT: string = '/storage/users'
const MANIFEST: string = 'center/quarantine/manifest.json'
const ABC: string = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'

class MemoryFiles implements CenterFiles {
  values: Map<string, string> = new Map()

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

  read(path: string): Uint8Array | null {
    this.reads.push(path)
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

  remove(path: string): boolean {
    if (path === this.failRemove) {
      return false
    }
    this.values.delete(path)
    return true
  }
}

class MapView implements FileView {
  real: Map<string, string | null> = new Map()
  opened: string[] = []

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
  }

  pathOf(fd: number): string | null {
    return null
  }
}

class FakeCipher implements QuarantineCipher {
  alias: string = ''
  bits: number = 0
  fail: boolean = false

  encrypt(alias: string, bits: number, plain: Uint8Array): CipherText | null {
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

  decrypt(alias: string, bits: number, bytes: Uint8Array, iv: string, tag: string): Uint8Array | null {
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

export function runQuarantineChecks(): void {
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
  let blocked = box1.put(FROM, 1, '', '安装包', ROOT, false)
  if (!(blocked instanceof CenterError) || blocked.code !== 'unsupported' ||
    blocked.message !== '当前系统不支持此功能' || files.read(MANIFEST) !== null ||
    bytes.reads.length !== 0 || view.opened.length !== 0) {
    fail('huks 未就绪时仍然写入了隔离区')
  }

  let full = box1.put(FROM, quarantineQuota + 1, '', '安装包', ROOT, true)
  if (!(full instanceof CenterError) || full.code !== 'quota' || full.message !== '隔离区已满' ||
    bytes.reads.length !== 0 || view.opened.length !== 0 || files.read(MANIFEST) !== null) {
    fail('配额不足时写了文件')
  }

  view.opened = []
  bytes.reads = []
  let denied = box1.put('/system/bin/sh', 3, '', '安装包', ROOT, true)
  if (!(denied instanceof CenterError) || denied.code !== 'rejected-system-path' ||
    view.opened.length !== 0 || bytes.reads.length !== 0 || bytes.values.has('/system/bin/sh')) {
    fail('系统路径被隔离或读取了')
  }
  let privateDenied = box1.put('/data/app/readme', 3, '', '安装包', '/storage/media', true)
  if (!(privateDenied instanceof CenterError) || privateDenied.code !== 'rejected-system-path' ||
    bytes.reads.length !== 0) {
    fail('/data/app 没有跟 FileOpen 同一套拒绝')
  }
  view.real.set('/storage/users/link', '/dev/null')
  bytes.values.set('/storage/users/link', plain)
  let linked = box1.put('/storage/users/link', 3, '', '安装包', ROOT, true)
  if (!(linked instanceof CenterError) || linked.code !== 'rejected-system-path' ||
    bytes.values.has('/storage/users/link') !== true) {
    fail('指向系统目录的符号链接被读取了')
  }

  bytes.reads = []
  let mismatch = box1.put(FROM, plain.length, 'aa', '安装包', ROOT, true)
  if (!(mismatch instanceof CenterError) || mismatch.code !== 'io' || files.read(MANIFEST) !== null ||
    bytes.values.has(FROM) !== true || bytes.values.has('center/quarantine/tmp/' + ID) === true) {
    fail('哈希不一致时改了源文件或留下了明文')
  }

  cipher.fail = true
  let encryptFail = box1.put(FROM, plain.length, '', '安装包', ROOT, true)
  cipher.fail = false
  if (!(encryptFail instanceof CenterError) || encryptFail.code !== 'io' || files.read(MANIFEST) !== null ||
    bytes.values.has('center/quarantine/blobs/' + ID) === true ||
    bytes.values.has('center/quarantine/tmp/' + ID) === true || bytes.values.has(FROM) !== true) {
    fail('加密失败留下了明文或清单')
  }

  bytes.failRemove = FROM
  let kept = box1.put(FROM, plain.length, '', '安装包', ROOT, true)
  bytes.failRemove = ''
  if (kept instanceof CenterError || kept.committed || kept.sha256 !== ABC || kept.stored !== ID ||
    kept.id !== ID || kept.stored.indexOf('.') >= 0 || cipher.alias !== 'jinyinhu.center.quarantine' ||
    cipher.bits !== 256) {
    fail('删源失败时没有留下 committed=false，或空串哈希没有写入算出的值')
  }
  let listed = rows(files)
  let blob = bytes.values.get('center/quarantine/blobs/' + ID)
  if (listed.length !== 1 || listed[0].committed || bytes.values.has(FROM) !== true ||
    bytes.values.has('center/quarantine/tmp/' + ID) === true || same(blob === undefined ? null : blob, plain)) {
    fail('未完成条目删了源，或密文目录里有明文')
  }

  bytes.values.delete('center/quarantine/blobs/' + ID)
  files.values.delete(MANIFEST)
  let done = box1.put(FROM, plain.length, ABC, '安装包', ROOT, true)
  if (done instanceof CenterError || !done.committed || done.sha256 !== ABC || bytes.values.has(FROM) === true) {
    fail('删源成功后没有把清单改成 committed=true')
  }
  bytes.reads = []
  let overflow = box1.put('/storage/users/b.txt', quarantineQuota, '', '安装包', ROOT, true)
  if (!(overflow instanceof CenterError) || overflow.code !== 'quota' ||
    bytes.reads.indexOf('/storage/users/b.txt') >= 0) {
    fail('已有明文后再放入超额文件没有拒绝')
  }

  files.values.delete(MANIFEST)
  bytes.values.set(FROM, plain)
  let restored = box1.put(FROM, plain.length, '', '安装包', ROOT, true)
  if (restored instanceof CenterError) {
    fail('恢复前的隔离失败')
    return
  }
  let back = box1.restore(ID, ROOT, '')
  if (back !== null || !same(bytes.values.get(FROM) === undefined ? null : bytes.values.get(FROM) as Uint8Array, plain) ||
    rows(files).length !== 0) {
    fail('恢复没有把明文写回原路径或没有从清单去掉')
  }

  bytes.values.set(FROM, plain)
  box1.put(FROM, plain.length, '', '安装包', ROOT, true)
  let edited = rows(files)
  edited[0].sha256 = '00'
  files.write(MANIFEST, JSON.stringify(edited))
  let badHash = box1.restore(ID, ROOT, '')
  if (!(badHash instanceof CenterError) || badHash.code !== 'io' || rows(files).length !== 1 ||
    bytes.values.has(FROM) === true) {
    fail('明文哈希不符时写回了文件或删了清单')
  }

  edited = rows(files)
  edited[0].sha256 = ABC
  edited[0].from = '/system/bin/sh'
  files.write(MANIFEST, JSON.stringify(edited))
  let badTarget = box1.restore(ID, ROOT, '')
  if (!(badTarget instanceof CenterError) || badTarget.code !== 'rejected-system-path' ||
    bytes.values.has('/system/bin/sh') === true || rows(files).length !== 1) {
    fail('恢复目标被拒绝时仍然写了文件')
  }

  bytes.failWrite = '/storage/other/b.txt'
  let partial = box1.restore(ID, '/storage/other', '/storage/other/b.txt')
  bytes.failWrite = ''
  if (!(partial instanceof CenterError) || rows(files)[0].from !== '/system/bin/sh' ||
    bytes.values.has('/storage/other/b.txt') === true) {
    fail('另选目录写失败时改了清单或留下了残缺文件')
  }

  let moved = box1.restore(ID, '/storage/other', '/storage/other/b.txt')
  if (moved !== null || rows(files).length !== 0 ||
    !same(bytes.values.get('/storage/other/b.txt') === undefined ? null : bytes.values.get('/storage/other/b.txt') as Uint8Array, plain)) {
    fail('另选目录通过 FileOpen 后没有写回，或写回前就改了清单')
  }
}
