import type { BusinessError } from '@ohos.base'
import fs from '@ohos.file.fs'
import cryptoFramework from '@ohos.security.cryptoFramework'
import { hashChunk } from '../center/CenterLimits'

const STOP: number = 1

export interface HashIo {
  /** 从 offset 起读满 buffer，返回读到的字节数。0 表示文件结束。 */
  read(fd: number, buffer: ArrayBuffer, offset: number): number
}

export interface Digest {
  update(bytes: Uint8Array): void
  hex(): string
}

/** 跨线程返回，只有字段。error 非空表示这一个文件读失败，不是 Worker 起不来。 */
export class HashResult {
  sha256: string = ''
  bytes: number = 0
  cancelled: boolean = false
  error: string = ''
}

/** 读 CancelFlag 的那块 4 字节共享内存。engine 不 import task。 */
export function cancelSet(cancel: SharedArrayBuffer): boolean {
  return Atomics.load(new Int32Array(cancel), 0) === STOP
}

/**
 * 按 hashChunk 分块更新 SHA-256。每个分块之后读一次取消标志，置上就停，不把整个文件哈希完。
 * 只给 HashWorker 在 TaskPool 里调用，禁止在 UI 线程整文件哈希。
 */
export function hashFd(io: HashIo, digest: Digest, fd: number, cancel: SharedArrayBuffer): HashResult {
  let result = new HashResult()
  if (cancelSet(cancel)) {
    result.cancelled = true
    return result
  }
  let buffer = new ArrayBuffer(hashChunk)
  while (true) {
    let count = 0
    try {
      count = io.read(fd, buffer, result.bytes)
    } catch (err) {
      result.error = 'read:' + errorText(err as Object)
      return result
    }
    if (count <= 0) {
      break
    }
    digest.update(new Uint8Array(buffer, 0, count))
    result.bytes += count
    if (cancelSet(cancel)) {
      result.cancelled = true
      return result
    }
  }
  result.sha256 = digest.hex()
  return result
}

export class FsHashIo implements HashIo {
  read(fd: number, buffer: ArrayBuffer, offset: number): number {
    return fs.readSync(fd, buffer, { offset: offset, length: buffer.byteLength })
  }
}

export class CryptoDigest implements Digest {
  private md: cryptoFramework.Md = cryptoFramework.createMd('SHA256')

  update(bytes: Uint8Array): void {
    this.md.updateSync({ data: bytes })
  }

  hex(): string {
    let bytes = this.md.digestSync().data
    let text = ''
    for (let i = 0; i < bytes.length; i++) {
      text += bytes[i].toString(16).padStart(2, '0')
    }
    return text
  }
}

function errorText(err: Object): string {
  try {
    let code = (err as BusinessError).code
    if (code !== undefined && code !== null) {
      return String(code)
    }
  } catch (e) {
  }
  return 'error'
}
