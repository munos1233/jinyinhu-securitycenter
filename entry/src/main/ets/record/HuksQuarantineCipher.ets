import huks from '@ohos.security.huks'
import cryptoFramework from '@ohos.security.cryptoFramework'
import util from '@ohos.util'
import type { ChunkSink, ChunkSource, CipherText, QuarantineCipher, StreamSeal } from './Quarantine'
import { StreamingSha256 } from './StreamingSha256'

const NONCE_SIZE: number = 12
const TAG_SIZE: number = 16
const CHUNK_SIZE: number = 64 * 1024
const AAD: Uint8Array = new Uint8Array([106, 121, 104, 45, 113, 117, 97, 114, 97, 110, 116, 105, 110, 101])

class CipherResult implements CipherText {
  iv: string = ''
  tag: string = ''
  bytes: Uint8Array = new Uint8Array(0)
}

class StreamResult implements StreamSeal {
  iv: string = ''
  tag: string = ''
  sha256: string = ''
}

/** AES-256-GCM; the key remains in HUKS and is never exported. */
export class HuksQuarantineCipher implements QuarantineCipher {
  async encryptStream(alias: string, bits: number, length: number, source: ChunkSource,
    sink: ChunkSink): Promise<StreamSeal | null> {
    if (bits !== 256 || length < 0 || !Number.isInteger(length)) return null
    let handle: number = -1
    try {
      if (!(await huks.isKeyItemExist(alias, emptyOptions()))) await huks.generateKeyItem(alias, keyOptions())
      let nonce = cryptoFramework.createRandom().generateRandomSync(NONCE_SIZE).data
      if (nonce.length !== NONCE_SIZE) return null
      let initial = cryptOptions(true, nonce, new Uint8Array(0), new Uint8Array(0))
      handle = (await huks.initSession(alias, initial)).handle
      let digest = new StreamingSha256()
      let offset = 0
      let written = 0
      while (length - offset > CHUNK_SIZE) {
        let data = source.read(offset, CHUNK_SIZE)
        if (data === null || data.length === 0 || data.length > CHUNK_SIZE || data.length > length - offset) {
          throw new Error('source read failed')
        }
        digest.update(data)
        let result = await huks.updateSession(handle, cryptOptions(true, nonce, new Uint8Array(0), data))
        if (result.outData !== undefined && result.outData.length > 0) {
          if (!sink.write(result.outData)) throw new Error('cipher write failed')
          written += result.outData.length
        }
        offset += data.length
      }
      let last = readExact(source, offset, length - offset)
      if (last === null) throw new Error('source read failed')
      digest.update(last)
      let final = await huks.finishSession(handle, cryptOptions(true, nonce, new Uint8Array(0), last))
      handle = -1
      if (final.outData === undefined || final.outData.length < TAG_SIZE) return null
      let body = final.outData.subarray(0, final.outData.length - TAG_SIZE)
      if (body.length > 0 && !sink.write(body)) return null
      written += body.length
      if (written !== length) return null
      let helper = new util.Base64Helper()
      let out = new StreamResult()
      out.iv = helper.encodeToStringSync(nonce)
      out.tag = helper.encodeToStringSync(final.outData.subarray(final.outData.length - TAG_SIZE))
      out.sha256 = digest.finish()
      return out
    } catch (err) {
      if (handle >= 0) { try { await huks.abortSession(handle, emptyOptions()) } catch (ignored) { } }
      return null
    }
  }

  async decryptStream(alias: string, bits: number, length: number, source: ChunkSource,
    sink: ChunkSink, iv: string, tag: string): Promise<string | null> {
    if (bits !== 256 || length < 0 || !Number.isInteger(length)) return null
    let handle: number = -1
    try {
      if (!(await huks.isKeyItemExist(alias, emptyOptions()))) return null
      let helper = new util.Base64Helper()
      let nonce = helper.decodeSync(iv)
      let authTag = helper.decodeSync(tag)
      if (nonce.length !== NONCE_SIZE || authTag.length !== TAG_SIZE) return null
      handle = (await huks.initSession(alias, cryptOptions(false, nonce, authTag, new Uint8Array(0)))).handle
      let digest = new StreamingSha256()
      let offset = 0
      let written = 0
      while (length - offset > CHUNK_SIZE) {
        let data = source.read(offset, CHUNK_SIZE)
        if (data === null || data.length === 0 || data.length > CHUNK_SIZE || data.length > length - offset) {
          throw new Error('cipher read failed')
        }
        let result = await huks.updateSession(handle, cryptOptions(false, nonce, authTag, data))
        if (result.outData !== undefined && result.outData.length > 0) {
          if (!sink.write(result.outData)) throw new Error('temporary write failed')
          digest.update(result.outData)
          written += result.outData.length
        }
        offset += data.length
      }
      let last = readExact(source, offset, length - offset)
      if (last === null) throw new Error('cipher read failed')
      let final = await huks.finishSession(handle, cryptOptions(false, nonce, authTag, last))
      handle = -1
      if (final.outData !== undefined && final.outData.length > 0) {
        if (!sink.write(final.outData)) return null
        digest.update(final.outData)
        written += final.outData.length
      }
      return written === length ? digest.finish() : null
    } catch (err) {
      if (handle >= 0) { try { await huks.abortSession(handle, emptyOptions()) } catch (ignored) { } }
      return null
    }
  }

  async encrypt(alias: string, bits: number, plain: Uint8Array): Promise<CipherText | null> {
    if (bits !== 256) return null
    try {
      if (!(await huks.isKeyItemExist(alias, emptyOptions()))) {
        await huks.generateKeyItem(alias, keyOptions())
      }
      let nonce = cryptoFramework.createRandom().generateRandomSync(NONCE_SIZE).data
      if (nonce.length !== NONCE_SIZE) return null
      let options = cryptOptions(true, nonce, new Uint8Array(0), plain)
      let sealed = await perform(alias, options, plain.length + TAG_SIZE)
      if (sealed === null || sealed.length !== plain.length + TAG_SIZE) return null
      let result = new CipherResult()
      let base64 = new util.Base64Helper()
      result.iv = base64.encodeToStringSync(nonce)
      result.tag = base64.encodeToStringSync(sealed.slice(sealed.length - TAG_SIZE))
      result.bytes = sealed.subarray(0, sealed.length - TAG_SIZE)
      return result
    } catch (err) {
      return null
    }
  }

  async decrypt(alias: string, bits: number, bytes: Uint8Array, iv: string, tag: string): Promise<Uint8Array | null> {
    if (bits !== 256) return null
    try {
      if (!(await huks.isKeyItemExist(alias, emptyOptions()))) return null
      let base64 = new util.Base64Helper()
      let nonce = base64.decodeSync(iv)
      let authTag = base64.decodeSync(tag)
      if (nonce.length !== NONCE_SIZE || authTag.length !== TAG_SIZE) return null
      let plain = await perform(alias, cryptOptions(false, nonce, authTag, bytes), bytes.length)
      return plain !== null && plain.length === bytes.length ? plain : null
    } catch (err) {
      return null
    }
  }
}

function readExact(source: ChunkSource, offset: number, length: number): Uint8Array | null {
  let out = new Uint8Array(length)
  let filled = 0
  while (filled < length) {
    let chunk = source.read(offset + filled, length - filled)
    if (chunk === null || chunk.length === 0 || chunk.length > length - filled) return null
    out.set(chunk, filled)
    filled += chunk.length
  }
  return out
}

function emptyOptions(): huks.HuksOptions {
  return { properties: [] }
}

function keyOptions(): huks.HuksOptions {
  let properties: huks.HuksParam[] = [
    { tag: huks.HuksTag.HUKS_TAG_ALGORITHM, value: huks.HuksKeyAlg.HUKS_ALG_AES },
    { tag: huks.HuksTag.HUKS_TAG_KEY_SIZE, value: huks.HuksKeySize.HUKS_AES_KEY_SIZE_256 },
    { tag: huks.HuksTag.HUKS_TAG_PURPOSE, value: huks.HuksKeyPurpose.HUKS_KEY_PURPOSE_ENCRYPT |
      huks.HuksKeyPurpose.HUKS_KEY_PURPOSE_DECRYPT }
  ]
  return { properties: properties }
}

function cryptOptions(encrypt: boolean, nonce: Uint8Array, tag: Uint8Array, data: Uint8Array): huks.HuksOptions {
  let properties: huks.HuksParam[] = [
    { tag: huks.HuksTag.HUKS_TAG_ALGORITHM, value: huks.HuksKeyAlg.HUKS_ALG_AES },
    { tag: huks.HuksTag.HUKS_TAG_KEY_SIZE, value: huks.HuksKeySize.HUKS_AES_KEY_SIZE_256 },
    { tag: huks.HuksTag.HUKS_TAG_PURPOSE, value: encrypt ? huks.HuksKeyPurpose.HUKS_KEY_PURPOSE_ENCRYPT :
      huks.HuksKeyPurpose.HUKS_KEY_PURPOSE_DECRYPT },
    { tag: huks.HuksTag.HUKS_TAG_PADDING, value: huks.HuksKeyPadding.HUKS_PADDING_NONE },
    { tag: huks.HuksTag.HUKS_TAG_BLOCK_MODE, value: huks.HuksCipherMode.HUKS_MODE_GCM },
    { tag: huks.HuksTag.HUKS_TAG_NONCE, value: nonce },
    { tag: huks.HuksTag.HUKS_TAG_ASSOCIATED_DATA, value: AAD }
  ]
  if (!encrypt) properties.push({ tag: huks.HuksTag.HUKS_TAG_AE_TAG, value: tag })
  return { properties: properties, inData: data }
}

async function perform(alias: string, options: huks.HuksOptions, maxLength: number): Promise<Uint8Array | null> {
  let input = options.inData
  if (input === undefined) return null
  let initial: huks.HuksOptions = { properties: options.properties, inData: new Uint8Array(0) }
  let handle = await huks.initSession(alias, initial)
  try {
    let output = new Uint8Array(maxLength)
    let written = 0
    let offset = 0
    while (input.length - offset > CHUNK_SIZE) {
      let update: huks.HuksOptions = { properties: options.properties, inData: input.slice(offset, offset + CHUNK_SIZE) }
      let result = await huks.updateSession(handle.handle, update)
      if (result.outData !== undefined) {
        if (written + result.outData.length > output.length) throw new Error('unexpected output')
        output.set(result.outData, written)
        written += result.outData.length
      }
      offset += CHUNK_SIZE
    }
    let finalOptions: huks.HuksOptions = { properties: options.properties, inData: input.slice(offset) }
    let final = await huks.finishSession(handle.handle, finalOptions)
    if (final.outData !== undefined) {
      if (written + final.outData.length > output.length) throw new Error('unexpected output')
      output.set(final.outData, written)
      written += final.outData.length
    }
    return output.subarray(0, written)
  } catch (err) {
    try { await huks.abortSession(handle.handle, emptyOptions()) } catch (ignored) { }
    return null
  }
}
