import { canonicalCert } from '../main/ets/engine/Decide'

const HEX64: string = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
const HEX40: string = '0123456789abcdef0123456789abcdef01234567'
const HEX32: string = '0123456789abcdef0123456789abcdef'
const LEADING64: string = 'sha2560123456789abcdef0123456789abcdef0123456789abcdef0123456789'

function fail(message: string): void {
  throw new Error(message)
}

function upperHex(value: string): string {
  let out = ''
  for (let i = 0; i < value.length; i++) {
    let code = value.charCodeAt(i)
    if (code >= 97 && code <= 102) {
      out += String.fromCharCode(code - 32)
    } else {
      out += value.charAt(i)
    }
  }
  return out
}

export function runCanonicalCertChecks(): void {
  if (canonicalCert('') !== '' || canonicalCert(' \n\t ') !== '') {
    fail('空串没有保持为空串')
  }
  if (canonicalCert('  Keep-Case:  ') !== 'Keep-Case:' || canonicalCert('Hello') !== 'Hello') {
    fail('非十六进制改了大小写或丢掉了首尾空白之外的字符')
  }
  if (canonicalCert('ABC') !== 'ABC') {
    fail('奇数长度的十六进制被改成了小写')
  }
  if (canonicalCert('AB') !== 'ab' || canonicalCert('AA:BB') !== 'aabb' ||
    canonicalCert('AA-BB') !== 'aabb' || canonicalCert('AA BB') !== 'aabb') {
    fail('偶数长度的十六进制没有去掉分隔符并转成小写')
  }
  if (canonicalCert('AB:CD') !== 'abcd' || canonicalCert('AB:CD').length !== 4) {
    fail('平台指纹被再做了一次哈希')
  }
  if (canonicalCert('SHA256:' + upperHex(HEX64)) !== HEX64 ||
    canonicalCert('SHA-256:' + upperHex(HEX64)) !== HEX64 ||
    canonicalCert('  SHA 256: ' + HEX64 + ' ') !== HEX64 ||
    canonicalCert(upperHex(HEX64)) !== HEX64 ||
    canonicalCert(canonicalCert('SHA-256:' + upperHex(HEX64))) !== HEX64) {
    fail('SHA256 前缀没有收成 64 位小写摘要')
  }
  let kept = canonicalCert(LEADING64)
  if (kept !== LEADING64 || kept.length !== 64 || kept === LEADING64.substring(6)) {
    fail('纯 64 位摘要去掉了开头的 sha256')
  }
  if (canonicalCert('SHA-1:' + upperHex(HEX40)) !== HEX40 ||
    canonicalCert('Sha1:' + HEX40) !== HEX40) {
    fail('SHA1 前缀没有收成 40 位小写摘要')
  }
  let pure40 = 'sha1' + HEX40.substring(0, 36)
  if (canonicalCert(pure40) !== pure40 || canonicalCert(pure40).length !== 40) {
    fail('纯 40 位摘要去掉了开头的 sha1')
  }
  if (canonicalCert('MD5:' + upperHex(HEX32)) !== HEX32 || canonicalCert('Md5-' + HEX32) !== HEX32) {
    fail('MD5 前缀没有收成 32 位小写摘要')
  }
  let pure32 = 'MD5' + HEX32.substring(0, 29)
  if (canonicalCert(pure32) !== pure32) {
    fail('非十六进制的 md5 开头被改了大小写')
  }
  if (canonicalCert('SHA256:NOPE') !== 'SHA256:NOPE' || canonicalCert('AA_BB') !== 'AA_BB') {
    fail('无法规范化时没有返回去掉首尾空白后的原文')
  }
}
