export function canonicalCert(value: string): string {
  let original = value.trim()
  let compact = stripSeparators(original)
  let body = stripKnownPrefix(compact)
  if (body.length > 0 && body.length % 2 === 0 && isHex(body)) {
    return toLowerAscii(body)
  }
  return original
}

function stripSeparators(value: string): string {
  let compact = ''
  for (let i = 0; i < value.length; i++) {
    let ch = value.charAt(i)
    if (ch !== ' ' && ch !== ':' && ch !== '-') {
      compact += ch
    }
  }
  return compact
}

function stripKnownPrefix(compact: string): string {
  let lower = toLowerAscii(compact)
  if (prefixed(lower, 'sha256', 64)) {
    return compact.substring(6)
  }
  if (prefixed(lower, 'sha1', 40)) {
    return compact.substring(4)
  }
  if (prefixed(lower, 'md5', 32)) {
    return compact.substring(3)
  }
  return compact
}

function prefixed(lower: string, prefix: string, remain: number): boolean {
  if (lower.length !== prefix.length + remain) {
    return false
  }
  for (let i = 0; i < prefix.length; i++) {
    if (lower.charAt(i) !== prefix.charAt(i)) {
      return false
    }
  }
  return isHex(lower.substring(prefix.length))
}

function isHex(value: string): boolean {
  if (value.length === 0) {
    return false
  }
  for (let i = 0; i < value.length; i++) {
    let code = value.charCodeAt(i)
    let digit = code >= 48 && code <= 57
    let lower = code >= 97 && code <= 102
    let upper = code >= 65 && code <= 70
    if (!digit && !lower && !upper) {
      return false
    }
  }
  return true
}

function toLowerAscii(value: string): string {
  let out = ''
  for (let i = 0; i < value.length; i++) {
    let code = value.charCodeAt(i)
    if (code >= 65 && code <= 90) {
      out += String.fromCharCode(code + 32)
    } else {
      out += value.charAt(i)
    }
  }
  return out
}
