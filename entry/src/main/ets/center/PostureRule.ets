export function pureModeOk(actual: string | number | boolean): boolean {
  if (actual === true) {
    return true
  }
  if (actual === 1) {
    return true
  }
  return actual === '1'
}

export function lockdownOk(actual: string): boolean {
  return actual.trim() === 'confidentiality'
}
