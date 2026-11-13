/**
 * nowIso() 只给记录页显示。不分配 seq，不给首页排序。
 */

function pad2(value: number): string {
  if (value < 10) {
    return '0' + value.toString()
  }
  return value.toString()
}

export function nowIso(): string {
  let date = new Date()
  let offset = -date.getTimezoneOffset()
  let sign = '+'
  let abs = offset
  if (offset < 0) {
    sign = '-'
    abs = -offset
  }
  let hours = Math.floor(abs / 60)
  let minutes = abs % 60
  return date.getFullYear().toString() + '-' + pad2(date.getMonth() + 1) + '-' + pad2(date.getDate()) +
    'T' + pad2(date.getHours()) + ':' + pad2(date.getMinutes()) + ':' + pad2(date.getSeconds()) +
    sign + pad2(hours) + ':' + pad2(minutes)
}
