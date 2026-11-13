import type { CountedByte } from './CenterTypes'

class CountedByteValue implements CountedByte {
  id: string = ''
  bytes: number = 0
  kind: 'cache' | 'installer' = 'cache'
}

export function sumParts(parts: CountedByte[]): number {
  let total = 0
  for (let i = 0; i < parts.length; i++) {
    total += parts[i].bytes
  }
  return total
}

export function subtractPart(parts: CountedByte[], id: string, kind: 'cache' | 'installer',
  bytes: number): CountedByte[] {
  let index = -1
  for (let i = 0; i < parts.length; i++) {
    if (parts[i].id === id && parts[i].kind === kind) {
      index = i
      break
    }
  }
  if (index < 0) {
    return parts
  }
  let next: CountedByte[] = []
  for (let i = 0; i < parts.length; i++) {
    if (i !== index) {
      next.push(parts[i])
      continue
    }
    let left = parts[i].bytes - bytes
    if (left < 0) {
      left = 0
    }
    if (left === 0) {
      continue
    }
    let row = new CountedByteValue()
    row.id = parts[i].id
    row.bytes = left
    row.kind = parts[i].kind
    next.push(row)
  }
  return next
}
