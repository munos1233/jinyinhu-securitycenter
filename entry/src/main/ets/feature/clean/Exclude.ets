import { hardPrefixes, privatePrefixes } from '../../center/CenterLimits'

export function isHardExcluded(path: string): boolean {
  return hits(path, hardPrefixes)
}

export function isPrivateDataPath(path: string): boolean {
  return hits(path, privatePrefixes)
}

export function privateBundleSegment(path: string): string {
  let base = firstSegment(path, '/base/')
  let database = firstSegment(path, '/database/')
  if (base.at < 0) {
    return database.seg
  }
  if (database.at < 0 || base.at <= database.at) {
    return base.seg
  }
  return database.seg
}

class SegmentHit {
  at: number = -1
  seg: string = ''
}

function hits(path: string, prefixes: string[]): boolean {
  for (let i = 0; i < prefixes.length; i++) {
    if (matchesPrefix(path, prefixes[i])) {
      return true
    }
  }
  return false
}

function matchesPrefix(path: string, prefix: string): boolean {
  if (path === prefix) {
    return true
  }
  return path.indexOf(prefix + '/') === 0
}

function firstSegment(path: string, mark: string): SegmentHit {
  let hit = new SegmentHit()
  let from = 0
  while (from < path.length) {
    let at = path.indexOf(mark, from)
    if (at < 0) {
      return hit
    }
    let start = at + mark.length
    let end = start
    while (end < path.length && path.charAt(end) !== '/') {
      end++
    }
    if (end > start) {
      hit.at = at
      hit.seg = path.substring(start, end)
      return hit
    }
    from = start
  }
  return hit
}
