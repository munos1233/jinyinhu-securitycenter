import { hilog } from '@kit.PerformanceAnalysisKit'
import { heavyBudgetMs, heavyMaxBytes, heavyMaxFiles } from '../../center/CenterLimits'
import type { CleanClass, FileHit, FileSource } from '../../center/CenterTypes'
import { listInstallers } from '../../engine/InstallerScan'
import type { InstallerOpen, InstallerScanResult } from '../../engine/InstallerScan'

const DOMAIN: number = 0x4A59
const TAG: string = 'Center'

export class CorpseResult {
  hits: FileHit[] = []
  stoppedByLimit: boolean = false
}

/**
 * 只调用 InstallerScan.listInstallers，再把 hits 写成 FileHit。
 * 禁止再实现一遍打开、扩展名和 HapReader。
 */
export class CorpseFinder {
  find(files: FileSource, open: InstallerOpen, installed: string[], stopped: () => boolean,
    maxFiles: number = heavyMaxFiles, maxBytes: number = heavyMaxBytes,
    deadlineMs: number = heavyBudgetMs): CorpseResult {
    let scan: InstallerScanResult
    try {
      scan = listInstallers(files, open, installed, stopped, maxFiles, maxBytes, deadlineMs)
    } catch (err) {
      hilog.warn(DOMAIN, TAG, 'corpse listInstallers failed')
      let empty = new CorpseResult()
      return empty
    }
    let out = new CorpseResult()
    out.stoppedByLimit = scan.stoppedByLimit === true
    for (let item of scan.hits) {
      out.hits.push(toHit(item.uri, item.name, item.size, item.sha256, item.reason, item.clazz))
    }
    return out
  }
}

function toHit(uri: string, name: string, size: number, sha256: string, reason: string,
  clazz: 'residue' | 'installer'): FileHit {
  let hit = new Hit()
  hit.uri = uri
  hit.name = name
  hit.size = size
  hit.sha256 = sha256
  hit.clazz = clazz
  hit.reason = reason
  hit.selected = false
  hit.groupId = ''
  return hit
}

class Hit implements FileHit {
  uri: string = ''
  name: string = ''
  size: number = 0
  sha256: string = ''
  clazz: CleanClass = 'residue'
  reason: string = ''
  selected: boolean = false
  groupId: string = ''
}
