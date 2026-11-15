import fs from '@ohos.file.fs'
import type { FileGrant, FileSource } from '../center/CenterTypes'
import { CenterError } from '../center/CenterError'
import { HapReader } from './HapReader'

export interface OpenedInstaller {
  fd: number
  path: string
}

// FileOpen implements this structural interface without an engine -> system runtime import.
export interface InstallerOpen {
  accept(uri: string, root: string): CenterError | string
  open(uri: string, root: string, fromPicker: boolean, grants: FileGrant[]): CenterError | OpenedInstaller
  release(opened: OpenedInstaller): void
}

export class InstallerScanHit {
  uri: string = ''
  name: string = ''
  size: number = 0
  bundleName: string = ''
  sha256: string = ''
  reason: string = ''
  clazz: 'residue' | 'installer' = 'residue'
}

export class InstallerScanResult {
  hits: InstallerScanHit[] = []
  stoppedByLimit: boolean = false
}

export class InstallerStat {
  directory: boolean = false
  symbolicLink: boolean = false
}

export interface InstallerIo {
  list(path: string): string[]
  stat(path: string): InstallerStat
  size(fd: number): number
  now(): number
}

export class FsInstallerIo implements InstallerIo {
  list(path: string): string[] {
    return fs.listFileSync(path)
  }

  stat(path: string): InstallerStat {
    let stat = fs.lstatSync(path)
    let result = new InstallerStat()
    result.directory = stat.isDirectory()
    result.symbolicLink = stat.isSymbolicLink()
    return result
  }

  size(fd: number): number {
    return fs.statSync(fd).size
  }

  now(): number {
    return Date.now()
  }
}

class ScanState {
  result: InstallerScanResult = new InstallerScanResult()
  grants: FileGrant[] = []
  installed: Set<string> = new Set<string>()
  seen: Set<string> = new Set<string>()
  stopped: () => boolean = () => false
  files: number = 0
  bytes: number = 0
  maxFiles: number = 0
  maxBytes: number = 0
  deadlineMs: number = 0
  started: number = 0
}

export class InstallerScanner {
  private io: InstallerIo
  private reader: HapReader

  constructor(io: InstallerIo = new FsInstallerIo(), reader: HapReader = new HapReader()) {
    this.io = io
    this.reader = reader
  }

  listInstallers(files: FileSource, open: InstallerOpen, installed: string[], stopped: () => boolean,
    maxFiles: number, maxBytes: number, deadlineMs: number): InstallerScanResult {
    let state = new ScanState()
    state.grants = files.persisted().filter((grant: FileGrant) => grant.persisted === true)
      .sort((a: FileGrant, b: FileGrant) => compareUtf8(a.uri, b.uri))
    state.installed = new Set<string>(installed)
    state.stopped = stopped
    state.maxFiles = maxFiles
    state.maxBytes = maxBytes
    state.deadlineMs = deadlineMs
    state.started = this.io.now()
    for (let grant of state.grants) {
      let root = grant.uri.startsWith('file:///') ? grant.uri.substring(7) : grant.uri
      if (!this.visit(grant.uri, root, open, state)) {
        break
      }
    }
    return state.result
  }

  private exhausted(state: ScanState): boolean {
    if (state.files >= state.maxFiles || state.bytes >= state.maxBytes ||
      this.io.now() - state.started >= state.deadlineMs) {
      state.result.stoppedByLimit = true
      return true
    }
    return state.stopped()
  }

  private visit(uri: string, root: string, open: InstallerOpen, state: ScanState): boolean {
    if (this.exhausted(state)) {
      return false
    }
    let accepted = open.accept(uri, root)
    if (accepted instanceof CenterError || state.seen.has(accepted)) {
      return !this.exhausted(state)
    }
    state.seen.add(accepted)
    try {
      let stat = this.io.stat(accepted)
      if (stat.symbolicLink) {
        return true
      }
      if (stat.directory) {
        let names = this.io.list(accepted).slice().sort(compareUtf8)
        for (let name of names) {
          if (name === '.' || name === '..' || name.indexOf('/') >= 0) {
            continue
          }
          if (!this.visit(accepted.replace(/\/$/, '') + '/' + name, root, open, state)) {
            return false
          }
        }
      } else if (accepted.toLowerCase().endsWith('.hap')) {
        return this.read(uri, root, open, state)
      }
    } catch (err) {
      // A disappeared or unreadable entry does not terminate the remaining authorized files.
    }
    return !this.exhausted(state)
  }

  private read(uri: string, root: string, open: InstallerOpen, state: ScanState): boolean {
    let opened = open.open(uri, root, false, state.grants)
    if (opened instanceof CenterError) {
      return !this.exhausted(state)
    }
    state.files++
    try {
      let size = this.io.size(opened.fd)
      if (!Number.isSafeInteger(size) || size < 0) {
        throw new Error('invalid installer size')
      }
      if (size > state.maxBytes - state.bytes) {
        state.result.stoppedByLimit = true
        return false
      }
      state.bytes += size
      let meta = this.reader.read(opened.fd, state.stopped)
      if (meta.bundleName.length > 0) {
        let hit = new InstallerScanHit()
        hit.uri = uri
        hit.name = uri.substring(uri.lastIndexOf('/') + 1)
        hit.size = size
        hit.bundleName = meta.bundleName
        hit.sha256 = meta.sha256
        if (state.installed.has(meta.bundleName)) {
          hit.clazz = 'installer'
          hit.reason = '已安装应用的安装包'
        } else {
          hit.reason = '该应用未安装'
        }
        state.result.hits.push(hit)
      }
    } catch (err) {
      // An opened file consumes its slot even when fstat or metadata reading fails.
    } finally {
      open.release(opened)
    }
    return !this.exhausted(state)
  }
}

export function listInstallers(files: FileSource, open: InstallerOpen, installed: string[],
  stopped: () => boolean, maxFiles: number, maxBytes: number, deadlineMs: number): InstallerScanResult {
  return new InstallerScanner().listInstallers(files, open, installed, stopped, maxFiles, maxBytes, deadlineMs)
}

function compareUtf8(a: string, b: string): number {
  let left = Array.from(a)
  let right = Array.from(b)
  for (let i = 0; i < Math.min(left.length, right.length); i++) {
    let difference = (left[i].codePointAt(0) || 0) - (right[i].codePointAt(0) || 0)
    if (difference !== 0) {
      return difference
    }
  }
  return left.length - right.length
}
