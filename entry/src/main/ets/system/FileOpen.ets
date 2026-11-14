import fs from '@ohos.file.fs';
import { hilog } from '@kit.PerformanceAnalysisKit';
import { CenterError } from '../center/CenterError';
import type { FileGrant } from '../center/CenterTypes';
import { isHardExcluded, isPrivateDataPath, privateBundleSegment } from '../feature/clean/Exclude';

const DOMAIN: number = 0x4A59
const TAG: string = 'Center'

export interface FileView {
  realpath(path: string): string | null
  open(path: string): number | null
  close(fd: number): void
  pathOf(fd: number): string | null
}

export class OpenedFile {
  fd: number = -1
  path: string = ''
}

export class FsFileView implements FileView {
  private lastFd: number = -1
  private lastPath: string = ''

  realpath(path: string): string | null {
    try {
      let stat = fs.lstatSync(path)
      if (stat.isSymbolicLink()) {
        return null
      }
      return path
    } catch (err) {
      return null
    }
  }

  open(path: string): number | null {
    try {
      let file = fs.openSync(path, fs.OpenMode.READ_ONLY)
      this.lastFd = file.fd
      this.lastPath = ''
      try {
        this.lastPath = file.path
      } catch (err) {
        this.lastPath = ''
      }
      return file.fd
    } catch (err) {
      return null
    }
  }

  close(fd: number): void {
    fs.closeSync(fd)
  }

  pathOf(fd: number): string | null {
    if (fd === this.lastFd && this.lastPath.length > 0) {
      return this.lastPath
    }
    return null
  }
}

export class FileOpen {
  private view: FileView

  constructor(view: FileView) {
    this.view = view
  }

  open(uri: string, root: string, fromPicker: boolean, grants: FileGrant[]): CenterError | OpenedFile {
    let parsed = pathOfUri(uri)
    if (parsed === null) {
      if (!fromPicker && !listed(grants, uri)) {
        return reject(uri)
      }
      let fd = this.view.open(uri)
      if (fd === null) {
        return ioError(uri)
      }
      let revealed = this.view.pathOf(fd)
      if (revealed !== null && revealed.length > 0) {
        let problem = this.assess(revealed, root)
        if (problem !== null) {
          this.view.close(fd)
          return problem
        }
        let opened = new OpenedFile()
        opened.fd = fd
        opened.path = revealed
        return opened
      }
      let opened = new OpenedFile()
      opened.fd = fd
      opened.path = ''
      return opened
    }
    let problem = this.assess(parsed, root)
    if (problem !== null) {
      return problem
    }
    let fd = this.view.open(parsed)
    if (fd === null) {
      return ioError(parsed)
    }
    let opened = new OpenedFile()
    opened.fd = fd
    opened.path = parsed
    return opened
  }

  private assess(original: string, root: string): CenterError | null {
    let real = this.view.realpath(original)
    let rootReal = this.view.realpath(root)
    if (real === null || rootReal === null) {
      return reject(original)
    }
    if (isHardExcluded(original) || isHardExcluded(real)) {
      return reject(original)
    }
    if (!inside(real, rootReal)) {
      return reject(original)
    }
    if (!isPrivateDataPath(rootReal) && (isPrivateDataPath(original) || isPrivateDataPath(real))) {
      return reject(original)
    }
    if (isPrivateDataPath(rootReal) && (!segmentOk(rootReal, real) || !segmentOk(rootReal, original))) {
      return reject(original)
    }
    return null
  }
}

function listed(grants: FileGrant[], uri: string): boolean {
  for (let i = 0; i < grants.length; i++) {
    if (grants[i].uri === uri) {
      return true
    }
  }
  return false
}

function pathOfUri(uri: string): string | null {
  if (uri.indexOf('/') === 0) {
    return uri
  }
  if (uri.indexOf('file://') === 0) {
    let rest = uri.substring('file://'.length)
    if (rest.indexOf('/') === 0) {
      return rest
    }
  }
  return null
}

function inside(target: string, root: string): boolean {
  if (root.length === 0) {
    return false
  }
  if (target === root) {
    return true
  }
  let prefix = root
  if (prefix.charAt(prefix.length - 1) !== '/') {
    prefix += '/'
  }
  return target.indexOf(prefix) === 0
}

function segmentOk(root: string, target: string): boolean {
  let rootSeg = privateBundleSegment(root)
  let targetSeg = privateBundleSegment(target)
  if (rootSeg.length === 0) {
    return targetSeg.length === 0
  }
  return targetSeg.length === 0 || targetSeg === rootSeg
}

function reject(raw: string): CenterError {
  hilog.error(DOMAIN, TAG, 'rejected-system-path')
  return new CenterError('rejected-system-path', raw)
}

function ioError(raw: string): CenterError {
  hilog.error(DOMAIN, TAG, 'io')
  return new CenterError('io', raw)
}
