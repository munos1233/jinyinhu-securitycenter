import fs from '@ohos.file.fs'
import type { FileGrant, FileSource, HapMeta, Fingerprint } from '../main/ets/center/CenterTypes'
import { hapReadMax } from '../main/ets/center/CenterLimits'
import { CenterError } from '../main/ets/center/CenterError'
import { decide } from '../main/ets/engine/Decide'
import { RuleLoad, OfficialRule } from '../main/ets/engine/RulePack'
import { BundleFinger } from '../main/ets/engine/BundleFinger'
import { FsHapIo, HapReader } from '../main/ets/engine/HapReader'
import { FsInstallerIo, InstallerScanner, listInstallers } from '../main/ets/engine/InstallerScan'
import type { OpenedInstaller } from '../main/ets/engine/InstallerScan'
import { FileOpen, FsFileView } from '../main/ets/system/FileOpen'

export interface HapFixture {
  name: string
  path: string
  bundleName: string
  version: string
  versionCode: number
  certSha256: string
  sha256: string
  declaredPermissions: string[]
}

function require(value: boolean, message: string): void {
  if (!value) {
    throw new Error(message)
  }
}

function openedRead(reader: HapReader, path: string): HapMeta {
  let file = fs.openSync(path, fs.OpenMode.READ_ONLY)
  try {
    return reader.read(file.fd)
  } finally {
    fs.closeSync(file.fd)
  }
}

class OversizedIo extends FsHapIo {
  reads: number = 0

  size(fd: number): number {
    return hapReadMax + 1
  }

  hash(fd: number, size: number, stopped: () => boolean): string {
    return 'large-file-hash'
  }

  readAt(fd: number, offset: number, length: number): Uint8Array {
    this.reads++
    throw new Error('oversized HAP must not be opened as an archive')
  }
}

class HashFailureIo extends FsHapIo {
  hash(fd: number, size: number, stopped: () => boolean): string {
    throw new Error('hash unavailable')
  }
}

class ChangingIo extends FsHapIo {
  readAt(fd: number, offset: number, length: number): Uint8Array {
    let part = super.readAt(fd, offset, length)
    if (offset === 0 && length > 5) {
      part[5] ^= 1
    }
    return part
  }

  hash(fd: number, size: number, stopped: () => boolean): string {
    // Keep the initial hash consistent with the original file, then change the
    // snapshot read. The reader must reject metadata from a different version.
    return new FsHapIo().hash(fd, size, stopped)
  }
}

class Sources implements FileSource {
  grants: FileGrant[] = []

  persisted(): FileGrant[] {
    return this.grants
  }

  forget(uri: string): void {
    throw new Error('enumeration must not revoke a grant')
  }
}

class Grant implements FileGrant {
  uri: string = ''
  displayName: string = ''
  persisted: boolean = true
  at: string = ''
}

class StableIo extends FsInstallerIo {
  list(path: string): string[] {
    return super.list(path).reverse()
  }

  now(): number {
    return 100
  }
}

class ExpiringIo extends StableIo {
  tick: number = 0

  now(): number {
    return this.tick++
  }
}

class FailingSizeIo extends StableIo {
  size(fd: number): number {
    throw new Error('fstat failed after open')
  }
}

class InvalidSizeIo extends StableIo {
  size(fd: number): number {
    return -1
  }
}

class TrackingOpen extends FileOpen {
  opened: string[] = []
  releases: number = 0

  constructor() {
    super(new FsFileView())
  }

  accept(uri: string, root: string): CenterError | string {
    if (uri.endsWith('/blocked.hap')) {
      return new CenterError('rejected-system-path', uri)
    }
    return super.accept(uri, root)
  }

  open(uri: string, root: string, fromPicker: boolean, grants: FileGrant[]): CenterError | OpenedInstaller {
    this.opened.push(uri)
    return super.open(uri, root, fromPicker, grants)
  }

  release(opened: OpenedInstaller): void {
    this.releases++
    super.release(opened)
  }
}

class CancellingReader extends HapReader {
  cancelled: boolean = false

  read(fd: number, stopped: () => boolean = () => false): HapMeta {
    let result = super.read(fd, stopped)
    this.cancelled = true
    return result
  }
}

function sources(uri: string): Sources {
  let result = new Sources()
  let grant = new Grant()
  grant.uri = uri
  result.grants.push(grant)
  return result
}

function checkBundleFinger(): void {
  let certificate = new Uint8Array([97, 98, 99])
  let platform = BundleFinger.read(' AA:BB ', certificate)
  require(platform.certAlgo === 'platform-fingerprint' && platform.certSha256 === 'aabb',
    'platform fingerprint must be normalized without another hash')
  let bytes = BundleFinger.read('', certificate)
  require(bytes.certAlgo === 'sha256-of-cert-bytes' &&
    bytes.certSha256 === 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    'certificate bytes must use their actual SHA-256')
  let fallback = BundleFinger.read('   ', certificate)
  require(fallback.certSha256 === bytes.certSha256 && fallback.certAlgo === bytes.certAlgo,
    'an empty normalized platform fingerprint must use available certificate bytes')
  let absent = BundleFinger.read('', new Uint8Array(0))
  require(absent.certAlgo === 'none' && absent.certSha256 === '', 'missing certificate must stay empty')
}

function checkFixtures(fixtures: HapFixture[]): void {
  let reader = new HapReader()
  let rules = new RuleLoad()
  let official = new OfficialRule()
  official.bundleName = 'com.test.fixture'
  official.certAlgo = 'sha256-of-cert-bytes'
  official.certSha256 = fixtures.filter((item: HapFixture): boolean => item.name === 'stored')
    .map((item: HapFixture): string => item.certSha256)
  rules.officials = [official]
  for (let fixture of fixtures) {
    let result = openedRead(reader, fixture.path)
    require(result.sha256 === fixture.sha256, fixture.name + ': file SHA-256 must survive metadata failures ' +
      JSON.stringify(result))
    require(result.bundleName === fixture.bundleName && result.version === fixture.version &&
      result.versionCode === fixture.versionCode, fixture.name + ': actual module.json fields must be decoded')
    require(result.certSha256 === fixture.certSha256 &&
      result.certAlgo === (fixture.certSha256.length > 0 ? 'sha256-of-cert-bytes' : 'none'),
      fixture.name + ': only a verified HAP signer certificate can supply identity')
    require(JSON.stringify(result.declaredPermissions) === JSON.stringify(fixture.declaredPermissions),
      fixture.name + ': declared permission names must be preserved')
    if (result.bundleName === official.bundleName) {
      let fp: Fingerprint = { kind: 'file', id: fixture.path, bundleName: result.bundleName,
        version: result.version, versionCode: result.versionCode, certSha256: result.certSha256,
        certAlgo: result.certAlgo, sha256: result.sha256, size: result.size, label: '' }
      let verdict = decide(fp, result.declaredPermissions, [], false, rules, [],
        { state: 'reached', level: 'ok', reason: '', evidence: '' })
      require(fixture.certSha256.length > 0 ? verdict.evidence === 'official' : verdict.level === 'unknown',
        fixture.name + ': unverified certificate material must not produce official or cloud-ok identity')
    }
  }
  let changed = openedRead(new HapReader(new ChangingIo()), fixtures.filter(
    (item: HapFixture): boolean => item.name === 'stored')[0].path)
  require(changed.bundleName === '' && changed.certSha256 === '' && changed.certAlgo === 'none',
    'a source that changes between hashing and snapshotting must not supply mixed metadata')
  let oversized = new OversizedIo()
  let result = new HapReader(oversized).read(0)
  require(result.size === hapReadMax + 1 && result.sha256 === 'large-file-hash' &&
    result.bundleName === '' && result.certAlgo === 'none' && oversized.reads === 0,
    'oversized HAP must retain only hash and size without reading ZIP metadata')
  result = openedRead(new HapReader(new HashFailureIo()), fixtures[0].path)
  require(result.sha256 === '' && result.bundleName === fixtures[0].bundleName,
    'a missing hash must remain empty while readable configuration is retained')
}

function checkInstallerScan(root: string): void {
  let source = sources(root)
  let open = new TrackingOpen()
  let scanner = new InstallerScanner(new StableIo())
  let first = scanner.listInstallers(source, open, ['com.test.installed'], () => false, 100, 100000000, 60000)
  let second = scanner.listInstallers(source, open, ['com.test.installed'], () => false, 100, 100000000, 60000)
  require(JSON.stringify(first) === JSON.stringify(second) && !first.stoppedByLimit && first.hits.length === 2,
    'stable traversal must produce the same authorized installer set and stop reason')
  let overlapping = sources(root)
  overlapping.grants.push(overlapping.grants[0])
  let deduplicated = scanner.listInstallers(overlapping, open, ['com.test.installed'], () => false, 100, 100000000, 60000)
  require(JSON.stringify(deduplicated) === JSON.stringify(first), 'overlapping grants must not duplicate files')
  require(first.hits[0].clazz === 'installer' && first.hits[0].reason === '已安装应用的安装包' &&
    first.hits[1].clazz === 'residue' && first.hits[1].reason === '该应用未安装',
    'classification must depend on the actual package name and installed set')
  require(first.hits.every((hit) => hit.sha256.length === 64), 'installer hashes must come from HapReader')
  require(open.opened.every((uri) => !uri.endsWith('/blocked.hap') && !uri.endsWith('.zip') &&
    uri.indexOf('/outside/') < 0) &&
    open.releases === open.opened.length, 'rejected and non-HAP files must never be opened and descriptors must close')
  let one = scanner.listInstallers(source, open, [], () => false, 1, 100000000, 60000)
  require(one.stoppedByLimit && one.hits.length === 1, 'reaching maxFiles must stop immediately')
  let bytes = scanner.listInstallers(source, open, [], () => false, 100, 1, 60000)
  require(bytes.stoppedByLimit && bytes.hits.length === 0, 'byte quota must stop before reading an oversized candidate')
  let time = new InstallerScanner(new ExpiringIo()).listInstallers(source, open, [], () => false, 100, 100000000, 1)
  require(time.stoppedByLimit && time.hits.length === 0, 'deadlineMs must be a real stop condition')
  let cancelled = scanner.listInstallers(source, open, [], () => true, 100, 100000000, 60000)
  require(!cancelled.stoppedByLimit && cancelled.hits.length === 0, 'cancellation alone is not quota exhaustion')
  let simultaneous = scanner.listInstallers(source, open, [], () => true, 0, 100000000, 60000)
  require(simultaneous.stoppedByLimit, 'quota exhaustion takes priority over concurrent cancellation')
  let noGrant = scanner.listInstallers(new Sources(), open, [], () => true, 0, 0, 0)
  require(!noGrant.stoppedByLimit && noGrant.hits.length === 0, 'no grants is not a quota stop')
  let transient = sources(root)
  transient.grants[0].persisted = false
  let transientOpen = new TrackingOpen()
  let unremembered = scanner.listInstallers(transient, transientOpen, [], () => false, 100, 100000000, 60000)
  require(unremembered.hits.length === 0 && !unremembered.stoppedByLimit && transientOpen.opened.length === 0,
    'old non-persisted grant rows must not authorize directory reads')
  let transientZero = scanner.listInstallers(transient, transientOpen, [], () => true, 0, 0, 0)
  require(transientZero.hits.length === 0 && !transientZero.stoppedByLimit,
    'a false-only grant list must behave like no authorization even with zero quota')
  for (let badIo of [new FailingSizeIo(), new InvalidSizeIo()]) {
    let badOpen = new TrackingOpen()
    let failedSize = new InstallerScanner(badIo).listInstallers(source, badOpen, [], () => false,
      1, 100000000, 60000)
    require(failedSize.stoppedByLimit && failedSize.hits.length === 0 &&
      badOpen.opened.length === 1 && badOpen.releases === 1,
      'every successful open counts toward maxFiles even if fstat fails or size is invalid')
  }
  let failedHashOpen = new TrackingOpen()
  let failedHash = new InstallerScanner(new StableIo(), new HapReader(new HashFailureIo())).listInstallers(
    source, failedHashOpen, [], () => false, 1, 100000000, 60000)
  require(failedHash.stoppedByLimit && failedHash.hits.length === 1 && failedHash.hits[0].sha256 === '' &&
    failedHashOpen.opened.length === 1 && failedHashOpen.releases === 1,
    'an unavailable hash must still consume exactly one opened-file slot and retain readable package data')
  let cancelling = new CancellingReader()
  let afterOne = new InstallerScanner(new StableIo(), cancelling).listInstallers(source, open, [],
    () => cancelling.cancelled, 100, 100000000, 60000)
  require(!afterOne.stoppedByLimit && afterOne.hits.length === 1,
    'cancellation after a finished file preserves that result and stops subsequent files')
  let defaultResult = listInstallers(source, open, ['com.test.installed'], () => false, 100, 100000000, 60000)
  require(JSON.stringify(defaultResult) === JSON.stringify(first), 'the exported default entry point must use real I/O')
  let uriResult = listInstallers(sources('file://' + root), open, [], () => false, 100, 100000000, 60000)
  require(uriResult.hits.length === 2, 'file URI grants must resolve to the same authorized directory')
}

export function runHapReaderChecks(fixtures: HapFixture[], installerRoot: string, cancellationPath: string): void {
  checkBundleFinger()
  checkFixtures(fixtures)
  checkInstallerScan(installerRoot)
  let file = fs.openSync(cancellationPath, fs.OpenMode.READ_ONLY)
  try {
    let io = new FsHapIo()
    let checks = 0
    let hash = io.hash(file.fd, io.size(file.fd), () => ++checks >= 2)
    require(hash === '' && checks === 2, 'file hashing must honor the same cancellation callback between chunks')
  } finally {
    fs.closeSync(file.fd)
  }
}
