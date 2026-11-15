import type {
  CacheRow,
  CleanReport,
  FileGrant,
  FileHit,
  FileToolReport,
  JobKind,
  JobProgress,
  JobRecord,
  JobState,
  Lane,
  QuarantineEntry
} from '../main/ets/center/CenterTypes'
import { CenterError } from '../main/ets/center/CenterError'
import {
  cachePlaceholder,
  cleanKind,
  cleanPageLook,
  cleanRequest,
  confirmText,
  defaultSelection,
  directoryGranted,
  installerPlaceholder,
  pickCleanJob,
  sectionKeys,
  selectCategory,
  selectedTotal,
  showsProcess,
  viewOnly
} from '../main/ets/pages/CleanView'
import type { QuarantineDesk } from '../main/ets/pages/QuarantineView'
import {
  deleteConfirm,
  discardCall,
  quarantineRow,
  quarantineTitle,
  restoreCall,
  restoreChoose,
  restoreRoot
} from '../main/ets/pages/QuarantineView'

interface HilogHost {
  __centerHilog?: string[]
}

class Cache implements CacheRow {
  bundleName: string = ''
  displayName: string = ''
  cacheBytes: number = 0
  selected: boolean = false
}

class Hit implements FileHit {
  uri: string = ''
  name: string = ''
  size: number = 0
  sha256: string = ''
  clazz: FileHit['clazz'] = 'residue'
  reason: string = ''
  selected: boolean = false
  groupId: string = ''
}

class Clean implements CleanReport {
  caches: CacheRow[] = []
  hits: FileHit[] = []
  groups = []
  complete: boolean = true
  note: string = ''
}

class Tool implements FileToolReport {
  hits: FileHit[] = []
  groups = []
  complete: boolean = true
  note: string = ''
}

class RecordRow implements JobRecord {
  jobId: string = ''
  seq: number = 0
  kind: JobKind = 'clean'
  lane: Lane = 'heavy'
  startedAt: string = ''
  finishedAt: string = ''
  state: JobState = 'done'
  itemCount: number = 0
  riskCount: number = 0
  summary: string = ''
  resultFile: string = ''
}

class Progress implements JobProgress {
  jobId: string = ''
  kind: JobKind = 'clean'
  lane: Lane = 'heavy'
  state: JobState = 'done'
  done: number = 0
  total: number = 0
  message: string = ''
}

class Grant implements FileGrant {
  uri: string = ''
  displayName: string = ''
  persisted: boolean = false
  at: string = ''
}

class Entry implements QuarantineEntry {
  id: string = ''
  from: string = ''
  stored: string = ''
  sha256: string = ''
  size: number = 0
  iv: string = ''
  tag: string = ''
  reason: string = ''
  at: string = ''
  committed: boolean = false
}

class Desk implements QuarantineDesk {
  restored: string[] = []
  discarded: string[] = []

  list(): QuarantineEntry[] | null {
    return []
  }

  async restore(id: string, root: string, choose: string): Promise<CenterError | null> {
    this.restored.push(id + '|' + root + '|' + choose)
    return null
  }

  async discard(id: string): Promise<CenterError | null> {
    this.discarded.push(id)
    return null
  }
}

function fail(message: string): void {
  throw new Error(message)
}

function cache(bundleName: string, bytes: number, selected: boolean): CacheRow {
  let row = new Cache()
  row.bundleName = bundleName
  row.displayName = bundleName
  row.cacheBytes = bytes
  row.selected = selected
  return row
}

function hit(uri: string, clazz: FileHit['clazz'], size: number, selected: boolean, reason: string): FileHit {
  let row = new Hit()
  row.uri = uri
  row.name = uri.substring(uri.lastIndexOf('/') + 1)
  row.size = size
  row.clazz = clazz
  row.selected = selected
  row.reason = reason
  return row
}

function clean(caches: CacheRow[], hits: FileHit[], complete: boolean, note: string): CleanReport {
  let report = new Clean()
  report.caches = caches
  report.hits = hits
  report.complete = complete
  report.note = note
  return report
}

function record(jobId: string, kind: JobKind, seq: number): JobRecord {
  let row = new RecordRow()
  row.jobId = jobId
  row.kind = kind
  row.seq = seq
  row.state = 'done'
  return row
}

function lookOf(params: string, report: CleanReport | FileToolReport, state: JobState = 'done') {
  let row = new RecordRow()
  row.jobId = 'job-1'
  row.kind = cleanKind(params)
  row.state = state
  let heavy = new Progress()
  heavy.jobId = row.jobId
  heavy.kind = row.kind
  heavy.state = state
  return cleanPageLook(params, row, JSON.stringify(report), heavy)
}

function placeholderOf(params: string, report: CleanReport, id: string): string {
  let sections = lookOf(params, report).sections
  for (let i = 0; i < sections.length; i++) {
    if (sections[i].id === id) {
      return sections[i].placeholder
    }
  }
  return ''
}

function hasSection(params: string, report: CleanReport, id: string): boolean {
  let sections = lookOf(params, report).sections
  for (let i = 0; i < sections.length; i++) {
    if (sections[i].id === id) {
      return true
    }
  }
  return false
}

export async function runCleanPagesChecks(): Promise<void> {
  if (cleanKind('cache') !== 'clean' || cleanKind('installer') !== 'clean' || cleanKind('residue') !== 'clean' ||
    cleanKind('') !== 'clean') {
    fail('cache、installer、residue 都入队 kind=clean')
  }
  let duplicate = cleanRequest('duplicate', [])
  let large = cleanRequest('large', ['file://docs/Download'])
  if (duplicate.kind !== 'duplicate' || large.kind !== 'large-file' || duplicate.kind === 'clean' ||
    large.kind === 'clean') {
    fail('duplicate 和 large 不能入成 kind=clean')
  }
  if (large.scope !== 'custom' || large.uris.length !== 1 || cleanRequest('cache', []).scope !== 'quick' ||
    cleanRequest('residue', []).focus !== '' || cleanRequest('installer', []).focus !== cleanRequest('cache', []).focus) {
    fail('residue 与 installer 是同一次清理请求，选择目录后才是自定义')
  }
  if (showsProcess('duplicate') || showsProcess('large') || !showsProcess('cache') || !showsProcess('residue') ||
    !viewOnly('duplicate') || !viewOnly('large') || viewOnly('installer')) {
    fail('重复文件和大文件只有开始，清理页才有立即处理')
  }

  let own = cache('com.jinyinhu.securitycenter', 20, false)
  let other = cache('com.example.app', 100, false)
  let residue = hit('file://docs/old.hap', 'residue', 40, true, '该应用未安装')
  let installed = hit('file://docs/mine.hap', 'installer', 9, true, '已安装应用的安装包')
  let report = clean([own, other], [residue, installed], true, '')
  let keys = defaultSelection(report)
  if (keys.length !== 2 || keys.indexOf('cache:com.example.app') < 0 ||
    keys.indexOf('cache:com.jinyinhu.securitycenter') < 0 || keys.indexOf('file:file://docs/old.hap') >= 0) {
    fail('读入页面时缓存默认勾选，安装包默认不勾选，不采用文件里的 selected')
  }
  let again = lookOf('cache', report)
  if (again.defaultKeys.join(',') !== keys.join(',') || again.lines.indexOf('仅统计了本应用缓存') >= 0) {
    fail('从记录重开仍按缓存默认勾选，并且不改写成仅统计了本应用缓存')
  }

  let limited = clean([], [], false, '已达本次扫描上限')
  if (cachePlaceholder(limited) !== '' || installerPlaceholder(limited) !== '' ||
    hasSection('cache', limited, 'cache') || placeholderOf('cache', limited, 'residue') === '没有缓存' ||
    lookOf('cache', limited).lines.indexOf('已达本次扫描上限') < 0 ||
    lookOf('cache', limited).lines.indexOf('没有缓存') >= 0 ||
    lookOf('cache', limited).lines.indexOf('没有安装包') >= 0) {
    fail('complete 为 false 时不把空列表写成没有缓存或没有安装包')
  }

  let offline = clean([own], [], true, '无法读取其他应用缓存')
  let offlineLook = lookOf('', offline)
  if (offlineLook.lines.indexOf('无法读取其他应用缓存') < 0 ||
    offlineLook.lines.indexOf('仅统计了本应用缓存') >= 0 ||
    offlineLook.lines.indexOf('没有垃圾') >= 0 || offlineLook.defaultKeys.length !== 1 ||
    placeholderOf('', offline, 'cache') === '没有缓存') {
    fail('端口不可用时要显示 note 里的无法读取其他应用缓存，不能写成没有垃圾')
  }

  let noDir = clean([other], [], true, '请先选择目录')
  if (installerPlaceholder(noDir) !== '请先选择目录' || placeholderOf('installer', noDir, 'need-dir') !== '请先选择目录' ||
    hasSection('installer', noDir, 'residue') || lookOf('residue', noDir).lines.indexOf('没有安装包') >= 0 ||
    !lookOf('cache', noDir).showTools) {
    fail('没有授权时安装包这一类只有请先选择目录，重复文件和大文件入口仍在')
  }

  let both = lookOf('installer', report)
  let residueKeys = sectionKeys(both.sections.filter((section) => section.id === 'residue')[0])
  let cacheKeys = sectionKeys(both.sections.filter((section) => section.id === 'cache')[0])
  let selected = selectCategory(both.defaultKeys, residueKeys, true)
  if (selected.indexOf('file:file://docs/old.hap') < 0 || selected.indexOf('cache:com.example.app') < 0) {
    fail('全选安装包时不应清掉缓存勾选')
  }
  let cleared = selectCategory(selected, cacheKeys, false)
  if (cleared.indexOf('cache:com.example.app') >= 0 || cleared.indexOf('file:file://docs/old.hap') < 0) {
    fail('取消全选缓存时不应改安装包勾选')
  }
  let total = selectedTotal(both.sections, ['cache:com.example.app', 'file:file://docs/mine.hap'])
  if (total.bytes !== 109 || total.count !== 2) {
    fail('顶部合计是已勾选缓存加已勾选安装包')
  }
  let text = confirmText(total.bytes, total.count)
  if (text.indexOf('109') < 0 || text.indexOf('2') < 0 || text.indexOf('缓存会直接清除') < 0 ||
    text.indexOf('安装包会进隔离区') < 0) {
    fail('确认文案要带上字节数、条数，并写明缓存直接清除、安装包进隔离区')
  }

  let dup = new Tool()
  dup.hits = [hit('/storage/users/a.bin', 'duplicate', 8, true, ''), hit('/storage/users/b.bin', 'duplicate', 8, true, '')]
  let dupLook = lookOf('duplicate', dup)
  if (!dupLook.viewOnly || dupLook.showTools || dupLook.defaultKeys.length !== 0 || dupLook.headline !== '重复文件' ||
    dupLook.sections.length !== 1 || dupLook.sections[0].selectable) {
    fail('重复文件页只查看，默认不勾选，没有立即处理')
  }
  let big = new Tool()
  big.hits = [hit('/storage/users/movie.mp4', 'large', 1024 * 1024 * 1024, false, '1GB+')]
  let bigLook = lookOf('large', big)
  if (bigLook.sections.length !== 1 || bigLook.sections[0].title !== '大文件' || bigLook.sections[0].selectable ||
    bigLook.sections[0].rows[0].detail !== '1GB+') {
    fail('大文件页只查看，并保留原有分档原因')
  }

  let jobs = [record('clean-1', 'clean', 3), record('dup-1', 'duplicate', 2), record('large-1', 'large-file', 4)]
  let picked = pickCleanJob(jobs, 'duplicate', '')
  let pickedLarge = pickCleanJob(jobs, 'large', '')
  if (picked === null || picked.kind !== 'duplicate' || pickedLarge === null || pickedLarge.kind !== 'large-file') {
    fail('重复文件和大文件重开时不读 CleanReport')
  }
  if (!directoryGranted([grantOf('/storage/users', true)]) || directoryGranted([grantOf('/storage/users', false)]) ||
    directoryGranted([])) {
    fail('没有持久授权时才先选择目录')
  }

  let bag = globalThis as HilogHost
  bag.__centerHilog = []
  let missing = clean([], [], false, '')
  let missingLook = lookOf('cache', missing)
  if (missingLook.lines.indexOf('本次扫描未完成') < 0 || (bag.__centerHilog ?? []).length === 0) {
    fail('complete 为 false 且 note 为空时要写本次扫描未完成，并打 hilog')
  }

  let kept = new Entry()
  kept.id = 'q1'
  kept.from = '/storage/users/old.hap'
  kept.size = 12
  kept.committed = false
  let row = quarantineRow(kept)
  if (row.status !== '未完成' || row.detail !== '副本已保存，原文件仍在' || row.name !== 'old.hap') {
    fail('未完成条目要说明副本已保存、原文件仍在')
  }
  kept.committed = true
  let stored = quarantineRow(kept)
  if (stored.status !== '已隔离' || stored.detail.length !== 0) {
    fail('已提交的隔离项不再写成未完成')
  }
  let confirm = deleteConfirm('old.hap', 12)
  if (confirm.indexOf('old.hap') < 0 || confirm.indexOf('12') < 0 || confirm.indexOf('清空全部') >= 0) {
    fail('删除的第二次确认要包含文件名和大小')
  }
  let grant = grantOf('/storage/users', true)
  if (restoreRoot(kept.from, [grant]) !== '/storage/users' || restoreChoose('/storage/users/', 'old.hap') !==
    '/storage/users/old.hap') {
    fail('恢复优先写回原授权目录，另选目录时带上文件名')
  }
  let desk = new Desk()
  if (await restoreCall(desk, kept, [grant], '') !== null || desk.restored[0] !== 'q1|/storage/users|' ||
    desk.discarded.length !== 0) {
    fail('恢复只调用隔离区恢复，不删除')
  }
  if (await discardCall(desk, 'q1') !== null || desk.discarded[0] !== 'q1') {
    fail('删除要走到隔离区 discard')
  }
  if (quarantineTitle(null) !== '无法读取该结果' || quarantineTitle([]) !== '隔离区没有文件') {
    fail('坏清单不能显示成空的隔离区')
  }
}

function grantOf(uri: string, persisted: boolean): FileGrant {
  let row = new Grant()
  row.uri = uri
  row.persisted = persisted
  return row
}
