import { CenterError } from '../main/ets/center/CenterError'
import type { FileGrant } from '../main/ets/center/CenterTypes'
import { isHardExcluded, isPrivateDataPath, privateBundleSegment } from '../main/ets/feature/clean/Exclude'
import type { FileView } from '../main/ets/system/FileOpen'
import { FileOpen, FsFileView, OpenedFile } from '../main/ets/system/FileOpen'

class Grant implements FileGrant {
  uri: string = ''
  displayName: string = ''
  persisted: boolean = true
  at: string = ''
}

class MapView implements FileView {
  real: Map<string, string | null> = new Map()
  opened: string[] = []
  closed: number[] = []
  present: Map<string, boolean> = new Map()
  reveal: string | null = null

  realpath(path: string): string | null {
    if (this.real.has(path)) {
      let value = this.real.get(path)
      if (value === undefined) {
        return null
      }
      return value
    }
    return path
  }

  open(path: string): number | null {
    this.opened.push(path)
    return 7
  }

  close(fd: number): void {
    this.closed.push(fd)
  }

  pathOf(fd: number): string | null {
    return this.reveal
  }
}

function fail(message: string): void {
  throw new Error(message)
}

function grant(uri: string): FileGrant[] {
  let row = new Grant()
  row.uri = uri
  let rows: FileGrant[] = []
  rows.push(row)
  return rows
}

function rejected(result: CenterError | OpenedFile): boolean {
  return result instanceof CenterError && result.code === 'rejected-system-path'
}

function opened(view: MapView, result: CenterError | OpenedFile): boolean {
  return result instanceof OpenedFile && view.opened.length === 1 && view.closed.length === 0
}

export function runFileOpenChecks(): void {
  if (!isHardExcluded('/system') || !isHardExcluded('/system/bin') || !isHardExcluded('/vendor') ||
    !isHardExcluded('/vendor/lib') || !isHardExcluded('/chip_prod') || !isHardExcluded('/chip_prod/a') ||
    !isHardExcluded('/proc') || !isHardExcluded('/proc/1') || !isHardExcluded('/sys') ||
    !isHardExcluded('/sys/kernel') || !isHardExcluded('/dev') || !isHardExcluded('/dev/null')) {
    fail('硬拒绝前缀没有按等于或后接斜杠命中')
  }
  if (isHardExcluded('/systematic') || isHardExcluded('/systemextra') || isHardExcluded('/device')) {
    fail('前缀被当成了字符串开头')
  }
  if (!isPrivateDataPath('/data/app') || !isPrivateDataPath('/data/app/el2/public/a') ||
    !isPrivateDataPath('/data/service') || !isPrivateDataPath('/data/service/readme') ||
    isPrivateDataPath('/data/apple') || isPrivateDataPath('/storage/users')) {
    fail('私有数据前缀判断不对')
  }
  if (privateBundleSegment('/data/app/el2/base/com.foo/files/a') !== 'com.foo' ||
    privateBundleSegment('/data/service/el1/database/com.bar/db') !== 'com.bar' ||
    privateBundleSegment('/x/database/bbb/base/aaa') !== 'bbb' ||
    privateBundleSegment('/data/app/base/aaa/database/bbb') !== 'aaa' ||
    privateBundleSegment('/data/service/el1/public/readme') !== '') {
    fail('包名段没有取最靠前的 /base/ 或 /database/')
  }

  let view = new MapView()
  view.present.set('/system/bin/sh', true)
  view.present.set('/storage/users/link', true)
  let opener = new FileOpen(view)
  let none: FileGrant[] = []
  if (!rejected(opener.open('/system/bin/sh', '/storage/users', false, none)) ||
    !rejected(opener.open('/proc/1', '/storage/users', false, none)) ||
    !rejected(opener.open('/dev/null', '/storage/users', false, none)) ||
    view.opened.length !== 0 || view.present.get('/system/bin/sh') !== true) {
    fail('硬拒绝路径被打开或读取了')
  }
  view.real.set('/storage/users/link', '/system/etc/a')
  if (!rejected(opener.open('/storage/users/link', '/storage/users', false, none)) ||
    view.opened.length !== 0 || view.present.get('/storage/users/link') !== true) {
    fail('指向系统目录的符号链接被读取了')
  }
  view.opened = []
  if (!rejected(opener.open('/system/bin/sh', '/system', false, none)) || view.opened.length !== 0) {
    fail('授权根盖过了硬拒绝')
  }

  view.opened = []
  if (!opened(view, opener.open('/systematic/app', '/systematic', false, none))) {
    fail('/systematic 被当成了 /system')
  }

  view.opened = []
  view.closed = []
  if (!rejected(opener.open('/storage/users/a', '/storage/other', false, none)) || view.opened.length !== 0) {
    fail('授权根外面的路径被打开了')
  }
  view.real.set('/storage/link', '/storage/users')
  if (!opened(view, opener.open('/storage/users/a.txt', '/storage/link', false, none))) {
    fail('授权根的 realpath 没有用来判断包含关系')
  }
  view.opened = []
  view.closed = []
  if (!opened(view, opener.open('/storage/users', '/storage/users', false, none))) {
    fail('目标等于授权根时没有通过')
  }

  view.opened = []
  view.closed = []
  if (!rejected(opener.open('/data/app/readme', '/data', false, none)) ||
    !rejected(opener.open('/data/service/readme', '/storage/media', false, none)) ||
    view.opened.length !== 0) {
    fail('非私有授权根链进 /data/app 或 /data/service 时没有拒绝')
  }

  let serviceRoot = '/data/service/el1/public'
  view.opened = []
  view.closed = []
  if (!opened(view, opener.open(serviceRoot + '/readme.txt', serviceRoot, false, none))) {
    fail('取不出包名段时，普通文件没有打开')
  }
  view.opened = []
  view.closed = []
  if (!rejected(opener.open(serviceRoot + '/base/com.other/a', serviceRoot, false, none)) ||
    !rejected(opener.open(serviceRoot + '/database/com.other/db', serviceRoot, false, none)) ||
    view.opened.length !== 0) {
    fail('别的包的 /base/ 或 /database/ 段被打开了')
  }

  let ownRoot = '/data/app/el2/base/com.foo'
  view.opened = []
  view.closed = []
  if (!opened(view, opener.open(ownRoot + '/files/a', ownRoot, false, none))) {
    fail('同一包名段没有打开')
  }
  view.opened = []
  view.closed = []
  if (!rejected(opener.open('/data/app/el2/base/com.other/a', ownRoot, false, none)) || view.opened.length !== 0) {
    fail('别的包的目录被当成了同一段')
  }

  view.opened = []
  view.closed = []
  if (!rejected(opener.open('content://media/1', '/storage/users', false, none)) || view.opened.length !== 0) {
    fail('解析不出路径、又没有选择器或授权的 uri 被打开了')
  }
  view.reveal = '/system/bin/x'
  let picked = opener.open('content://media/1', '/storage/users', true, none)
  if (!rejected(picked) || view.opened.length !== 1 || view.closed.length !== 1) {
    fail('打开后给出的系统路径没有复查或没有关闭描述符')
  }
  view.opened = []
  view.closed = []
  view.reveal = '/storage/users/a.txt'
  if (!opened(view, opener.open('content://media/1', '/storage/users', true, none))) {
    fail('当次选择器的 uri 在真实路径通过后没有留下描述符')
  }
  view.opened = []
  view.closed = []
  view.reveal = '/storage/users/a.txt'
  if (!opened(view, opener.open('content://media/2', '/storage/users', false, grant('content://media/2')))) {
    fail('仍有效的 FileGrant 没有被接受')
  }
  view.opened = []
  view.closed = []
  view.reveal = null
  if (!opened(view, opener.open('content://picker/1', '/storage/users', true, none))) {
    fail('没有路径的选择器 uri 在打开前被拒绝了')
  }
  view.opened = []
  view.closed = []
  if (!opened(view, opener.open('file:///storage/users/a.txt', '/storage/users', false, none))) {
    fail('file uri 没有按路径检查')
  }

  let device = new FileOpen(new FsFileView())
  let gone = device.accept('/storage/users/gone.txt', '/storage/users')
  if (gone !== '/storage/users/gone.txt') {
    fail('源文件已经不在时，恢复路径被拒绝了')
  }
  let folded = device.accept('/storage/users/../users/a.txt', '/storage/users')
  if (folded !== '/storage/users/a.txt') {
    fail('路径里的 .. 没有按目录折叠')
  }
  let link = device.accept('/storage/users/link', '/storage/users')
  if (!(link instanceof CenterError) || link.code !== 'rejected-system-path') {
    fail('符号链接在设备打开时被当成了普通文件')
  }
  let outside = device.accept('/storage/users/../../etc/passwd', '/storage/users')
  if (!(outside instanceof CenterError)) {
    fail('折出文件系统根的路径被允许了')
  }
}
