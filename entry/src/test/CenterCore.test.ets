import { CenterError, centerErrorMessage, isUiMessageNotVerdictReason } from '../main/ets/center/CenterError'
import {
  cloudAlg,
  cloudBatch,
  cloudKid,
  cloudTimeoutMs,
  gateCacheMs,
  hapEntriesMax,
  hapEntryMax,
  hapReadMax,
  hardPrefixes,
  hashChunk,
  heavyBudgetMs,
  heavyMaxBytes,
  heavyMaxFiles,
  jobMax,
  laneOf,
  largeTiers,
  listMax,
  lookalikeDistance,
  lookalikeMinLength,
  privatePrefixes,
  quarantineQuota,
  reasonMax,
  useListMax,
  useLookbackMs
} from '../main/ets/center/CenterLimits'
import { nowIso } from '../main/ets/center/Clock'
import { subtractPart, sumParts } from '../main/ets/center/CleanMath'
import { groupOf, isSensitive } from '../main/ets/center/SensitiveCatalog'
import type { CountedByte, Fingerprint, QueryKey } from '../main/ets/center/CenterTypes'
import { toQueryKey } from '../main/ets/engine/QueryKey'

class ByteRow implements CountedByte {
  id: string = ''
  bytes: number = 0
  kind: 'cache' | 'installer' = 'cache'
}

class Finger implements Fingerprint {
  kind: 'bundle' | 'file' = 'bundle'
  id: string = ''
  bundleName: string = ''
  version: string = ''
  versionCode: number = 0
  certSha256: string = ''
  certAlgo: 'platform-fingerprint' | 'sha256-of-cert-bytes' | 'none' = 'none'
  sha256: string = ''
  size: number = 0
  label: string = ''
}

function fail(message: string): void {
  throw new Error(message)
}

function row(id: string, bytes: number, kind: 'cache' | 'installer'): CountedByte {
  let item = new ByteRow()
  item.id = id
  item.bytes = bytes
  item.kind = kind
  return item
}

export function runCenterCoreChecks(): void {
  let mb = 1024 * 1024
  if (largeTiers.length !== 3 || largeTiers[0] !== 100 * mb || largeTiers[1] !== 500 * mb ||
    largeTiers[2] !== 1024 * mb) {
    fail('largeTiers 不是 100MB、500MB、1GB')
  }
  if (hashChunk !== mb || reasonMax !== 200 || listMax !== 2000 || jobMax !== 100) {
    fail('hashChunk、reasonMax、listMax 或 jobMax 不对')
  }
  if (quarantineQuota !== 512 * mb || hapReadMax !== 200 * mb || hapEntriesMax !== 200 ||
    hapEntryMax !== 2 * mb) {
    fail('隔离或安装包上限不对')
  }
  if (useLookbackMs !== 7 * 24 * 60 * 60 * 1000 || useListMax !== 100) {
    fail('最近使用窗口不对')
  }
  if (cloudTimeoutMs !== 5000 || cloudBatch !== 50 || gateCacheMs !== 30000) {
    fail('云或门闸时限不对')
  }
  if (cloudAlg !== 'SHA256withECDSA' || cloudKid !== 'primary') {
    fail('云算法或 kid 不对')
  }
  if (heavyMaxFiles !== 5000 || heavyMaxBytes !== 2 * 1024 * mb || heavyBudgetMs !== 10 * 60 * 1000) {
    fail('重作业上限不对')
  }
  if (lookalikeDistance !== 2 || lookalikeMinLength !== 10) {
    fail('相似包名限额不对')
  }
  if (hardPrefixes.length !== 6 || hardPrefixes[0] !== '/system' || hardPrefixes[5] !== '/dev') {
    fail('硬拒绝前缀不对')
  }
  if (privatePrefixes.length !== 2 || privatePrefixes[0] !== '/data/app' || privatePrefixes[1] !== '/data/service') {
    fail('私有数据前缀不对')
  }
  if (laneOf('protect') !== 'light' || laneOf('permission') !== 'light' || laneOf('apps') !== 'light') {
    fail('轻车道不对')
  }
  if (laneOf('exam') !== 'heavy' || laneOf('malware') !== 'heavy' || laneOf('clean') !== 'heavy' ||
    laneOf('duplicate') !== 'heavy' || laneOf('large-file') !== 'heavy') {
    fail('重车道不对')
  }

  let parts: CountedByte[] = [row('a', 10, 'cache'), row('b', 4, 'installer'), row('a', 7, 'installer')]
  if (sumParts(parts) !== 21) {
    fail('sumParts 不是字节之和')
  }
  let missing = subtractPart(parts, 'none', 'cache', 1)
  if (missing !== parts || sumParts(missing) !== 21) {
    fail('没有这条时应原样返回')
  }
  let partial = subtractPart(parts, 'a', 'cache', 3)
  if (partial.length !== 3 || partial[0].bytes !== 7 || partial[1].id !== 'b' || partial[2].bytes !== 7) {
    fail('减法改了其它条目')
  }
  if (parts[0].bytes !== 10) {
    fail('减法改了原数组')
  }
  let gone = subtractPart(parts, 'b', 'installer', 9)
  if (gone.length !== 2 || gone[0].id !== 'a' || gone[1].kind !== 'installer') {
    fail('减到 0 应去掉这条')
  }
  let otherKind = subtractPart(parts, 'a', 'installer', 2)
  if (otherKind.length !== 3 || otherKind[0].bytes !== 10 || otherKind[2].bytes !== 5) {
    fail('同 id 不同 kind 被减错')
  }

  let fp = new Finger()
  fp.kind = 'file'
  fp.id = 'file://secret'
  fp.bundleName = ''
  fp.version = '1.2.3'
  fp.versionCode = 9
  fp.certSha256 = 'aa'
  fp.certAlgo = 'sha256-of-cert-bytes'
  fp.sha256 = 'bb'
  fp.size = 4
  fp.label = '名字'
  let key: QueryKey = toQueryKey(fp)
  if (key.bundleName !== '' || key.versionCode !== 9 || key.certSha256 !== 'aa' || key.sha256 !== 'bb') {
    fail('toQueryKey 没有只复制四个字段')
  }

  if (groupOf('ohos.permission.READ_MEDIA') !== '媒体' || !isSensitive('ohos.permission.READ_MEDIA')) {
    fail('READ_MEDIA 应在媒体组且敏感')
  }
  if (groupOf('ohos.permission.LOCATION_IN_BACKGROUND') !== '位置' ||
    groupOf('ohos.permission.CAMERA') !== '相机' ||
    groupOf('ohos.permission.PLACE_CALL') !== '电话') {
    fail('敏感分组表不对')
  }
  if (groupOf('ohos.permission.INTERNET') !== '其它' || isSensitive('ohos.permission.INTERNET')) {
    fail('其它组不应敏感')
  }
  if (isSensitive('READ_MEDIA')) {
    fail('不带 ohos.permission. 前缀不应算媒体')
  }

  let cloud = new CenterError('cloud', 'raw-cloud')
  let unsigned = new CenterError('unsigned-cloud', 'raw-sign')
  if (cloud.message !== '云查询失败，已使用本地结果' || cloud.raw !== 'raw-cloud') {
    fail('cloud 的界面短句不对')
  }
  if (unsigned.message !== '云端结果无效' || !isUiMessageNotVerdictReason('unsigned-cloud') ||
    !isUiMessageNotVerdictReason('cloud') || isUiMessageNotVerdictReason('io')) {
    fail('unsigned-cloud 短句被当成可以写入 Verdict 的原因')
  }
  if (centerErrorMessage('unsupported') !== '当前系统不支持此功能' ||
    centerErrorMessage('cancelled') !== '已停止' ||
    centerErrorMessage('interrupted') !== '扫描已中断' ||
    centerErrorMessage('rejected-system-path') !== '系统目录已跳过' ||
    centerErrorMessage('io') !== '文件处理失败' ||
    centerErrorMessage('parse') !== '规则文件损坏，仍使用上一份' ||
    centerErrorMessage('quota') !== '隔离区已满') {
    fail('CenterError 九句里有句子不对')
  }
  let shown = '未联网'
  if (shown === cloud.message || shown === unsigned.message) {
    fail('界面短句不应代替行内原因')
  }

  let stamp = nowIso()
  if (stamp.length < 19 || stamp.indexOf('T') < 0) {
    fail('nowIso 不是给记录页显示的时间串')
  }
  let seq = 1
  if (stamp === seq.toString()) {
    fail('nowIso 不能当作 seq')
  }
}
