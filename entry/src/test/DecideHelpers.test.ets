import type { Fingerprint, HitAction, ScanHit, Verdict, VerdictSource } from '../main/ets/center/CenterTypes'
import { reasonMax } from '../main/ets/center/CenterLimits'
import { Anomaly } from '../main/ets/center/Anomaly'
import { Heuristic } from '../main/ets/engine/Heuristic'
import { Lookalike } from '../main/ets/engine/Lookalike'
import { HeuristicRule, OfficialRule, RuleLoad } from '../main/ets/engine/RulePack'

const CAMERA: string = 'ohos.permission.CAMERA'
const BACKGROUND: string = 'ohos.permission.LOCATION_IN_BACKGROUND'
const RECEIVE_SMS: string = 'ohos.permission.RECEIVE_SMS'
const SEND_MESSAGES: string = 'ohos.permission.SEND_MESSAGES'
const READ_CONTACTS: string = 'ohos.permission.READ_CONTACTS'
const PLACE_CALL: string = 'ohos.permission.PLACE_CALL'

class TestFingerprint implements Fingerprint {
  kind: 'bundle' | 'file' = 'bundle'
  id: string = 'com.example.app'
  bundleName: string = 'com.example.app'
  version: string = ''
  versionCode: number = 1
  certSha256: string = 'AA:BB'
  certAlgo: 'platform-fingerprint' | 'sha256-of-cert-bytes' | 'none' = 'platform-fingerprint'
  sha256: string = ''
  size: number = 0
  label: string = ''
}

class TestVerdict implements Verdict {
  level: 'ok' | 'unknown' | 'suspicious' | 'risk' = 'suspicious'
  source: VerdictSource = 'local-rule'
  reason: string = ''
  evidence: string = 'heuristic'
  cloud: 'unchecked' | 'offline' | 'reached' = 'offline'
}

class TestHit implements ScanHit {
  fingerprint: Fingerprint = new TestFingerprint()
  displayName: string = ''
  verdict: Verdict = new TestVerdict()
  quarantined: boolean = false
  action: HitAction = 'none'
  granted: string[] = [BACKGROUND, CAMERA]
}

function require(value: boolean, message: string): void {
  if (!value) {
    throw new Error(message)
  }
}

function official(name: string, algo: string = 'platform-fingerprint'): OfficialRule {
  let row = new OfficialRule()
  row.bundleName = name
  row.certAlgo = algo
  row.certSha256 = ['ccdd']
  return row
}

function heuristic(id: string, permissions: string[], reason: string): HeuristicRule {
  let row = new HeuristicRule()
  row.id = id
  row.permissions = permissions
  row.reason = reason
  return row
}

function rulesWithHeuristics(): RuleLoad {
  let rules = new RuleLoad()
  rules.heuristics = [
    heuristic('sms-and-contacts', [RECEIVE_SMS, READ_CONTACTS], '短信和通讯录'),
    heuristic('sms-and-call', [SEND_MESSAGES, PLACE_CALL], '短信和拨打电话'),
    heuristic('background-location-and-camera', [BACKGROUND, CAMERA], '后台定位和相机')
  ]
  return rules
}

function checkLookalike(): void {
  let fp = new TestFingerprint()
  let rules = new RuleLoad()
  rules.officials = [
    official('com.example.aab', 'sha256-of-cert-bytes'),
    official('com.example.apq')
  ]
  let before = JSON.stringify(rules)
  let pick = Lookalike.select(fp, rules)
  require(pick.bundleName === 'com.example.apq' && pick.certAlgo === 'platform-fingerprint',
    '相似包名必须先选最短距离，再比较字典序')
  require(Lookalike.matches(pick, fp), '同算法且证书不同的选中行应命中相似包名')
  require(JSON.stringify(rules) === before, '相似包名比较不能改动规则')
  pick.certSha256.push('eeff')
  require(rules.officials[1].certSha256.length === 1, '选中行的证书数组必须独立')

  rules.officials = [official('com.example.apz'), official('com.example.apa')]
  require(Lookalike.select(fp, rules).bundleName === 'com.example.apa',
    '距离相同必须取字典序较小的包名')
  rules.officials.reverse()
  require(Lookalike.select(fp, rules).bundleName === 'com.example.apa',
    '不同规则顺序不能改变不同包名的距离同分结果')

  rules.officials = [official('com.example.apq', 'sha256-of-cert-bytes')]
  pick = Lookalike.select(fp, rules)
  require(pick.bundleName === 'com.example.apq' && !Lookalike.matches(pick, fp),
    '选中行算法不同时仍须返回该行，matches 则为 false')
  fp.kind = 'file'
  require(Lookalike.select(fp, rules).bundleName === 'com.example.apq',
    '读出包名的安装包必须使用相同的相似包名选择')
  fp.bundleName = ''
  require(Lookalike.select(fp, rules).bundleName === '', '没有包名的文件不能得到相似包名')
  fp.bundleName = 'com.example.app'
  fp.kind = 'bundle'

  rules.officials = [official('com.example.apq'), official(fp.bundleName, 'sha256-of-cert-bytes')]
  require(Lookalike.select(fp, rules).bundleName === '', '存在全等登记名时不得按距离挑选')
  let ignored = official(fp.bundleName)
  ignored.certSha256 = []
  rules.officials = [ignored, official('com.example.apq')]
  require(Lookalike.select(fp, rules).bundleName === 'com.example.apq',
    '空登记证书行不得参与全等判断')

  rules.officials = [official('com.example.apq')]
  rules.officials[0].certSha256 = ['aa-bb']
  pick = Lookalike.select(fp, rules)
  require(!Lookalike.matches(pick, fp), '相似包名的证书比较必须规范化')
  rules.officials = [official('com.distant.name')]
  require(Lookalike.select(fp, rules).bundleName === '', '超出编辑距离的登记名必须跳过')
  fp.bundleName = 'short.app'
  rules.officials = [official('short.apq')]
  pick = Lookalike.select(fp, rules)
  require(pick.bundleName === '' && pick.certAlgo === '' && pick.certSha256.length === 0,
    '较短名字不足十个字符时必须返回全部为空的选择')
}

function checkHeuristic(): void {
  let fp = new TestFingerprint()
  let rules = rulesWithHeuristics()
  require(!Heuristic.matches(fp, [BACKGROUND, CAMERA], [], true, rules).matched,
    '已装应用只声明权限时不能命中')
  require(!Heuristic.matches(fp, [], [BACKGROUND, CAMERA], false, rules).matched,
    'grantsReady=false 时已装应用不能命中')
  require(!Heuristic.matches(fp, [], [CAMERA], true, rules).matched,
    '只有相机授权时不能命中后台定位加相机')
  let granted = [BACKGROUND, CAMERA]
  let result = Heuristic.matches(fp, [], granted, true, rules)
  require(result.matched && result.reason === '已允许：后台定位和相机',
    '后台定位和相机都已授予时必须命中并使用固定前缀')
  require(granted.length === 2 && granted[0] === BACKGROUND, '启发式不能改动已授予权限')
  require(Heuristic.matches(fp, [], [RECEIVE_SMS, READ_CONTACTS], true, rules).matched,
    '短信加通讯录都已授予时必须命中')
  require(Heuristic.matches(fp, [], [SEND_MESSAGES, PLACE_CALL], true, rules).matched,
    '短信加拨打电话都已授予时必须命中')
  result = Heuristic.matches(fp, [], [RECEIVE_SMS, READ_CONTACTS, SEND_MESSAGES, PLACE_CALL], true, rules)
  require(result.reason === '已允许：短信和通讯录、短信和拨打电话', '多条命中原因必须合并')

  fp.kind = 'file'
  result = Heuristic.matches(fp, [BACKGROUND, CAMERA], [], false, rules)
  require(result.matched && result.reason === '安装包中声明：后台定位和相机',
    '安装包应在授权不可用时按声明命中')
  require(!Heuristic.matches(fp, [], [BACKGROUND, CAMERA], true, rules).matched,
    '安装包不能从 granted 推断声明')
  rules.heuristics = [heuristic('too-short', [CAMERA], '只有相机')]
  require(!Heuristic.matches(fp, [CAMERA], [], false, rules).matched, '少于两个权限的规则不能命中')
  rules.heuristics = [heuristic('long', [BACKGROUND, CAMERA], '长'.repeat(reasonMax + 1))]
  result = Heuristic.matches(fp, [BACKGROUND, CAMERA], [], false, rules)
  require(result.matched && result.reason.length === reasonMax && result.reason.startsWith('安装包中声明：'),
    '启发式合并原因必须包括前缀并受 reasonMax 约束')
}

function checkAnomaly(): void {
  let rules = rulesWithHeuristics()
  let trusted = new TestHit()
  trusted.verdict.source = 'trust'
  trusted.verdict.level = 'ok'
  let officialHit = new TestHit()
  officialHit.verdict.evidence = 'official'
  let self = new TestHit()
  self.fingerprint.bundleName = 'com.jinyinhu.securitycenter'
  let file = new TestHit()
  file.fingerprint.kind = 'file'
  let removed = new TestHit()
  removed.action = 'uninstall'
  let empty = new TestHit()
  empty.granted = []
  let partial = new TestHit()
  partial.granted = [CAMERA]
  let hits = [trusted, officialHit, self, file, removed, empty, partial]
  let before = JSON.stringify(hits)
  require(Anomaly.count(hits, rules) === 1, '异常人数必须排除登记、自身、文件、已处理和未完整授权的行')
  require(JSON.stringify(hits) === before, '异常人数统计不能改动快照')
  require(Anomaly.count([trusted], rules) === 1, '信任来源仍按已授予快照计入异常')
  require(Anomaly.count([], rules) === 0, '空快照异常人数应为零')
}

export function runDecideHelpersChecks(): void {
  checkLookalike()
  checkHeuristic()
  checkAnomaly()
}
