import type { CloudView, Fingerprint, TrustEntry, Verdict } from '../main/ets/center/CenterTypes'
import { reasonMax } from '../main/ets/center/CenterLimits'
import { canonicalCert, decide, terminalBeforeCloud } from '../main/ets/engine/Decide'
import { BundleRule, FileRule, HeuristicRule, OfficialRule, RuleLoad } from '../main/ets/engine/RulePack'

const CAMERA: string = 'ohos.permission.CAMERA'
const BACKGROUND: string = 'ohos.permission.LOCATION_IN_BACKGROUND'

function require(value: boolean, message: string): void {
  if (!value) {
    throw new Error(message)
  }
}

function fingerprint(): Fingerprint {
  return { kind: 'bundle', id: 'com.example.app', bundleName: 'com.example.app',
    version: '1', versionCode: 1, certSha256: 'AA:BB', certAlgo: 'platform-fingerprint',
    sha256: '', size: 0, label: '应用' }
}

function cloud(level: 'ok' | 'unknown' | 'risk' | 'none' = 'unknown'): CloudView {
  return { state: 'reached', level: level, reason: '', evidence: 'signed' }
}

function offline(reason: string = '未联网'): CloudView {
  return { state: 'offline', level: 'none', reason: reason, evidence: '' }
}

function bundle(cert: string = 'aabb', algo: string = 'platform-fingerprint'): BundleRule {
  let row = new BundleRule()
  row.bundleName = 'com.example.app'
  row.certAlgo = algo
  row.certSha256 = cert
  row.level = 'risk'
  row.reason = '演示用风险包'
  return row
}

function official(name: string = 'com.example.app', cert: string = 'aabb',
  algo: string = 'platform-fingerprint'): OfficialRule {
  let row = new OfficialRule()
  row.bundleName = name
  row.certAlgo = algo
  row.certSha256 = [cert]
  return row
}

function fileRule(level: string): FileRule {
  let row = new FileRule()
  row.sha256 = 'file-hash'
  row.level = level
  row.reason = '文件规则'
  return row
}

function trusted(fp: Fingerprint): TrustEntry[] {
  return [{ kind: 'bundle', fingerprint: canonicalCert(fp.certSha256), id: fp.bundleName,
    versionCode: fp.versionCode, at: '' }]
}

function heuristicRules(): RuleLoad {
  let rules = new RuleLoad()
  let row = new HeuristicRule()
  row.permissions = [BACKGROUND, CAMERA]
  row.reason = '后台定位和相机'
  rules.heuristics = [row]
  return rules
}

function judge(fp: Fingerprint, rules: RuleLoad, view: CloudView = cloud(),
  trust: TrustEntry[] = [], granted: string[] = []): Verdict {
  return decide(fp, [BACKGROUND, CAMERA], granted, true, rules, trust, view)
}

function checkTerminals(): void {
  let fp = fingerprint()
  let rules = new RuleLoad()
  require(terminalBeforeCloud(fp, rules) === null, '已装应用缺文件哈希仍应进入云批次')
  fp.id = ''
  require(terminalBeforeCloud(fp, rules)?.evidence === 'empty-fingerprint', '包 id 为空必须终止')
  fp = fingerprint()
  fp.kind = 'file'
  require(terminalBeforeCloud(fp, rules)?.evidence === 'empty-fingerprint', '文件空哈希必须终止')
  fp.sha256 = 'file-hash'
  rules.files = [fileRule('risk'), fileRule('ok')]
  require(judge(fp, rules, cloud('ok')).source === 'local-black', '文件黑哈希必须压过白哈希和云端正常')
  fp = fingerprint()
  fp.sha256 = 'file-hash'
  require(terminalBeforeCloud(fp, rules) === null, '包的文件哈希不能匹配文件黑规则')
  rules.bundles = [bundle()]
  rules.officials = [official()]
  let terminal = terminalBeforeCloud(fp, rules)
  require(terminal?.level === 'risk' && terminal.source === 'local-black',
    '高置信黑规则必须先于登记相符，不产生查询键')
  require(judge(fp, rules, cloud('ok'), trusted(fp)).source === 'local-black', '黑规则必须压过信任和云端正常')
  fp.kind = 'file'
  rules.files = []
  require(judge(fp, rules, cloud('ok')).source === 'local-black', '读出包名的安装包必须匹配包黑规则')
  fp = fingerprint()
  rules.bundles = []
  require(terminalBeforeCloud(fp, rules) === null, '登记相符必须继续问云')
  rules.officials = [official('com.example.app', 'ccdd')]
  terminal = terminalBeforeCloud(fp, rules)
  require(terminal?.evidence === 'impersonation' && terminal.reason === '签名与官方记录不符',
    '登记证书不符必须终止并使用缺省原因')
  require(judge(fp, rules, cloud('ok'), trusted(fp)).level === 'risk', '登记不符必须压过信任')
  rules.officials[0].reason = '登记原因'
  require(judge(fp, rules, offline()).reason === '登记原因', '终止结论不追加云失败')
  rules.officials.push(official())
  require(terminalBeforeCloud(fp, rules) === null, '有登记相符时不能用另一条登记证书判冒名')
  rules.officials = [official()]
  fp.certSha256 = ''
  require(terminalBeforeCloud(fp, rules) === null && judge(fp, rules, cloud('ok')).level === 'unknown',
    '空证书不能判冒名或登记相符，不能变成云端正常')
}

function checkCloudAndLocalOrder(): void {
  let fp = fingerprint()
  let rules = heuristicRules()
  rules.officials = [official()]
  require(judge(fp, rules, cloud('risk'), trusted(fp)).source === 'cloud', '云端风险必须压过登记相符和信任')
  let value = judge(fp, rules, offline(), [], [BACKGROUND, CAMERA])
  require(value.level === 'ok' && value.source === 'local-rule' && value.evidence === 'official' &&
    value.cloud === 'offline' && value.reason === '签名与官方记录一致、未联网',
    '离线登记相符应保持本地正常且不受启发式改写')
  value = judge(fp, rules, cloud('unknown'))
  require(value.reason === '签名与官方记录一致、云端暂无结果', '登记相符必须保留云端暂无结果')
  rules.officials[0].reason = '签名不符原因不应用于相符'
  require(judge(fp, rules, cloud()).reason.startsWith('签名与官方记录一致'), '登记相符不能使用不符原因')
  rules.officials = []
  value = judge(fp, rules, offline(), trusted(fp), [BACKGROUND, CAMERA])
  require(value.level === 'ok' && value.source === 'trust', '信任必须先于权限启发式')
  require(judge(fp, rules, cloud(), trusted(fp)).reason.endsWith('云端暂无结果'), '信任必须保留云端暂无结果')
  let wrongVersion = trusted(fp)
  wrongVersion[0].versionCode++
  require(judge(fp, rules, cloud(), wrongVersion).source !== 'trust', '包信任必须限定版本')
  let wrongName = trusted(fp)
  wrongName[0].id = 'com.example.other'
  require(judge(fp, rules, cloud(), wrongName).source !== 'trust', '包信任必须限定包名')
  let emptyTrust = trusted(fp)
  emptyTrust[0].fingerprint = ''
  require(judge(fp, rules, cloud(), emptyTrust).source !== 'trust', '空证书信任不得命中')
  fp.kind = 'file'
  fp.sha256 = 'file-hash'
  rules.files = [fileRule('ok')]
  require(judge(fp, rules, cloud('risk')).source === 'cloud', '云端风险必须压过白哈希')
  require(judge(fp, rules, offline()).level === 'ok', '白哈希不能被安装包声明启发式改写')
  rules.files = []
  let fileTrust: TrustEntry[] = [{ kind: 'file-sha256', fingerprint: 'file-hash',
    id: 'file://old', versionCode: 100, at: '' }]
  fp.id = 'file://new'
  require(judge(fp, rules, offline(), fileTrust).source === 'trust', '文件信任按哈希匹配，不比较 uri 和版本')
  require(judge(fp, rules, cloud('risk'), fileTrust).source === 'cloud', '云端风险必须压过文件信任')
}

function checkCertificateBranches(): void {
  let fp = fingerprint()
  let rules = new RuleLoad()
  rules.bundles = [bundle('ccdd')]
  require(terminalBeforeCloud(fp, rules) === null, '同名黑名单证书不符必须问云，不判冒名')
  let value = judge(fp, rules, cloud('ok'), trusted(fp))
  require(value.level === 'unknown' && value.evidence === 'bundle-cert-mismatch' && value.source !== 'cloud',
    '同名黑名单证书不符不能被云端正常或信任改写')
  require(judge(fp, rules, cloud('risk')).source === 'cloud', '云端风险仍优先于同名黑名单证书不符')
  rules.officials = [official()]
  require(judge(fp, rules, cloud('ok')).evidence === 'official', '登记相符必须先于其它黑名单证书不符')
  rules.officials = []
  rules.bundles = [bundle('aabb', 'sha256-of-cert-bytes')]
  value = judge(fp, rules, cloud('ok'), trusted(fp))
  require(value.evidence === 'cert-uncompared' && value.level === 'unknown', '算法不同比对不能被信任或云端正常改写')
  rules.bundles = []
  rules.officials = [official('com.example.app', 'aabb', 'sha256-of-cert-bytes')]
  require(judge(fp, rules, cloud('ok')).evidence === 'cert-uncompared', '全部全等登记算法不同时必须未知')
  rules.officials.push(official())
  require(judge(fp, rules, cloud('ok')).evidence === 'official', '任一全等登记算法相符且证书一致时应正常')
  rules.officials = [official('com.example.apq', 'ccdd', 'sha256-of-cert-bytes')]
  require(judge(fp, rules, cloud('ok')).evidence === 'cert-uncompared', '选中相似包名算法不同时必须在第八步结束')
  fp.kind = 'file'
  fp.sha256 = 'file-hash'
  require(judge(fp, rules, cloud('ok')).evidence === 'cert-uncompared', '安装包同样必须检查选中行算法')
  fp.kind = 'bundle'
  rules.officials = [official('com.example.aab', 'ccdd', 'sha256-of-cert-bytes'),
    official('com.example.apq', 'ccdd')]
  require(judge(fp, rules, cloud('ok')).evidence === 'lookalike', '更远登记名的算法不得覆盖最近的相符算法')
  rules.officials[1].certSha256 = ['AA-BB']
  require(judge(fp, rules, cloud('ok')).source === 'cloud', '选中相似包名允许同一规范化证书时不应可疑')
}

function checkHeuristicAndFallback(): void {
  let fp = fingerprint()
  let rules = heuristicRules()
  let value = judge(fp, rules, cloud('ok'), [], [BACKGROUND, CAMERA])
  require(value.level === 'suspicious' && value.evidence === 'heuristic' &&
    value.reason === '已允许：后台定位和相机、云端查询正常', '云端正常不能改写权限可疑')
  value = decide(fp, [BACKGROUND, CAMERA], [BACKGROUND, CAMERA], false, rules, [], cloud('ok'))
  require(value.source === 'cloud', '授权不可读时不能用权限启发式')
  require(judge(fp, rules, cloud('ok'), [], [CAMERA]).source === 'cloud', '只授予相机不应可疑')
  rules.officials = [official('com.example.apq', 'ccdd')]
  value = judge(fp, rules, offline(), [], [BACKGROUND, CAMERA])
  require(value.evidence === 'heuristic+lookalike' && value.reason.includes('com.example.apq') &&
    value.cloud === 'offline' && value.reason.endsWith('未联网'), '两种命中应同时保留证据、包名和离线说明')
  rules.officials = []
  let nameOnly = bundle('')
  nameOnly.step = 12
  nameOnly.level = 'unknown'
  rules.bundles = [nameOnly]
  value = judge(fp, rules, cloud('ok'))
  require(value.source === 'cloud' && value.level === 'ok', '证书可用时云端正常必须先于仅包名规则')
  value = judge(fp, rules, offline())
  require(value.level === 'unknown' && value.evidence === 'match=name-only', '仅包名只能产生未知')
  value = judge(fp, rules, cloud('unknown'))
  require(value.reason.endsWith('云端暂无结果'), '仅包名在线未知应保留云端暂无结果')
  rules.bundles = []
  rules.heuristics = []
  require(judge(fp, rules, offline()).reason === '未联网', '离线无结论只保留云失败句')
  require(judge(fp, rules, cloud()).reason === '暂无匹配结果、云端暂无结果', '在线未知应使用固定文案')
  value = judge(fp, rules, { state: 'offline', level: 'ok', reason: '未联网', evidence: '' })
  require(value.source !== 'cloud' && value.level === 'unknown', '手工构造离线正常不得产生云端正常')
  value = judge(fp, rules, cloud('none'))
  require(value.cloud === 'offline' && value.reason === '未联网，云端结果无效', '非法云等级必须按离线处理')
  value = judge(fp, rules, { state: 'unchecked', level: 'none', reason: '', evidence: '' })
  require(value.level === 'unknown' && value.evidence === 'unchecked-cloud', 'unchecked 必须返回调用错误标记')
  fp.certSha256 = ''
  require(judge(fp, rules, cloud('ok')).level === 'unknown', '证书为空不能写云端正常')
  fp.certSha256 = 'aabb'
  fp.certAlgo = 'none'
  require(judge(fp, rules, cloud('ok')).level === 'unknown', '证书算法为 none 不能写云端正常')
  fp.kind = 'file'
  fp.bundleName = ''
  fp.sha256 = 'file-hash'
  require(judge(fp, rules, cloud('ok')).source === 'cloud', '普通文件可按哈希得到云端正常')
}

function checkReasonLimitsAndPurity(): void {
  let fp = fingerprint()
  let rules = new RuleLoad()
  let row = bundle('')
  row.step = 12
  row.reason = '长'.repeat(reasonMax + 20)
  rules.bundles = [row]
  for (let reason of ['未联网', '未联网，云服务未配置', '未联网，云端结果无效']) {
    let value = judge(fp, rules, offline(reason))
    require(value.reason.length === reasonMax && value.reason.endsWith(reason), '长原因必须完整保留云失败句')
  }
  let value = judge(fp, rules, cloud())
  require(value.reason.length === reasonMax && value.reason.endsWith('云端暂无结果'), '长原因必须完整保留云端暂无结果')
  rules = heuristicRules()
  rules.heuristics[0].reason = '长'.repeat(reasonMax + 20)
  value = judge(fp, rules, cloud('ok'), [], [BACKGROUND, CAMERA])
  require(value.reason.length === reasonMax && value.reason.endsWith('云端查询正常'), '长可疑原因必须完整保留云端正常说明')
  rules.officials = [official('com.example.apq', 'ccdd')]
  for (let view of [cloud('ok'), offline('未联网，云服务未配置')]) {
    value = judge(fp, rules, view, [], [BACKGROUND, CAMERA])
    require(value.reason.length <= reasonMax && value.reason.includes('com.example.apq'),
      '长启发式原因必须为选中官方包名预留空间')
    require(value.reason.endsWith(view.state === 'offline' ? view.reason : '云端查询正常'),
      '长混合原因必须完整保留云端后缀')
  }
  let trust = trusted(fp)
  let view = cloud('ok')
  let before = JSON.stringify([fp, rules, trust, view])
  judge(fp, rules, view, trust, [BACKGROUND, CAMERA])
  require(JSON.stringify([fp, rules, trust, view]) === before, '判定函数不能修改输入或信任区')
}

export function runDecideChecks(): void {
  checkTerminals()
  checkCloudAndLocalOrder()
  checkCertificateBranches()
  checkHeuristicAndFallback()
  checkReasonLimitsAndPurity()
}
