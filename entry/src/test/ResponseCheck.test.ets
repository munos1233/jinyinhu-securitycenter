import type { QueryKey } from '../main/ets/center/CenterTypes'
import { cloudAlg, cloudKid } from '../main/ets/center/CenterLimits'
import type { ReputationItem, ReputationResponse, SignatureVerifier } from '../main/ets/cloud/ResponseCheck'
import { ResponseCheck } from '../main/ets/cloud/ResponseCheck'

export type TestSigner = (text: string) => string

const NONCE: string = '0123456789abcdef0123456789abcdef'
const INVALID: string = '未联网，云端结果无效'

class TestKey implements QueryKey {
  bundleName: string = 'com.example.alpha'
  versionCode: number = 1
  certSha256: string = 'aabb'
  sha256: string = ''
}

class TestItem implements ReputationItem {
  bundleName: string = ''
  versionCode: number = 0
  certSha256: string = ''
  sha256: string = ''
  level: string = 'ok'
  reason: string = '云端查询正常'
  evidence: string = 'signed-result'
}

class TestResponse implements ReputationResponse {
  alg: string = cloudAlg
  kid: string = cloudKid
  nonce: string = NONCE
  version: string = '2026.11.12'
  items: ReputationItem[] = []
  signature: string = ''
}

function require(value: boolean, message: string): void {
  if (!value) {
    throw new Error(message)
  }
}

function keys(): QueryKey[] {
  let first = new TestKey()
  let second = new TestKey()
  second.bundleName = ''
  second.versionCode = 0
  second.certSha256 = ''
  second.sha256 = 'user-file-hash'
  return [first, second]
}

function response(request: QueryKey[]): ReputationResponse {
  let result = new TestResponse()
  for (let i = 0; i < request.length; i++) {
    let item = new TestItem()
    item.bundleName = request[i].bundleName
    item.versionCode = request[i].versionCode
    item.certSha256 = request[i].certSha256
    item.sha256 = request[i].sha256
    result.items.push(item)
  }
  return result
}

function textOf(result: ReputationResponse, versionTexts: string[] = []): string {
  let lines: string[] = []
  for (let i = 0; i < result.items.length; i++) {
    let item = result.items[i]
    let version = versionTexts.length > i ? versionTexts[i] : String(item.versionCode)
    lines.push([item.bundleName, version, item.certSha256, item.sha256,
      item.level, item.reason, item.evidence].join('|'))
  }
  return result.nonce + '\n' + result.version + '\n' + lines.join('\n')
}

function signed(request: QueryKey[], sign: TestSigner): ReputationResponse {
  let result = response(request)
  result.signature = sign(textOf(result))
  return result
}

function reject(request: QueryKey[], nonce: string, result: ReputationResponse | null,
  verify: SignatureVerifier, message: string): void {
  let checked = ResponseCheck.accept(request, nonce, result, verify)
  require(!checked.accepted && checked.version === '' && checked.views.length === request.length, message)
  for (let i = 0; i < checked.views.length; i++) {
    let view = checked.views[i]
    require(view.state === 'offline' && view.level === 'none' && view.reason === INVALID, message)
  }
}

function checkValid(sign: TestSigner, verify: SignatureVerifier): void {
  let request = keys()
  let result = signed(request, sign)
  let beforeRequest = JSON.stringify(request)
  let beforeResult = JSON.stringify(result)
  let checked = ResponseCheck.accept(request, NONCE, result, verify)
  require(checked.accepted && checked.version === result.version && checked.views.length === 2,
    '规范签名响应应整批通过并保留已验签版本')
  require(checked.views[0].state === 'reached' && checked.views[0].level === 'ok' &&
    checked.views[0].reason === result.items[0].reason &&
    checked.views[0].evidence === result.items[0].evidence, '验签通过后必须保留行结论')
  require(JSON.stringify(request) === beforeRequest && JSON.stringify(result) === beforeResult,
    '响应校验不能修改请求或响应')

  result.items[0].reason = 'éΩ中文结果🙂' + '\ud800' + '\udfff'
  result.items[1].reason = '另一个结果'
  result.items[1].level = 'risk'
  result.signature = sign(textOf(result))
  checked = ResponseCheck.accept(request, NONCE, result, verify)
  require(checked.accepted && checked.views[0].reason === result.items[0].reason &&
    checked.views[1].level === 'risk', '签名必须覆盖精确 UTF-8 文本及原始条目顺序')

  result = signed(request, sign)
  result.version = '2026.1.2'
  result.signature = sign(textOf(result))
  require(ResponseCheck.accept(request, NONCE, result, verify).accepted,
    '版本格式比较属于规则包，已签名的非定宽版本不应导致整批验签失败')
  let empty = signed([], sign)
  checked = ResponseCheck.accept([], NONCE, empty, verify)
  require(checked.accepted && checked.views.length === 0, '空批次仍应验证规范头部')
}

function checkWholeBatchFailures(sign: TestSigner, verify: SignatureVerifier): void {
  let request = keys()
  let result = signed(request, sign)
  result.alg = 'SHA256withRSA'
  reject(request, NONCE, result, verify, '算法不匹配必须整批拒绝')
  result = signed(request, sign)
  result.kid = 'secondary'
  reject(request, NONCE, result, verify, 'kid 不匹配必须整批拒绝')
  result = signed(request, sign)
  reject(request, 'fedcba9876543210fedcba9876543210', result, verify, '旧 nonce 响应必须整批拒绝')
  result.items[0].reason = '签名之后篡改'
  reject(request, NONCE, result, verify, '内容篡改必须导致真实 ECDSA 验签失败')
  result = signed(request, sign)
  result.signature = 'invalid-base64-signature'
  reject(request, NONCE, result, verify, '无效签名必须整批拒绝')
  result = signed(request, sign)
  result.items.pop()
  result.signature = sign(textOf(result))
  reject(request, NONCE, result, verify, '条目数量不一致必须整批拒绝')
  result = signed(request, sign)
  result.items.reverse()
  result.signature = sign(textOf(result))
  reject(request, NONCE, result, verify, '已签名的乱序回显不能按应用原始下标回填')

  let mismatches: ReputationResponse[] = []
  result = response(request)
  result.items[0].bundleName = 'com.other'
  mismatches.push(result)
  result = response(request)
  result.items[0].versionCode = 2
  mismatches.push(result)
  result = response(request)
  result.items[0].certSha256 = 'ccdd'
  mismatches.push(result)
  result = response(request)
  result.items[0].sha256 = 'another-hash'
  mismatches.push(result)
  for (let i = 0; i < mismatches.length; i++) {
    mismatches[i].signature = sign(textOf(mismatches[i]))
    reject(request, NONCE, mismatches[i], verify, '回显四字段任一不一致都必须整批拒绝')
  }
  reject(request, NONCE, null, verify, '空响应必须整批拒绝')
  reject(request, NONCE, signed(request, sign), () => false, '验签返回 false 必须整批拒绝')
  reject(request, NONCE, signed(request, sign), () => {
    throw new Error('verify failed')
  }, '验签抛错必须整批拒绝')
}

function checkDelimiters(sign: TestSigner, verify: SignatureVerifier): void {
  let request = keys()
  let delimiters = ['|', '\n', '\r']
  for (let i = 0; i < delimiters.length; i++) {
    let delimiter = delimiters[i]
    let bad: ReputationResponse[] = []
    let result = response(request)
    result.version += delimiter
    bad.push(result)
    result = response(request)
    result.items[0].bundleName += delimiter
    bad.push(result)
    result = response(request)
    result.items[0].certSha256 += delimiter
    bad.push(result)
    result = response(request)
    result.items[0].sha256 += delimiter
    bad.push(result)
    result = response(request)
    result.items[0].level += delimiter
    bad.push(result)
    result = response(request)
    result.items[0].reason += delimiter
    bad.push(result)
    result = response(request)
    result.items[0].evidence += delimiter
    bad.push(result)
    for (let j = 0; j < bad.length; j++) {
      bad[j].signature = sign(textOf(bad[j]))
      reject(request, NONCE, bad[j], verify, '字段分隔符或换行必须整批拒绝')
    }
    result = signed(request, sign)
    result.signature += delimiter
    reject(request, NONCE, result, verify, 'signature 字段中的分隔符或换行必须整批拒绝')
  }
}

function checkDecimalAndShape(sign: TestSigner, verify: SignatureVerifier): void {
  let request = keys()
  let result = response(request)
  result.signature = sign(textOf(result, ['01', '0']))
  reject(request, NONCE, result, verify, '签名文本 versionCode=01 必须整批拒绝')
  result.signature = sign(textOf(result, ['1.0', '0']))
  reject(request, NONCE, result, verify, '签名文本 versionCode=1.0 必须整批拒绝')
  result.signature = sign(textOf(result) + '\n')
  reject(request, NONCE, result, verify, '签名文本额外增加换行必须整批拒绝')
  let malformed = [
    'false', '[]', '{}',
    '{"alg":"SHA256withECDSA","kid":"primary","nonce":"' + NONCE +
      '","version":"2026.11.12","items":[null,null],"signature":"x"}',
    '{"alg":"SHA256withECDSA","kid":"primary","nonce":"' + NONCE +
      '","version":"2026.11.12","items":{},"signature":"x"}'
  ]
  for (let i = 0; i < malformed.length; i++) {
    let parsed = JSON.parse(malformed[i]) as ReputationResponse
    reject(request, NONCE, parsed, verify, '不合格响应结构必须整批拒绝且不能抛错')
  }
  result = response(request)
  let serialized = JSON.stringify(result).replace('"versionCode":1', '"versionCode":"01"')
  let parsed = JSON.parse(serialized) as ReputationResponse
  parsed.signature = sign(textOf(result))
  reject(request, NONCE, parsed, verify, 'versionCode 的数字字符串不能代替数字')
  result = response(request)
  result.items[0].versionCode = 1.5
  result.signature = sign(textOf(result))
  reject(request, NONCE, result, verify, 'versionCode 必须是非负整数')
  request[0].versionCode = Number.MAX_SAFE_INTEGER
  result = signed(request, sign)
  require(ResponseCheck.accept(request, NONCE, result, verify).accepted,
    '安全整数上界必须按完整十进制写法验证')
}

function checkInvalidLevel(sign: TestSigner, verify: SignatureVerifier): void {
  let request = keys()
  let result = response(request)
  result.items[0].level = 'suspicious'
  result.items[1].level = 'unknown'
  result.signature = sign(textOf(result))
  let checked = ResponseCheck.accept(request, NONCE, result, verify)
  require(checked.accepted && checked.version === result.version &&
    checked.views[0].state === 'offline' && checked.views[0].level === 'none' &&
    checked.views[0].reason === INVALID && checked.views[1].state === 'reached' &&
    checked.views[1].level === 'unknown', '验签通过后的单条非法等级只能拒绝该条')
}

export function runResponseCheckChecks(sign: TestSigner, verify: SignatureVerifier): void {
  checkValid(sign, verify)
  checkWholeBatchFailures(sign, verify)
  checkDelimiters(sign, verify)
  checkDecimalAndShape(sign, verify)
  checkInvalidLevel(sign, verify)
}
