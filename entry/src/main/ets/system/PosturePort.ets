import screenLockFileManager from '@ohos.ability.screenLockFileManager';
import type { BusinessError } from '@ohos.base';
import systemParameterEnhance from '@ohos.systemParameterEnhance';
import { hilog } from '@kit.PerformanceAnalysisKit';
import type { CheckStatus, PosturePort, ProtectFact } from '../center/CenterTypes';
import { lockdownOk, pureModeOk } from '../center/PostureRule';

const DOMAIN: number = 0x4A59
const TAG: string = 'Center'

const PURE_MODE_KEY: string = 'persist.jyh.pure_mode'
const LOCKDOWN_KEYS: string[] = ['const.jyh.lockdown', 'persist.jyh.lockdown']

export const PURE_MODE_UNREADABLE: string = '无法读取纯净模式'
export const LOCKDOWN_UNREADABLE: string = '无法读取锁定状态'
export const EL5_UNREADABLE: string = '无法读取加密服务'

export type ParamOutcome = 'value' | 'missing' | 'failed'

export class ParamRead {
  outcome: ParamOutcome = 'failed'
  value: string = ''
  reason: string = ''
}

export interface ParamReader {
  read(key: string): ParamRead
}

/** present：服务在；absent：系统答复服务不在；no-interface：没有查询接口；failed：查询出错。 */
export type El5Outcome = 'present' | 'absent' | 'no-interface' | 'failed'

export class El5Read {
  outcome: El5Outcome = 'failed'
  reason: string = ''
}

export interface El5Query {
  query(): El5Read
}

class Fact implements ProtectFact {
  id: string = ''
  status: CheckStatus = 'unsupported'
  expected: string = ''
  actual: string = ''
  detail: string = ''
}

function fact(id: string, status: CheckStatus, expected: string, actual: string, detail: string): Fact {
  let value = new Fact()
  value.id = id
  value.status = status
  value.expected = expected
  value.actual = actual
  value.detail = detail
  return value
}

export class ParamPosturePort implements PosturePort {
  private params: ParamReader
  private keys: El5Query

  constructor(params: ParamReader, keys: El5Query) {
    this.params = params
    this.keys = keys
  }

  async pureMode(): Promise<ProtectFact> {
    try {
      let read = this.params.read(PURE_MODE_KEY)
      if (read.outcome !== 'value') {
        hilog.warn(DOMAIN, TAG, 'posture pure-mode unreadable: %{public}s', read.reason)
        return fact('pure-mode', 'unsupported', '1', '', PURE_MODE_UNREADABLE)
      }
      if (pureModeOk(read.value)) {
        return fact('pure-mode', 'ok', '1', read.value, '纯净模式已开启')
      }
      return fact('pure-mode', 'risk', '1', read.value, '纯净模式未开启')
    } catch (err) {
      hilog.error(DOMAIN, TAG, 'posture pure-mode failed: %{public}s', codeOf(err as Object))
      return fact('pure-mode', 'unsupported', '1', '', PURE_MODE_UNREADABLE)
    }
  }

  async lockdown(): Promise<ProtectFact> {
    try {
      let reasons: string[] = []
      for (let i = 0; i < LOCKDOWN_KEYS.length; i++) {
        let read = this.params.read(LOCKDOWN_KEYS[i])
        if (read.outcome !== 'value') {
          reasons.push(LOCKDOWN_KEYS[i] + ':' + read.reason)
          continue
        }
        if (lockdownOk(read.value)) {
          return fact('lockdown', 'ok', 'confidentiality', read.value, '锁定模式为 confidentiality')
        }
        return fact('lockdown', 'risk', 'confidentiality', read.value, '锁定模式不是 confidentiality')
      }
      hilog.warn(DOMAIN, TAG, 'posture lockdown unreadable: %{public}s', reasons.join(','))
      return fact('lockdown', 'unsupported', 'confidentiality', '', LOCKDOWN_UNREADABLE)
    } catch (err) {
      hilog.error(DOMAIN, TAG, 'posture lockdown failed: %{public}s', codeOf(err as Object))
      return fact('lockdown', 'unsupported', 'confidentiality', '', LOCKDOWN_UNREADABLE)
    }
  }

  async el5(): Promise<ProtectFact> {
    try {
      let read = this.keys.query()
      if (read.outcome === 'present') {
        return fact('el5', 'ok', '在', '在', '文件加密服务在')
      }
      if (read.outcome === 'absent') {
        return fact('el5', 'risk', '在', '不在', '文件加密服务不在')
      }
      hilog.warn(DOMAIN, TAG, 'posture el5 unreadable: %{public}s %{public}s', read.outcome, read.reason)
      return fact('el5', 'unsupported', '在', '', EL5_UNREADABLE)
    } catch (err) {
      hilog.error(DOMAIN, TAG, 'posture el5 failed: %{public}s', codeOf(err as Object))
      return fact('el5', 'unsupported', '在', '', EL5_UNREADABLE)
    }
  }
}

function codeOf(err: Object): string {
  try {
    let code = (err as BusinessError).code
    if (code !== undefined && code !== null) {
      return String(code)
    }
  } catch (e) {
  }
  return 'error'
}

const PARAM_NOT_FOUND: string = '14700101'
const CAPABILITY_ABSENT: string = '801'

export class SdkParamReader implements ParamReader {
  read(key: string): ParamRead {
    let read = new ParamRead()
    if (typeof systemParameterEnhance.getSync !== 'function') {
      read.outcome = 'failed'
      read.reason = 'missing:getSync'
      return read
    }
    try {
      read.value = systemParameterEnhance.getSync(key)
      read.outcome = 'value'
    } catch (err) {
      let code = codeOf(err as Object)
      read.outcome = code === PARAM_NOT_FOUND ? 'missing' : 'failed'
      read.reason = code
    }
    return read
  }
}

export class SdkEl5Query implements El5Query {
  query(): El5Read {
    let read = new El5Read()
    if (typeof screenLockFileManager.queryAppKeyState !== 'function') {
      read.outcome = 'no-interface'
      read.reason = 'missing:queryAppKeyState'
      return read
    }
    try {
      screenLockFileManager.queryAppKeyState()
      read.outcome = 'present'
    } catch (err) {
      let code = codeOf(err as Object)
      read.outcome = code === CAPABILITY_ABSENT ? 'absent' : 'failed'
      read.reason = code
    }
    return read
  }
}
