import abilityAccessCtrl from '@ohos.abilityAccessCtrl';
import type { Permissions } from '@ohos.abilityAccessCtrl';
import type { BusinessError } from '@ohos.base';
import bundleManager from '@ohos.bundle.bundleManager';
import privacyManager from '@ohos.privacyManager';
import { hilog } from '@kit.PerformanceAnalysisKit';
import { CenterError } from '../center/CenterError';
import { useListMax, useLookbackMs } from '../center/CenterLimits';
import type {
  AccessFacts,
  AccessRevoke,
  BundleRow,
  GrantLookup,
  InstallSource,
  PermissionFact,
  UseFact
} from '../center/CenterTypes';
import { groupOf, isSensitive } from '../center/SensitiveCatalog';
import type { GateRefusal, SystemGate } from './SystemGate';

const DOMAIN: number = 0x4A59
const TAG: string = 'Center'

const PREFIX: string = 'ohos.permission.'

/** 撤权时写入的 flag。用户之后不能再申请，只能去系统设置重新打开。禁止传 0 或 PERMISSION_USER_SET。 */
export const PERMISSION_USER_FIXED: number = 1 << 1
export const PERMISSION_SYSTEM_FIXED: number = 1 << 2
export const PERMISSION_PRE_AUTHORIZED_CANCELABLE: number = 1 << 3
export const PERMISSION_FIXED_FOR_SECURITY_POLICY: number = 1 << 5
export const PERMISSION_FIXED_BY_ADMIN_POLICY: number = 1 << 7

const STATUS_DENIED: number = -1
const STATUS_GRANTED: number = 0
const STATUS_NOT_DETERMINED: number = 1
const STATUS_RESTRICTED: number = 3

/** 201：权限被拒；202：非系统应用；801：本设备没有该接口。 */
const REFUSED: string[] = ['201', '202', '801']

type Grant = 'granted' | 'denied' | 'unknown'

export class RawAccess {
  tokenId: number = 0
  label: string = ''
  permissions: string[] = []
}

export class RawUse {
  bundleName: string = ''
  permission: string = ''
  at: number = 0
}

export interface AccessSource {
  bundleOf(bundleName: string): Promise<RawAccess>
  statusOf(tokenId: number, permissions: string[]): Promise<number[]>
  flagsOf(tokenId: number, permission: string): Promise<number>
  revoke(tokenId: number, permission: string): Promise<void>
  usedSince(begin: number, end: number): Promise<RawUse[]>
}

class Fact implements PermissionFact {
  bundleName: string = ''
  displayName: string = ''
  permission: string = ''
  label: string = ''
  group: string = ''
  sensitive: boolean = false
  declared: boolean = true
  grant: Grant = 'unknown'
  fixed: boolean = false
  tokenId: number = 0
  source: InstallSource = 'unknown'
}

class Use implements UseFact {
  bundleName: string = ''
  displayName: string = ''
  permission: string = ''
  label: string = ''
  at: string = ''
}

class GrantRead {
  grant: Grant = 'unknown'
  fixed: boolean = false
}

/** 读授权时被系统拒绝。整次结果退回 unknown，Gate 已记成 unsupported。 */
class Refused {
  raw: string = ''
}

export function isFixed(flags: number): boolean {
  return (flags & (PERMISSION_SYSTEM_FIXED | PERMISSION_FIXED_FOR_SECURITY_POLICY | PERMISSION_FIXED_BY_ADMIN_POLICY)) !== 0
}

export function grantOf(status: number): Grant {
  if (status === STATUS_GRANTED) {
    return 'granted'
  }
  if (status === STATUS_DENIED || status === STATUS_NOT_DETERMINED || status === STATUS_RESTRICTED) {
    return 'denied'
  }
  return 'unknown'
}

export function permissionLabel(permission: string): string {
  return permission.indexOf(PREFIX) === 0 ? permission.substring(PREFIX.length) : permission
}

export class AccessPort implements AccessFacts, GrantLookup, AccessRevoke {
  private gate: SystemGate
  private refusal: GateRefusal
  private source: AccessSource
  private now: () => number

  constructor(gate: SystemGate, refusal: GateRefusal, source: AccessSource, now: () => number) {
    this.gate = gate
    this.refusal = refusal
    this.source = source
    this.now = now
  }

  ready(): boolean {
    return this.gate.grants().status === 'ready'
  }

  async grantedOf(bundleName: string): Promise<string[]> {
    if (!this.ready()) {
      return []
    }
    let raw = await this.readBundle(bundleName)
    if (raw === null || raw.tokenId === 0) {
      return []
    }
    let permissions = unique(raw.permissions)
    let reads = await this.readGrants(bundleName, raw.tokenId, permissions)
    if (reads instanceof Refused) {
      return []
    }
    let out: string[] = []
    for (let i = 0; i < permissions.length; i++) {
      if (reads[i].grant === 'granted') {
        out.push(permissions[i])
      }
    }
    return out
  }

  async facts(bundles: BundleRow[]): Promise<PermissionFact[]> {
    let out: Fact[] = []
    let refused = false
    for (let b = 0; b < bundles.length; b++) {
      let row = bundles[b]
      let raw = await this.readBundle(row.bundleName)
      let tokenId = raw === null ? 0 : raw.tokenId
      let displayName = raw === null || raw.label.length === 0 ? row.bundleName : raw.label
      let permissions = unique(row.declaredPermissions)
      let reads: GrantRead[] | Refused | null = null
      if (!refused && tokenId !== 0 && this.ready()) {
        reads = await this.readGrants(row.bundleName, tokenId, permissions)
        if (reads instanceof Refused) {
          refused = true
        }
      }
      for (let i = 0; i < permissions.length; i++) {
        let fact = new Fact()
        fact.bundleName = row.bundleName
        fact.displayName = displayName
        fact.permission = permissions[i]
        fact.label = permissionLabel(permissions[i])
        fact.group = groupOf(permissions[i])
        fact.sensitive = isSensitive(permissions[i])
        fact.tokenId = tokenId
        fact.source = row.source
        if (reads !== null && !(reads instanceof Refused)) {
          fact.grant = reads[i].grant
          fact.fixed = reads[i].fixed
        }
        out.push(fact)
      }
    }
    if (refused) {
      for (let i = 0; i < out.length; i++) {
        out[i].grant = 'unknown'
        out[i].fixed = false
      }
    }
    return out
  }

  async canRevoke(tokenId: number, permission: string): Promise<boolean> {
    if (!validToken(tokenId) || !this.ready() || this.gate.revoke().status !== 'ready') {
      return false
    }
    try {
      return !isFixed(await this.source.flagsOf(tokenId, permission))
    } catch (err) {
      let code = codeOf(err as Object)
      hilog.warn(DOMAIN, TAG, 'access flags recheck failed: %{public}s', code)
      if (REFUSED.indexOf(code) >= 0) {
        this.refusal.refuse('grants', 'getPermissionFlags:' + code)
      }
      return false
    }
  }

  async revoke(tokenId: number, permission: string): Promise<void> {
    if (!validToken(tokenId)) {
      throw new CenterError('unsupported', 'token-unreadable')
    }
    let gate = this.gate.revoke()
    if (gate.status !== 'ready') {
      throw new CenterError('unsupported', gate.reason)
    }
    try {
      await this.source.revoke(tokenId, permission)
    } catch (err) {
      let code = codeOf(err as Object)
      hilog.error(DOMAIN, TAG, 'access revoke %{public}s failed: %{public}s', permission, code)
      if (REFUSED.indexOf(code) >= 0) {
        let raw = 'revokeUserGrantedPermission:' + code
        this.refusal.refuse('revoke', raw)
        throw new CenterError('unsupported', raw)
      }
      throw err as Error
    }
  }

  async recentUses(): Promise<UseFact[]> {
    let gate = this.gate.usedStats()
    if (gate.status !== 'ready') {
      throw new CenterError('unsupported', gate.reason)
    }
    let end = this.now()
    let begin = end - useLookbackMs
    let raws: RawUse[]
    try {
      raws = await this.source.usedSince(begin, end)
    } catch (err) {
      let raw = 'getPermissionUsedRecord:' + codeOf(err as Object)
      hilog.error(DOMAIN, TAG, 'access recent uses failed: %{public}s', raw)
      throw new CenterError('unsupported', raw)
    }
    let kept: RawUse[] = []
    for (let i = 0; i < raws.length; i++) {
      if (raws[i].at >= begin && raws[i].at <= end) {
        kept.push(raws[i])
      }
    }
    kept.sort((a: RawUse, b: RawUse): number => b.at - a.at)
    let out: UseFact[] = []
    for (let i = 0; i < kept.length && i < useListMax; i++) {
      let use = new Use()
      use.bundleName = kept[i].bundleName
      use.displayName = kept[i].bundleName
      use.permission = kept[i].permission
      use.label = permissionLabel(kept[i].permission)
      use.at = new Date(kept[i].at).toISOString()
      out.push(use)
    }
    return out
  }

  private async readBundle(bundleName: string): Promise<RawAccess | null> {
    try {
      let raw = await this.source.bundleOf(bundleName)
      if (!validToken(raw.tokenId)) {
        hilog.warn(DOMAIN, TAG, 'access token unreadable %{public}s', bundleName)
        raw.tokenId = 0
      }
      return raw
    } catch (err) {
      hilog.warn(DOMAIN, TAG, 'access bundle unreadable %{public}s: %{public}s', bundleName, codeOf(err as Object))
      return null
    }
  }

  private async readGrants(bundleName: string, tokenId: number, permissions: string[]): Promise<GrantRead[] | Refused> {
    let reads: GrantRead[] = []
    for (let i = 0; i < permissions.length; i++) {
      reads.push(new GrantRead())
    }
    if (permissions.length === 0) {
      return reads
    }
    let statuses: number[]
    try {
      statuses = await this.source.statusOf(tokenId, permissions)
    } catch (err) {
      return this.failed(bundleName, 'getPermissionsStatus', err as Object, reads)
    }
    if (statuses.length !== permissions.length) {
      hilog.warn(DOMAIN, TAG, 'access status length mismatch %{public}s', bundleName)
      return reads
    }
    for (let i = 0; i < permissions.length; i++) {
      let grant = grantOf(statuses[i])
      if (grant === 'unknown') {
        continue
      }
      let flags: number
      try {
        flags = await this.source.flagsOf(tokenId, permissions[i])
      } catch (err) {
        let failed = this.failed(bundleName, 'getPermissionFlags', err as Object, reads)
        if (failed instanceof Refused) {
          return failed
        }
        reads[i].grant = grant
        continue
      }
      reads[i].grant = grant
      reads[i].fixed = isFixed(flags)
    }
    return reads
  }

  private failed(bundleName: string, api: string, err: Object, reads: GrantRead[]): GrantRead[] | Refused {
    let code = codeOf(err)
    hilog.warn(DOMAIN, TAG, 'access %{public}s %{public}s failed: %{public}s', api, bundleName, code)
    if (REFUSED.indexOf(code) < 0) {
      return reads
    }
    let refused = new Refused()
    refused.raw = api + ':' + code
    this.refusal.refuse('grants', refused.raw)
    return refused
  }
}

function validToken(tokenId: number): boolean {
  return typeof tokenId === 'number' && Number.isInteger(tokenId) && tokenId > 0
}

function unique(names: string[]): string[] {
  let out: string[] = []
  for (let i = 0; i < names.length; i++) {
    if (out.indexOf(names[i]) < 0) {
      out.push(names[i])
    }
  }
  return out
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

class Missing extends Error {
  code: number = 801
}

const INFO_FLAGS: number = bundleManager.BundleFlag.GET_BUNDLE_INFO_WITH_APPLICATION |
  bundleManager.BundleFlag.GET_BUNDLE_INFO_WITH_REQUESTED_PERMISSION

export class SdkAccessSource implements AccessSource {
  async bundleOf(bundleName: string): Promise<RawAccess> {
    let info = await bundleManager.getBundleInfo(bundleName, INFO_FLAGS)
    let raw = new RawAccess()
    let app = info.appInfo
    if (app !== undefined && app !== null) {
      if (typeof app.accessTokenId === 'number') {
        raw.tokenId = app.accessTokenId
      }
      if (typeof app.label === 'string' && app.label.length > 0 && app.label.indexOf('$') !== 0) {
        raw.label = app.label
      }
    }
    let details = info.reqPermissionDetails
    if (details !== undefined && details !== null) {
      for (let i = 0; i < details.length; i++) {
        raw.permissions.push(details[i].name)
      }
    }
    return raw
  }

  async statusOf(tokenId: number, permissions: string[]): Promise<number[]> {
    let manager = abilityAccessCtrl.createAtManager()
    if (typeof manager.getPermissionsStatus !== 'function') {
      throw new Missing('missing:getPermissionsStatus')
    }
    let list: Permissions[] = []
    for (let i = 0; i < permissions.length; i++) {
      list.push(permissions[i] as Permissions)
    }
    let result = await manager.getPermissionsStatus(tokenId, list)
    let out: number[] = []
    for (let i = 0; i < result.length; i++) {
      out.push(result[i] as number)
    }
    return out
  }

  async flagsOf(tokenId: number, permission: string): Promise<number> {
    let manager = abilityAccessCtrl.createAtManager()
    if (typeof manager.getPermissionFlags !== 'function') {
      throw new Missing('missing:getPermissionFlags')
    }
    return await manager.getPermissionFlags(tokenId, permission as Permissions)
  }

  async revoke(tokenId: number, permission: string): Promise<void> {
    let manager = abilityAccessCtrl.createAtManager()
    if (typeof manager.revokeUserGrantedPermission !== 'function') {
      throw new Missing('missing:revokeUserGrantedPermission')
    }
    await manager.revokeUserGrantedPermission(tokenId, permission as Permissions, PERMISSION_USER_FIXED)
  }

  async usedSince(begin: number, end: number): Promise<RawUse[]> {
    if (typeof privacyManager.getPermissionUsedRecord !== 'function') {
      throw new Missing('missing:getPermissionUsedRecord')
    }
    let request: privacyManager.PermissionUsedRequest = {
      beginTime: begin,
      endTime: end,
      flag: privacyManager.PermissionUsageFlag.FLAG_PERMISSION_USAGE_DETAIL
    }
    let response = await privacyManager.getPermissionUsedRecord(request)
    let out: RawUse[] = []
    let bundles = response.bundleRecords
    if (bundles === undefined || bundles === null) {
      return out
    }
    for (let b = 0; b < bundles.length; b++) {
      let records = bundles[b].permissionRecords
      if (records === undefined || records === null) {
        continue
      }
      for (let r = 0; r < records.length; r++) {
        let details = records[r].accessRecords
        if (details !== undefined && details !== null && details.length > 0) {
          for (let d = 0; d < details.length; d++) {
            out.push(useOf(bundles[b].bundleName, records[r].permissionName, details[d].timestamp))
          }
        } else if (records[r].lastAccessTime > 0) {
          out.push(useOf(bundles[b].bundleName, records[r].permissionName, records[r].lastAccessTime))
        }
      }
    }
    return out
  }
}

function useOf(bundleName: string, permission: string, at: number): RawUse {
  let use = new RawUse()
  use.bundleName = bundleName
  use.permission = permission
  use.at = at
  return use
}
