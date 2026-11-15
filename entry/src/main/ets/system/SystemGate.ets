import abilityAccessCtrl from '@ohos.abilityAccessCtrl';
import type { Permissions } from '@ohos.abilityAccessCtrl';
import type { BusinessError } from '@ohos.base';
import bundleManager from '@ohos.bundle.bundleManager';
import installer from '@ohos.bundle.installer';
import storageStatistics from '@ohos.file.storageStatistics';
import fileShare from '@ohos.fileshare';
import privacyManager from '@ohos.privacyManager';
import huks from '@ohos.security.huks';
import { hilog } from '@kit.PerformanceAnalysisKit';
import { gateCacheMs } from '../center/CenterLimits';
import type { Gate, GateStatus } from '../center/CenterTypes';

const DOMAIN: number = 0x4A59
const TAG: string = 'Center'

const SENSITIVE: Permissions = 'ohos.permission.GET_SENSITIVE_PERMISSIONS'
const REVOKE: Permissions = 'ohos.permission.REVOKE_SENSITIVE_PERMISSIONS'
const USED_STATS: Permissions = 'ohos.permission.PERMISSION_USED_STATS'
const REMOVE_CACHE: Permissions = 'ohos.permission.REMOVE_CACHE_FILES'
const PERSIST: Permissions = 'ohos.permission.FILE_ACCESS_PERSIST'
const ABSENT_BUNDLE: string = 'com.jinyinhu.securitycenter.gate.absent'
const HUKS_ALIAS: string = 'jyh.center.gate.probe'

export interface SystemGate {
  bundles(): Gate
  grants(): Gate
  revoke(): Gate
  usedStats(): Gate
  cacheStats(): Gate
  clearCache(): Gate
  uninstall(): Gate
  persistFileGrant(): Gate
  userPickedFiles(): Gate
  ownCache(): Gate
  posture(): Gate
  huks(): Gate
  probe(): Promise<void>
  invalidate(): void
  stale(): boolean
}

export interface GateProbes {
  bundles(): Promise<Gate>
  grants(): Promise<Gate>
  revoke(): Promise<Gate>
  usedStats(): Promise<Gate>
  cacheStats(): Promise<Gate>
  clearCache(): Promise<Gate>
  uninstall(): Promise<Gate>
  persistFileGrant(): Promise<Gate>
  posture(): Promise<Gate>
  huks(): Promise<Gate>
}

export type RefusableGate = 'grants' | 'revoke' | 'cacheStats' | 'clearCache' | 'persistFileGrant'

/** 端口调用时被系统拒绝，把对应 Gate 记成 unsupported。下一次 probe() 重新探测。 */
export interface GateRefusal {
  refuse(id: RefusableGate, reason: string): void
}

export class GateValue implements Gate {
  id: string = ''
  status: GateStatus = 'unsupported'
  reason: string = ''
}

export function gateOf(id: string, status: GateStatus, reason: string): GateValue {
  let gate = new GateValue()
  gate.id = id
  gate.status = status
  gate.reason = reason
  return gate
}

export function errorCode(err: Object): string {
  try {
    let code = (err as BusinessError).code
    if (code !== undefined && code !== null) {
      return String(code)
    }
  } catch (e) {
  }
  return 'error'
}

class GateSet {
  bundles: Gate = gateOf('bundles', 'unsupported', 'not-probed')
  grants: Gate = gateOf('grants', 'unsupported', 'not-probed')
  revoke: Gate = gateOf('revoke', 'unsupported', 'not-probed')
  usedStats: Gate = gateOf('usedStats', 'unsupported', 'not-probed')
  cacheStats: Gate = gateOf('cacheStats', 'unsupported', 'not-probed')
  clearCache: Gate = gateOf('clearCache', 'unsupported', 'not-probed')
  uninstall: Gate = gateOf('uninstall', 'unsupported', 'not-probed')
  persistFileGrant: Gate = gateOf('persistFileGrant', 'unsupported', 'not-probed')
  posture: Gate = gateOf('posture', 'unsupported', 'not-probed')
  huks: Gate = gateOf('huks', 'unsupported', 'not-probed')
}

export class ProbedGate implements SystemGate, GateRefusal {
  private probes: GateProbes
  private now: () => number
  private current: GateSet = new GateSet()
  private probedAt: number = -1
  private generation: number = 0
  private started: number = 0
  private applied: number = 0
  private inflight: Promise<void> | null = null
  private inflightGeneration: number = -1

  constructor(probes: GateProbes, now: () => number) {
    this.probes = probes
    this.now = now
  }

  bundles(): Gate {
    return this.current.bundles
  }

  grants(): Gate {
    return this.current.grants
  }

  revoke(): Gate {
    return this.current.revoke
  }

  usedStats(): Gate {
    return this.current.usedStats
  }

  cacheStats(): Gate {
    return this.current.cacheStats
  }

  clearCache(): Gate {
    return this.current.clearCache
  }

  uninstall(): Gate {
    return this.current.uninstall
  }

  persistFileGrant(): Gate {
    return this.current.persistFileGrant
  }

  userPickedFiles(): Gate {
    return gateOf('userPickedFiles', 'ready', '')
  }

  ownCache(): Gate {
    return gateOf('ownCache', 'ready', '')
  }

  posture(): Gate {
    return this.current.posture
  }

  huks(): Gate {
    return this.current.huks
  }

  probe(): Promise<void> {
    if (this.inflight !== null && this.inflightGeneration === this.generation) {
      return this.inflight
    }
    let generation = this.generation
    this.started++
    let run = this.started
    let task = this.collect().then((next: GateSet): void => {
      if (run > this.applied) {
        this.applied = run
        this.current = next
      }
      if (generation === this.generation) {
        this.probedAt = this.now()
      }
      if (this.inflight === task) {
        this.inflight = null
      }
    })
    this.inflight = task
    this.inflightGeneration = generation
    return task
  }

  invalidate(): void {
    this.generation++
    this.probedAt = -1
  }

  refuse(id: RefusableGate, reason: string): void {
    hilog.warn(DOMAIN, TAG, 'gate %{public}s refused: %{public}s', id, reason)
    let gate = gateOf(id, 'unsupported', reason)
    if (id === 'grants') {
      this.current.grants = gate
    } else if (id === 'revoke') {
      this.current.revoke = gate
    } else if (id === 'cacheStats') {
      this.current.cacheStats = gate
    } else if (id === 'clearCache') {
      this.current.clearCache = gate
    } else {
      this.current.persistFileGrant = gate
    }
  }

  stale(): boolean {
    if (this.probedAt < 0) {
      return true
    }
    return this.now() - this.probedAt >= gateCacheMs
  }

  private async collect(): Promise<GateSet> {
    let next = new GateSet()
    let results = await Promise.all([
      settle('bundles', this.probes.bundles()),
      settle('grants', this.probes.grants()),
      settle('revoke', this.probes.revoke()),
      settle('usedStats', this.probes.usedStats()),
      settle('cacheStats', this.probes.cacheStats()),
      settle('clearCache', this.probes.clearCache()),
      settle('uninstall', this.probes.uninstall()),
      settle('persistFileGrant', this.probes.persistFileGrant()),
      settle('posture', this.probes.posture()),
      settle('huks', this.probes.huks())
    ])
    next.bundles = results[0]
    next.grants = results[1]
    next.revoke = results[2]
    next.usedStats = results[3]
    next.cacheStats = results[4]
    next.clearCache = results[5]
    next.uninstall = results[6]
    next.persistFileGrant = results[7]
    next.posture = results[8]
    next.huks = results[9]
    return next
  }
}

async function settle(id: string, pending: Promise<Gate>): Promise<Gate> {
  try {
    let gate = await pending
    if (gate.status === 'ready') {
      return gateOf(id, 'ready', '')
    }
    hilog.info(DOMAIN, TAG, 'gate %{public}s unsupported: %{public}s', id, gate.reason)
    return gateOf(id, 'unsupported', gate.reason)
  } catch (err) {
    let reason = 'probe-failed:' + errorCode(err as Object)
    hilog.error(DOMAIN, TAG, 'gate %{public}s %{public}s', id, reason)
    return gateOf(id, 'unsupported', reason)
  }
}

class SelfApp {
  bundleName: string = ''
  tokenId: number = 0
}

export class SdkGateProbes implements GateProbes {
  async bundles(): Promise<Gate> {
    try {
      await bundleManager.getAllBundleInfo(bundleManager.BundleFlag.GET_BUNDLE_INFO_DEFAULT)
      return gateOf('bundles', 'ready', '')
    } catch (err) {
      return gateOf('bundles', 'unsupported', 'getAllBundleInfo:' + errorCode(err as Object))
    }
  }

  async grants(): Promise<Gate> {
    let manager = abilityAccessCtrl.createAtManager()
    if (typeof manager.getPermissionFlags !== 'function') {
      return gateOf('grants', 'unsupported', 'missing:getPermissionFlags')
    }
    return granted('grants', SENSITIVE)
  }

  async revoke(): Promise<Gate> {
    let manager = abilityAccessCtrl.createAtManager()
    if (typeof manager.revokeUserGrantedPermission !== 'function') {
      return gateOf('revoke', 'unsupported', 'missing:revokeUserGrantedPermission')
    }
    return granted('revoke', REVOKE)
  }

  async usedStats(): Promise<Gate> {
    if (typeof privacyManager.getPermissionUsedRecord !== 'function') {
      return gateOf('usedStats', 'unsupported', 'missing:getPermissionUsedRecord')
    }
    return granted('usedStats', USED_STATS)
  }

  async cacheStats(): Promise<Gate> {
    if (typeof storageStatistics.getBundleStats !== 'function') {
      return gateOf('cacheStats', 'unsupported', 'missing:getBundleStats')
    }
    let self = selfApp()
    if (self === null) {
      return gateOf('cacheStats', 'unsupported', 'self-unreadable')
    }
    try {
      await storageStatistics.getBundleStats(self.bundleName)
      return gateOf('cacheStats', 'ready', '')
    } catch (err) {
      return gateOf('cacheStats', 'unsupported', 'getBundleStats:' + errorCode(err as Object))
    }
  }

  async clearCache(): Promise<Gate> {
    if (typeof bundleManager.cleanBundleCacheFiles !== 'function') {
      return gateOf('clearCache', 'unsupported', 'missing:cleanBundleCacheFiles')
    }
    // 真调一次会清掉本应用自己的缓存，所以只查方法与授权。
    return granted('clearCache', REMOVE_CACHE)
  }

  async uninstall(): Promise<Gate> {
    let tool: installer.BundleInstaller
    try {
      tool = await installer.getBundleInstaller()
    } catch (err) {
      return gateOf('uninstall', 'unsupported', 'getBundleInstaller:' + errorCode(err as Object))
    }
    try {
      await tool.uninstall(ABSENT_BUNDLE)
      return gateOf('uninstall', 'ready', '')
    } catch (err) {
      let code = errorCode(err as Object)
      // 201/202 是权限被拒；INSTALL_BUNDLE 或 UNINSTALL_BUNDLE 任一授予时，系统会走到「包不存在」这一类错误。
      if (code === '201' || code === '202') {
        return gateOf('uninstall', 'unsupported', 'uninstall:' + code)
      }
      return gateOf('uninstall', 'ready', '')
    }
  }

  async persistFileGrant(): Promise<Gate> {
    if (typeof fileShare.persistPermission !== 'function') {
      return gateOf('persistFileGrant', 'unsupported', 'missing:persistPermission')
    }
    return granted('persistFileGrant', PERSIST)
  }

  async posture(): Promise<Gate> {
    return gateOf('posture', 'unsupported', 'jyh_security_center-not-implemented')
  }

  async huks(): Promise<Gate> {
    let options: huks.HuksOptions = {
      properties: [
        { tag: huks.HuksTag.HUKS_TAG_ALGORITHM, value: huks.HuksKeyAlg.HUKS_ALG_AES },
        { tag: huks.HuksTag.HUKS_TAG_KEY_SIZE, value: huks.HuksKeySize.HUKS_AES_KEY_SIZE_256 },
        {
          tag: huks.HuksTag.HUKS_TAG_PURPOSE,
          value: huks.HuksKeyPurpose.HUKS_KEY_PURPOSE_ENCRYPT | huks.HuksKeyPurpose.HUKS_KEY_PURPOSE_DECRYPT
        }
      ]
    }
    try {
      await huks.generateKeyItem(HUKS_ALIAS, options)
    } catch (err) {
      return gateOf('huks', 'unsupported', 'generateKeyItem:' + errorCode(err as Object))
    }
    try {
      await huks.deleteKeyItem(HUKS_ALIAS, { properties: [] })
    } catch (err) {
      hilog.warn(DOMAIN, TAG, 'gate huks probe key not deleted: %{public}s', errorCode(err as Object))
    }
    return gateOf('huks', 'ready', '')
  }
}

function selfApp(): SelfApp | null {
  try {
    let info = bundleManager.getBundleInfoForSelfSync(bundleManager.BundleFlag.GET_BUNDLE_INFO_WITH_APPLICATION)
    let self = new SelfApp()
    self.bundleName = info.name
    self.tokenId = info.appInfo.accessTokenId
    return self
  } catch (err) {
    hilog.error(DOMAIN, TAG, 'gate self bundle unreadable: %{public}s', errorCode(err as Object))
    return null
  }
}

function granted(id: string, permission: Permissions): Gate {
  let self = selfApp()
  if (self === null || self.tokenId === 0) {
    return gateOf(id, 'unsupported', 'self-unreadable')
  }
  try {
    let status = abilityAccessCtrl.createAtManager().checkAccessTokenSync(self.tokenId, permission)
    if (status === abilityAccessCtrl.GrantStatus.PERMISSION_GRANTED) {
      return gateOf(id, 'ready', '')
    }
    return gateOf(id, 'unsupported', 'not-granted:' + permission)
  } catch (err) {
    return gateOf(id, 'unsupported', 'checkAccessToken:' + errorCode(err as Object))
  }
}
