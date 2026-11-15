import type { BusinessError } from '@ohos.base';
import bundleManager from '@ohos.bundle.bundleManager';
import storageStatistics from '@ohos.file.storageStatistics';
import { hilog } from '@kit.PerformanceAnalysisKit';
import { CenterError } from '../center/CenterError';
import type { CacheClear, CacheStats } from '../center/CenterTypes';
import type { GateRefusal, SystemGate } from './SystemGate';

const DOMAIN: number = 0x4A59
const TAG: string = 'Center'

/** 201：权限被拒；202：非系统应用；801：本设备没有该接口。 */
const REFUSED: string[] = ['201', '202', '801']

export interface CacheSource {
  cacheBytes(bundleName: string): Promise<number>
  clear(bundleName: string): Promise<void>
}

/** 统计只当场返回，不另存一份。 */
export class CachePort implements CacheStats, CacheClear {
  private gate: SystemGate
  private refusal: GateRefusal
  private source: CacheSource

  constructor(gate: SystemGate, refusal: GateRefusal, source: CacheSource) {
    this.gate = gate
    this.refusal = refusal
    this.source = source
  }

  async stats(bundleName: string): Promise<number> {
    let gate = this.gate.cacheStats()
    if (gate.status !== 'ready') {
      throw new CenterError('unsupported', gate.reason)
    }
    let bytes: number
    try {
      bytes = await this.source.cacheBytes(bundleName)
    } catch (err) {
      throw this.failed('cacheStats', 'getBundleStats', bundleName, err as Object)
    }
    if (typeof bytes !== 'number' || !Number.isFinite(bytes) || bytes < 0) {
      hilog.warn(DOMAIN, TAG, 'cache stats malformed %{public}s', bundleName)
      throw new CenterError('io', 'getBundleStats:malformed')
    }
    return Math.floor(bytes)
  }

  async clear(bundleName: string): Promise<void> {
    let gate = this.gate.clearCache()
    if (gate.status !== 'ready') {
      throw new CenterError('unsupported', gate.reason)
    }
    try {
      await this.source.clear(bundleName)
    } catch (err) {
      throw this.failed('clearCache', 'cleanBundleCacheFiles', bundleName, err as Object)
    }
  }

  private failed(id: 'cacheStats' | 'clearCache', api: string, bundleName: string, err: Object): CenterError {
    let code = codeOf(err)
    let raw = api + ':' + code
    hilog.error(DOMAIN, TAG, 'cache %{public}s %{public}s failed: %{public}s', api, bundleName, code)
    if (REFUSED.indexOf(code) >= 0) {
      this.refusal.refuse(id, raw)
      return new CenterError('unsupported', raw)
    }
    return new CenterError('io', raw)
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

class Missing extends Error {
  code: number = 801
}

export class SdkCacheSource implements CacheSource {
  async cacheBytes(bundleName: string): Promise<number> {
    if (typeof storageStatistics.getBundleStats !== 'function') {
      throw new Missing('missing:getBundleStats')
    }
    let stats = await storageStatistics.getBundleStats(bundleName)
    return stats.cacheSize
  }

  async clear(bundleName: string): Promise<void> {
    if (typeof bundleManager.cleanBundleCacheFiles !== 'function') {
      throw new Missing('missing:cleanBundleCacheFiles')
    }
    await bundleManager.cleanBundleCacheFiles(bundleName)
  }
}
