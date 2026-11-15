import { taskpool } from '@kit.ArkTS'
import { hilog } from '@kit.PerformanceAnalysisKit'
import { CenterError } from '../center/CenterError'
import { CryptoDigest, FsHashIo, hashFd, HashResult } from './Hash'

const DOMAIN: number = 0x4A59
const TAG: string = 'Center'
/**
 * CenterError.raw 的前缀。带这个前缀的 io 让整次作业 failed，其余 io 只让该条失败。
 * Runner 不得吞掉它：该次是体检时，JobRunner 要靠它记 failed 并收口已写下的结果。
 */
export const WORKER_DOWN: string = 'hash-worker:'

@Concurrent
function hashInWorker(fd: number, cancel: SharedArrayBuffer): HashResult {
  return hashFd(new FsHashIo(), new CryptoDigest(), fd, cancel)
}

export interface HashPool {
  run(fd: number, cancel: SharedArrayBuffer): Promise<HashResult>
}

/** cancel 是 CancelFlag.buffer 本身，TaskPool 与 UI 线程共享，不是布尔值的副本。 */
export class TaskPoolHash implements HashPool {
  run(fd: number, cancel: SharedArrayBuffer): Promise<HashResult> {
    let task = new taskpool.Task(hashInWorker, fd, cancel)
    return taskpool.execute(task) as Promise<HashResult>
  }
}

export class HashWorker {
  private pool: HashPool

  constructor(pool: HashPool = new TaskPoolHash()) {
    this.pool = pool
  }

  /**
   * Worker 起不来时抛 raw 以 WORKER_DOWN 开头的 io，不退回 UI 线程哈希，也不返回空结果。
   * 单个文件读失败抛普通 io。取消时返回 cancelled=true，sha256 为空串。
   */
  async hash(fd: number, cancel: SharedArrayBuffer): Promise<HashResult> {
    let pending: Promise<HashResult>
    try {
      pending = this.pool.run(fd, cancel)
    } catch (err) {
      throw workerDown(err as Object)
    }
    let result: HashResult
    try {
      result = await pending
    } catch (err) {
      throw workerDown(err as Object)
    }
    if (result.error.length > 0) {
      throw new CenterError('io', result.error)
    }
    return result
  }
}

export function isWorkerDown(err: Object): boolean {
  if (!(err instanceof CenterError)) {
    return false
  }
  return err.code === 'io' && err.raw.indexOf(WORKER_DOWN) === 0
}

function workerDown(err: Object): CenterError {
  let detail = 'error'
  if (err instanceof Error) {
    detail = err.message
  }
  hilog.error(DOMAIN, TAG, 'hash worker unavailable: %{public}s', detail)
  return new CenterError('io', WORKER_DOWN + detail)
}
