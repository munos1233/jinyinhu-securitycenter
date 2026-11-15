import type { CancelFlag as CenterCancel } from '../center/CenterTypes'

export const CANCEL_BYTES: number = 4
const GO: number = 0
const STOP: number = 1

/**
 * 一个作业一份。整数 0 继续，1 取消。
 * 传给 TaskPool 的是 buffer 本身，Worker 每个分块之后读同一块内存。
 */
export class CancelFlag implements CenterCancel {
  buffer: SharedArrayBuffer
  private cells: Int32Array

  constructor() {
    this.buffer = new SharedArrayBuffer(CANCEL_BYTES)
    this.cells = new Int32Array(this.buffer)
    Atomics.store(this.cells, 0, GO)
  }

  cancel(): void {
    Atomics.store(this.cells, 0, STOP)
  }

  cancelled(): boolean {
    return Atomics.load(this.cells, 0) === STOP
  }
}

/** ReputationClient 的 CancelRead。只看本次传入的标志。 */
export function readCancel(flag: CenterCancel): boolean {
  if (flag instanceof CancelFlag) {
    return flag.cancelled()
  }
  return false
}
