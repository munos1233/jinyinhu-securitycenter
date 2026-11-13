import type { CenterFiles } from './Writer'
import { Writer } from './Writer'

export const preferencesName: string = 'jinyinhu'
export const rulesVersionKey: string = 'center.rulesVersion'
export const grantsKey: string = 'center.grants'

export class CenterStore {
  static prepare(files: CenterFiles): void {
    Writer.bind(files)
    Writer.recover()
  }
}
