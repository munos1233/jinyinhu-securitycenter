import { RulePack } from '../engine/RulePack'
import type { CenterFiles } from './Writer'
import { Writer } from './Writer'

export const preferencesName: string = 'jinyinhu'
export const rulesVersionKey: string = 'center.rulesVersion'
export const grantsKey: string = 'center.grants'

export class CenterStore {
  static prepare(files: CenterFiles, readRules: (() => string | null) | null = null): void {
    Writer.bind(files)
    Writer.recover()
    let text: string | null = null
    if (readRules !== null) {
      try {
        text = readRules()
      } catch (err) {
        text = null
      }
    }
    RulePack.load(text)
  }
}
