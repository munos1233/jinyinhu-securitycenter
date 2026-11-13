import type { CenterFiles } from './Writer'
import { Writer } from './Writer'

export class CenterStore {
  static prepare(files: CenterFiles): void {
    Writer.bind(files)
    Writer.recover()
  }
}
