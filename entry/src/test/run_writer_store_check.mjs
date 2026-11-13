import { spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const root = resolve(here, '../../..')
const files = [
  ['entry/src/main/ets/center/CenterTypes.ets', 'CenterTypes.ts'],
  ['entry/src/main/ets/center/CenterLimits.ets', 'CenterLimits.ts'],
  ['entry/src/main/ets/center/Clock.ets', 'Clock.ts'],
  ['entry/src/main/ets/feature/exam/ExamState.ets', 'ExamState.ts'],
  ['entry/src/main/ets/record/Writer.ets', 'Writer.ts'],
  ['entry/src/main/ets/record/ResultStore.ets', 'ResultStore.ts'],
  ['entry/src/main/ets/record/CenterStore.ets', 'CenterStore.ts'],
  ['entry/src/test/WriterStore.test.ets', 'WriterStore.test.ts']
]

function prep(source) {
  return source
    .replace(/import fs from '@ohos\.file\.fs';\n/,
      "const fs = { openSync() { throw new Error('unused'); }, statSync() { return { size: 0 }; }, readSync() {}, writeSync() {}, closeSync() {}, renameSync() {}, unlinkSync() {}, mkdirSync() {} };\n")
    .replace(/import \{ hilog \} from '@kit\.PerformanceAnalysisKit';\n/,
      "const hilog = { error() {}, info() {}, warn() {} };\n")
    .replaceAll("from '../center/CenterLimits'", "from './CenterLimits.ts'")
    .replaceAll("from '../center/Clock'", "from './Clock.ts'")
    .replaceAll("from '../center/CenterTypes'", "from './CenterTypes.ts'")
    .replaceAll("from '../../center/CenterTypes'", "from './CenterTypes.ts'")
    .replaceAll("from '../feature/exam/ExamState'", "from './ExamState.ts'")
    .replaceAll("from '../main/ets/center/CenterLimits'", "from './CenterLimits.ts'")
    .replaceAll("from '../main/ets/center/CenterTypes'", "from './CenterTypes.ts'")
    .replaceAll("from '../main/ets/record/CenterStore'", "from './CenterStore.ts'")
    .replaceAll("from '../main/ets/record/ResultStore'", "from './ResultStore.ts'")
    .replaceAll("from '../main/ets/record/Writer'", "from './Writer.ts'")
    .replace(/from '\.\/Writer'(?!\.ts)/g, "from './Writer.ts'")
}

const dir = mkdtempSync(join(tmpdir(), 'writer-store-'))
try {
  for (const [from, to] of files) {
    writeFileSync(join(dir, to), prep(readFileSync(resolve(root, from), 'utf8')))
  }
  writeFileSync(join(dir, 'main.ts'),
    "import { runWriterStoreChecks } from './WriterStore.test.ts';\nrunWriterStoreChecks();\n")
  const run = spawnSync(process.execPath, ['--experimental-strip-types', join(dir, 'main.ts')], {
    encoding: 'utf8'
  })
  if (run.status !== 0) {
    process.stderr.write(run.stdout || '')
    process.stderr.write(run.stderr || '')
    process.exit(run.status === null ? 1 : run.status)
  }
} finally {
  rmSync(dir, { recursive: true, force: true })
}
