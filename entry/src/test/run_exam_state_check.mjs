import { spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const root = resolve(here, '../../..')
const files = [
  ['entry/src/main/ets/center/CenterTypes.ets', 'CenterTypes.ts'],
  ['entry/src/main/ets/center/PostureRule.ets', 'PostureRule.ts'],
  ['entry/src/main/ets/feature/exam/ExamState.ets', 'ExamState.ts'],
  ['entry/src/test/ExamState.test.ets', 'ExamState.test.ts']
]

function prep(source) {
  return source
    .replace(/import \{ hilog \} from '@kit\.PerformanceAnalysisKit';\n/,
      "const hilog = { error() {}, info() {}, warn() {} };\n")
    .replaceAll("from '../../center/CenterTypes'", "from './CenterTypes.ts'")
    .replaceAll("from '../main/ets/center/PostureRule'", "from './PostureRule.ts'")
    .replaceAll("from '../main/ets/center/CenterTypes'", "from './CenterTypes.ts'")
    .replaceAll("from '../main/ets/feature/exam/ExamState'", "from './ExamState.ts'")
}

const dir = mkdtempSync(join(tmpdir(), 'exam-state-'))
try {
  for (const [from, to] of files) {
    writeFileSync(join(dir, to), prep(readFileSync(resolve(root, from), 'utf8')))
  }
  writeFileSync(join(dir, 'main.ts'),
    "import { runExamStateChecks } from './ExamState.test.ts';\nrunExamStateChecks();\n")
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
