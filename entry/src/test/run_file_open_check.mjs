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
  ['entry/src/main/ets/center/CenterError.ets', 'CenterError.ts'],
  ['entry/src/main/ets/feature/clean/Exclude.ets', 'Exclude.ts'],
  ['entry/src/main/ets/system/FileOpen.ets', 'FileOpen.ts'],
  ['entry/src/test/FileOpen.test.ets', 'FileOpen.test.ts']
]

function prep(source) {
  return source
    .replace(/import fs from '@ohos\.file\.fs';\n/,
      "const fs = { openSync() { throw new Error('unused'); }, lstatSync(path) { if (String(path).indexOf('link') >= 0) { return { isSymbolicLink() { return true; } }; } throw new Error('missing'); }, closeSync() {}, OpenMode: { READ_ONLY: 0 } };\n")
    .replace(/import \{ hilog \} from '@kit\.PerformanceAnalysisKit';\n/g,
      "const hilog = { error() {}, info() {}, warn() {} };\n")
    .replaceAll("from '../../center/CenterLimits'", "from './CenterLimits.ts'")
    .replaceAll("from '../center/CenterError'", "from './CenterError.ts'")
    .replaceAll("from '../center/CenterTypes'", "from './CenterTypes.ts'")
    .replaceAll("from './CenterTypes'", "from './CenterTypes.ts'")
    .replaceAll("from '../feature/clean/Exclude'", "from './Exclude.ts'")
    .replaceAll("from '../main/ets/center/CenterError'", "from './CenterError.ts'")
    .replaceAll("from '../main/ets/center/CenterTypes'", "from './CenterTypes.ts'")
    .replaceAll("from '../main/ets/feature/clean/Exclude'", "from './Exclude.ts'")
    .replaceAll("from '../main/ets/system/FileOpen'", "from './FileOpen.ts'")
    .replace(/from '\.\/CenterTypes'(?!\.ts)/g, "from './CenterTypes.ts'")
}

const dir = mkdtempSync(join(tmpdir(), 'file-open-'))
try {
  for (const [from, to] of files) {
    writeFileSync(join(dir, to), prep(readFileSync(resolve(root, from), 'utf8')))
  }
  writeFileSync(join(dir, 'main.ts'),
    "import { runFileOpenChecks } from './FileOpen.test.ts';\nrunFileOpenChecks();\n")
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
