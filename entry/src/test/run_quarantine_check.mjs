import { readFileSync } from 'node:fs'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const root = resolve(here, '../../..')
const EXCLUDE = '/data/storage/el2/base/files/center/quarantine'
const backup = JSON.parse(readFileSync(resolve(root, 'entry/src/main/resources/base/profile/backup_config.json'), 'utf8'))
const excludes = Array.isArray(backup.excludes) ? backup.excludes : null
if (excludes === null) {
  if (backup.allowToBackupRestore !== false) {
    process.stderr.write('没有 excludes 时不能整包备份\n')
    process.exit(1)
  }
} else if (backup.allowToBackupRestore !== true || excludes.indexOf(EXCLUDE) < 0) {
  process.stderr.write('排除路径必须是 ' + EXCLUDE + '\n')
  process.exit(1)
}
const ability = readFileSync(resolve(root, 'entry/src/main/ets/entrybackupability/EntryBackupAbility.ets'), 'utf8')
if (ability.indexOf('quarantine') >= 0) {
  process.stderr.write('EntryBackupAbility 读取了隔离目录\n')
  process.exit(1)
}

const files = [
  ['entry/src/main/ets/center/CenterTypes.ets', 'CenterTypes.ts'],
  ['entry/src/main/ets/center/CenterLimits.ets', 'CenterLimits.ts'],
  ['entry/src/main/ets/center/CenterError.ets', 'CenterError.ts'],
  ['entry/src/main/ets/center/Clock.ets', 'Clock.ts'],
  ['entry/src/main/ets/feature/exam/ExamState.ets', 'ExamState.ts'],
  ['entry/src/main/ets/feature/clean/Exclude.ets', 'Exclude.ts'],
  ['entry/src/main/ets/system/FileOpen.ets', 'FileOpen.ts'],
  ['entry/src/main/ets/record/Writer.ets', 'Writer.ts'],
  ['entry/src/main/ets/record/StreamingSha256.ets', 'StreamingSha256.ts'],
  ['entry/src/main/ets/record/Quarantine.ets', 'Quarantine.ts'],
  ['entry/src/test/Quarantine.test.ets', 'Quarantine.test.ts']
]

function prep(source) {
  return source
    .replace(/import fs from '@ohos\.file\.fs';\n/,
      "const fs = { openSync() { throw new Error('unused'); }, statSync() { return { size: 0 }; }, readSync() {}, writeSync() {}, closeSync() {}, lstatSync() { throw new Error('unused'); }, unlinkSync() {}, OpenMode: { READ_ONLY: 0, CREATE: 0, TRUNC: 0 } };\n")
    .replace(/import \{ hilog \} from '@kit\.PerformanceAnalysisKit';\n/g,
      "const hilog = { error() {}, info() {}, warn() {} };\n")
    .replaceAll("from '../../center/CenterLimits'", "from './CenterLimits.ts'")
    .replaceAll("from '../center/Clock'", "from './Clock.ts'")
    .replaceAll("from '../center/CenterError'", "from './CenterError.ts'")
    .replaceAll("from '../center/CenterLimits'", "from './CenterLimits.ts'")
    .replaceAll("from '../center/CenterTypes'", "from './CenterTypes.ts'")
    .replaceAll("from './CenterTypes'", "from './CenterTypes.ts'")
    .replaceAll("from '../feature/exam/ExamState'", "from './ExamState.ts'")
    .replaceAll("from '../feature/clean/Exclude'", "from './Exclude.ts'")
    .replaceAll("from '../system/FileOpen'", "from './FileOpen.ts'")
    .replaceAll("from '../engine/HashWorker'", "from './HashWorker.ts'")
    .replaceAll("from './Writer'", "from './Writer.ts'")
    .replaceAll("from './StreamingSha256'", "from './StreamingSha256.ts'")
    .replaceAll("from '../main/ets/center/CenterError'", "from './CenterError.ts'")
    .replaceAll("from '../main/ets/center/CenterLimits'", "from './CenterLimits.ts'")
    .replaceAll("from '../main/ets/center/CenterTypes'", "from './CenterTypes.ts'")
    .replaceAll("from '../main/ets/system/FileOpen'", "from './FileOpen.ts'")
    .replaceAll("from '../main/ets/record/Quarantine'", "from './Quarantine.ts'")
    .replaceAll("from '../main/ets/record/StreamingSha256'", "from './StreamingSha256.ts'")
    .replaceAll("from '../main/ets/record/Writer'", "from './Writer.ts'")
    .replace(/from '\.\/CenterTypes'(?!\.ts)/g, "from './CenterTypes.ts'")
    .replace(/from '\.\/Writer'(?!\.ts)/g, "from './Writer.ts'")
}

const dir = mkdtempSync(join(tmpdir(), 'quarantine-'))
try {
  for (const [from, to] of files) {
    writeFileSync(join(dir, to), prep(readFileSync(resolve(root, from), 'utf8')))
  }
  writeFileSync(join(dir, 'HashWorker.ts'), 'export class HashWorker { async hash() { throw new Error("unused"); } }\n')
  writeFileSync(join(dir, 'main.ts'),
    "import { runQuarantineChecks } from './Quarantine.test.ts';\nawait runQuarantineChecks();\n")
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
