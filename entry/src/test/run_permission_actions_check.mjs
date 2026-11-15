import { spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../../..')
const ACTIONS = 'entry/src/main/ets/record/PermissionActions.ets'
const files = [
  ['entry/src/main/ets/center/CenterTypes.ets', 'CenterTypes.ts'],
  ['entry/src/main/ets/center/CenterLimits.ets', 'CenterLimits.ts'],
  ['entry/src/main/ets/center/CenterError.ets', 'CenterError.ts'],
  ['entry/src/main/ets/center/Clock.ets', 'Clock.ts'],
  ['entry/src/main/ets/center/CleanMath.ets', 'CleanMath.ts'],
  ['entry/src/main/ets/center/SensitiveCatalog.ets', 'SensitiveCatalog.ts'],
  ['entry/src/main/ets/center/Anomaly.ets', 'Anomaly.ts'],
  ['entry/src/main/ets/engine/Decide.ets', 'Decide.ts'],
  ['entry/src/main/ets/engine/LocalRuleEngine.ets', 'LocalRuleEngine.ts'],
  ['entry/src/main/ets/engine/Lookalike.ets', 'Lookalike.ts'],
  ['entry/src/main/ets/engine/Heuristic.ets', 'Heuristic.ts'],
  ['entry/src/main/ets/engine/RulePack.ets', 'RulePack.ts'],
  ['entry/src/main/ets/feature/exam/ExamState.ets', 'ExamState.ts'],
  ['entry/src/main/ets/record/Writer.ets', 'Writer.ts'],
  ['entry/src/main/ets/record/AuditLog.ets', 'AuditLog.ts'],
  ['entry/src/main/ets/record/TrustList.ets', 'TrustList.ts'],
  ['entry/src/main/ets/engine/AppJudge.ets', 'AppJudge.ts'],
  ['entry/src/main/ets/engine/QueryKey.ets', 'QueryKey.ts'],
  [ACTIONS, 'PermissionActions.ts'],
  ['entry/src/test/PermissionActions.test.ets', 'PermissionActions.test.ts']
]

const stubs = {
  'hilog-sdk.mjs': `export const hilog = { info() {}, warn() {}, error() {} };\n`,
  'fs-sdk.mjs': `export default {
  openSync() { throw new Error('fs is replaced by MemoryFiles in tests'); },
  listFileSync() { throw new Error('fs is replaced by FakeOwn in tests'); },
  OpenMode: { READ_ONLY: 0, CREATE: 0, READ_WRITE: 0, TRUNC: 0 }
};\n`
}

function prepare(text) {
  return text.replace(/\r\n/g, '\n')
    .replace(/^import type [^;]*?from '[^']+';?\n?/gms, '')
    .replace(/from '(@[^']+)'/g, (original, module) => {
      if (module === '@kit.PerformanceAnalysisKit') return "from './hilog-sdk.mjs'"
      if (module === '@ohos.file.fs') return "from './fs-sdk.mjs'"
      return original
    })
    .replace(/from '(\.{1,2}\/[^']+)'/g, (original, path) =>
      path.endsWith('.mjs') ? original : `from './${path.split('/').at(-1)}.ts'`)
}

const dir = mkdtempSync(join(tmpdir(), 'permission-actions-'))
try {
  for (const [name, text] of Object.entries(stubs)) {
    writeFileSync(join(dir, name), text)
  }
  for (const [from, to] of files) {
    writeFileSync(join(dir, to), prepare(readFileSync(resolve(root, from), 'utf8')))
  }
  writeFileSync(join(dir, 'main.ts'),
    "import { runPermissionActionsChecks } from './PermissionActions.test.ts';\nawait runPermissionActionsChecks();\nprocess.stdout.write('PermissionActions checks passed\\n');\n")
  const result = spawnSync(process.execPath, ['--experimental-strip-types', join(dir, 'main.ts')], {
    encoding: 'utf8'
  })
  process.stdout.write(result.stdout || '')
  process.stderr.write(result.stderr || '')
  if (result.status !== 0) {
    process.exitCode = result.status === null ? 1 : result.status
  }
} finally {
  rmSync(dir, { recursive: true, force: true })
}
