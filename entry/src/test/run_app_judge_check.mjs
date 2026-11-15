import { spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { decisionFiles, prepareDecisionSource } from './decision_test_support.mjs'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../../..')
const files = [
  ...decisionFiles,
  ['entry/src/main/ets/center/CenterTypes.ets', 'CenterTypes.ts'],
  ['entry/src/main/ets/center/CenterLimits.ets', 'CenterLimits.ts'],
  ['entry/src/main/ets/center/Anomaly.ets', 'Anomaly.ts'],
  ['entry/src/main/ets/center/SensitiveCatalog.ets', 'SensitiveCatalog.ts'],
  ['entry/src/main/ets/engine/RulePack.ets', 'RulePack.ts'],
  ['entry/src/main/ets/engine/Decide.ets', 'Decide.ts'],
  ['entry/src/main/ets/engine/QueryKey.ets', 'QueryKey.ts'],
  ['entry/src/main/ets/feature/exam/ExamState.ets', 'ExamState.ts'],
  ['entry/src/main/ets/engine/AppJudge.ets', 'AppJudge.ts'],
  ['entry/src/test/AppJudge.test.ets', 'AppJudge.test.ts']
]

function prepare(source, name) {
  let result = prepareDecisionSource(source).replace(/from '(\.{1,2}\/[^']+)'/g, (_, path) => {
    const name = path.split('/').at(-1)
    return `from './${name.endsWith('.ts') ? name : `${name}.ts`}'`
  })
  if (name === 'Decide.ts') {
    result = result.replace("  if (cloud.state === 'unchecked') {",
      "  globalThis.__centerDecideCalls++;\n  if (cloud.state === 'unchecked') {")
  }
  if (name === 'ExamState.ts') {
    result = result.replace('  let status = new AppsItemStatusValue()',
      '  globalThis.__centerAppsStatusCalls++;\n  let status = new AppsItemStatusValue()')
      .replace('  let noCloud = hasSentence(detail, NO_CLOUD)',
        '  globalThis.__centerAppendCalls++;\n  let noCloud = hasSentence(detail, NO_CLOUD)')
      .replace('  let counting: CheckItem[] = []',
        '  globalThis.__centerStateCalls++;\n  let counting: CheckItem[] = []')
  }
  return result
}

const dir = mkdtempSync(join(tmpdir(), 'app-judge-'))
try {
  for (const [from, to] of files) {
    writeFileSync(join(dir, to), prepare(readFileSync(resolve(root, from), 'utf8'), to))
  }
  writeFileSync(join(dir, 'main.ts'),
    "import { runAppJudgeChecks } from './AppJudge.test.ts';\nawait runAppJudgeChecks();\nprocess.stdout.write('AppJudge and rejudgeGranted checks passed\\n');\n")
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
