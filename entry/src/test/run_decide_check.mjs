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
  ['entry/src/main/ets/engine/RulePack.ets', 'RulePack.ts'],
  ['entry/src/main/ets/engine/Decide.ets', 'Decide.ts'],
  ['entry/src/test/CanonicalCert.test.ets', 'CanonicalCert.test.ts'],
  ['entry/src/test/DecideHelpers.test.ets', 'DecideHelpers.test.ts'],
  ['entry/src/test/Decide.test.ets', 'Decide.test.ts']
]

const dir = mkdtempSync(join(tmpdir(), 'decide-'))
try {
  for (const [from, to] of files) {
    writeFileSync(join(dir, to), prepareDecisionSource(readFileSync(resolve(root, from), 'utf8')))
  }
  writeFileSync(join(dir, 'main.ts'), [
    "import { runCanonicalCertChecks } from './CanonicalCert.test.ts'",
    "import { runDecideHelpersChecks } from './DecideHelpers.test.ts'",
    "import { runDecideChecks } from './Decide.test.ts'",
    'runCanonicalCertChecks()',
    'runDecideHelpersChecks()',
    'runDecideChecks()'
  ].join('\n'))
  const run = spawnSync(process.execPath, ['--experimental-strip-types', join(dir, 'main.ts')], {
    encoding: 'utf8'
  })
  process.stdout.write(run.stdout || '')
  process.stderr.write(run.stderr || '')
  if (run.status !== 0) {
    process.exitCode = run.status ?? 1
  }
} finally {
  rmSync(dir, { recursive: true, force: true })
}
