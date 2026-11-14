import { readFileSync } from 'node:fs'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const root = resolve(here, '../../..')
const sample = JSON.parse(readFileSync(resolve(root, 'entry/src/main/ets/rules/default_rules.json'), 'utf8'))
if (sample.version !== '2026.11.12' || sample.files[0].sha256 !== '' ||
  sample.heuristics.length !== 3 || sample.heuristics[0].id !== 'sms-and-contacts' ||
  sample.heuristics[1].id !== 'sms-and-call' ||
  sample.heuristics[2].id !== 'background-location-and-camera' ||
  sample.bundles[0].bundleName !== 'com.example.risk' ||
  sample.officials[0].bundleName !== 'com.example.official') {
  process.stderr.write('default_rules.json 不是第 7 节样例\n')
  process.exit(1)
}

const files = [
  ['entry/src/main/ets/center/CenterTypes.ets', 'CenterTypes.ts'],
  ['entry/src/main/ets/center/CenterLimits.ets', 'CenterLimits.ts'],
  ['entry/src/main/ets/center/CenterError.ets', 'CenterError.ts'],
  ['entry/src/main/ets/center/Clock.ets', 'Clock.ts'],
  ['entry/src/main/ets/feature/exam/ExamState.ets', 'ExamState.ts'],
  ['entry/src/main/ets/engine/Decide.ets', 'Decide.ts'],
  ['entry/src/main/ets/engine/RulePack.ets', 'RulePack.ts'],
  ['entry/src/main/ets/record/Writer.ets', 'Writer.ts'],
  ['entry/src/main/ets/record/CenterStore.ets', 'CenterStore.ts'],
  ['entry/src/test/RulePack.test.ets', 'RulePack.test.ts']
]

function prep(source) {
  return source
    .replace(/import fs from '@ohos\.file\.fs';\n/,
      "const fs = { openSync() { throw new Error('unused'); }, statSync() { return { size: 0 }; }, readSync() {}, writeSync() {}, closeSync() {}, renameSync() {}, unlinkSync() {}, mkdirSync() {} };\n")
    .replace(/import \{ hilog \} from '@kit\.PerformanceAnalysisKit';\n/g,
      "const hilog = { error(domain, tag, message) { const bag = globalThis; if (!Array.isArray(bag.__centerHilog)) { bag.__centerHilog = []; } bag.__centerHilog.push(String(message)); }, info() {}, warn() {} };\n")
    .replaceAll("from '../center/CenterLimits'", "from './CenterLimits.ts'")
    .replaceAll("from '../center/Clock'", "from './Clock.ts'")
    .replaceAll("from '../center/CenterTypes'", "from './CenterTypes.ts'")
    .replaceAll("from '../../center/CenterTypes'", "from './CenterTypes.ts'")
    .replaceAll("from '../feature/exam/ExamState'", "from './ExamState.ts'")
    .replaceAll("from './Decide'", "from './Decide.ts'")
    .replaceAll("from '../engine/RulePack'", "from './RulePack.ts'")
    .replaceAll("from '../main/ets/engine/RulePack'", "from './RulePack.ts'")
    .replaceAll("from '../main/ets/record/CenterStore'", "from './CenterStore.ts'")
    .replaceAll("from '../main/ets/record/Writer'", "from './Writer.ts'")
    .replace(/from '\.\/Decide'(?!\.ts)/g, "from './Decide.ts'")
    .replace(/from '\.\/Writer'(?!\.ts)/g, "from './Writer.ts'")
}

const dir = mkdtempSync(join(tmpdir(), 'rule-pack-'))
try {
  for (const [from, to] of files) {
    writeFileSync(join(dir, to), prep(readFileSync(resolve(root, from), 'utf8')))
  }
  writeFileSync(join(dir, 'main.ts'),
    "import { runRulePackChecks } from './RulePack.test.ts';\nrunRulePackChecks();\n")
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
