import { spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const root = resolve(here, '../../..')
const files = [
  ['entry/src/main/ets/center/CenterTypes.ets', 'CenterTypes.ts'],
  ['entry/src/main/ets/center/CenterError.ets', 'CenterError.ts'],
  ['entry/src/main/ets/center/CenterLimits.ets', 'CenterLimits.ts'],
  ['entry/src/main/ets/center/Clock.ets', 'Clock.ts'],
  ['entry/src/main/ets/center/SensitiveCatalog.ets', 'SensitiveCatalog.ts'],
  ['entry/src/main/ets/center/CleanMath.ets', 'CleanMath.ts'],
  ['entry/src/main/ets/engine/QueryKey.ets', 'QueryKey.ts'],
  ['entry/src/test/CenterCore.test.ets', 'CenterCore.test.ts']
]

function prep(source) {
  return source
    .replaceAll("from './CenterTypes'", "from './CenterTypes.ts'")
    .replaceAll("from '../center/CenterTypes'", "from './CenterTypes.ts'")
    .replaceAll("from '../main/ets/center/CenterError'", "from './CenterError.ts'")
    .replaceAll("from '../main/ets/center/CenterLimits'", "from './CenterLimits.ts'")
    .replaceAll("from '../main/ets/center/Clock'", "from './Clock.ts'")
    .replaceAll("from '../main/ets/center/CleanMath'", "from './CleanMath.ts'")
    .replaceAll("from '../main/ets/center/SensitiveCatalog'", "from './SensitiveCatalog.ts'")
    .replaceAll("from '../main/ets/center/CenterTypes'", "from './CenterTypes.ts'")
    .replaceAll("from '../main/ets/engine/QueryKey'", "from './QueryKey.ts'")
}

const dir = mkdtempSync(join(tmpdir(), 'center-core-'))
try {
  for (const [from, to] of files) {
    writeFileSync(join(dir, to), prep(readFileSync(resolve(root, from), 'utf8')))
  }
  writeFileSync(join(dir, 'main.ts'), "import { runCenterCoreChecks } from './CenterCore.test.ts';\nrunCenterCoreChecks();\n")
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
