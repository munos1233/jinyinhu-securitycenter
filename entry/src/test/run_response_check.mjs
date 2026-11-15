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
  ['entry/src/main/ets/cloud/ResponseCheck.ets', 'ResponseCheck.ts'],
  ['entry/src/test/ResponseCheck.test.ets', 'ResponseCheck.test.ts']
]

function prepare(source) {
  return source.replaceAll('\r\n', '\n')
    .replaceAll("from '../center/CenterTypes'", "from './CenterTypes.ts'")
    .replaceAll("from '../center/CenterLimits'", "from './CenterLimits.ts'")
    .replaceAll("from './CenterTypes'", "from './CenterTypes.ts'")
    .replaceAll("from '../main/ets/center/CenterTypes'", "from './CenterTypes.ts'")
    .replaceAll("from '../main/ets/center/CenterLimits'", "from './CenterLimits.ts'")
    .replaceAll("from '../main/ets/cloud/ResponseCheck'", "from './ResponseCheck.ts'")
}

const dir = mkdtempSync(join(tmpdir(), 'response-check-'))
try {
  for (const [from, to] of files) {
    writeFileSync(join(dir, to), prepare(readFileSync(resolve(root, from), 'utf8')))
  }
  writeFileSync(join(dir, 'main.ts'), `
import { generateKeyPairSync, sign, verify } from 'node:crypto';
import { runResponseCheckChecks } from './ResponseCheck.test.ts';
const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
runResponseCheckChecks(
  (text: string) => sign('sha256', Buffer.from(text, 'utf8'), pair.privateKey).toString('base64'),
  (message: Uint8Array, signature: string) => verify('sha256', message, pair.publicKey, Buffer.from(signature, 'base64'))
);
process.stdout.write('ResponseCheck checks passed with P-256 ECDSA-SHA256 signatures\\n');
`)
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
