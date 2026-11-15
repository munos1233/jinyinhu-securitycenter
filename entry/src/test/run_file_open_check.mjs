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
      "const fs = { openSync() { throw new Error('unused'); }, lstatSync(path) { if (globalThis.__realFileStat) { return globalThis.__realFileStat(path); } if (path === '/storage/users/link') { return { isSymbolicLink() { return true; } }; } if (String(path).startsWith('/storage/users/link/')) { return { isSymbolicLink() { return false; } }; } throw new Error('missing'); }, closeSync() {}, OpenMode: { READ_ONLY: 0 } };\n")
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
    `import { runFileOpenChecks } from './FileOpen.test.ts';
import { FileOpen, FsFileView } from './FileOpen.ts';
import { CenterError } from './CenterError.ts';
import { lstatSync, mkdirSync, symlinkSync } from 'node:fs';
import { join } from 'node:path';
runFileOpenChecks();
const directory = ${JSON.stringify(join(dir, 'filesystem'))};
mkdirSync(join(directory, 'storage/users'), { recursive: true });
mkdirSync(join(directory, 'system/private/subdir'), { recursive: true });
symlinkSync(join(directory, 'system/private'), join(directory, 'storage/users/link'),
  process.platform === 'win32' ? 'junction' : 'dir');
globalThis.__realFileStat = (path: string) => lstatSync(join(directory, path.substring(1)));
const opener = new FileOpen(new FsFileView());
const escaped = opener.accept('/storage/users/link/subdir/sample.hap', '/storage/users/link/subdir');
if (!(escaped instanceof CenterError) || escaped.code !== 'rejected-system-path') {
  throw new Error('真实文件系统中的祖先链接绕过了授权根');
}
if (opener.accept('/storage/users/new.hap', '/storage/users') !== '/storage/users/new.hap') {
  throw new Error('普通授权目录中的恢复目标被错误拒绝');
}
`)
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
