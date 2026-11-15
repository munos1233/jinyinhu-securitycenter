import { spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../../..')
const added = [
  'entry/src/main/ets/task/JobQueue.ets',
  'entry/src/main/ets/task/CancelFlag.ets',
  'entry/src/main/ets/task/JobRunner.ets',
  'entry/src/main/ets/task/Contexts.ets',
  'entry/src/main/ets/task/RunnerRegistry.ets',
  'entry/src/main/ets/engine/Hash.ets',
  'entry/src/main/ets/engine/HashWorker.ets'
]
const files = [
  ['entry/src/main/ets/center/CenterTypes.ets', 'CenterTypes.ts'],
  ['entry/src/main/ets/center/CenterLimits.ets', 'CenterLimits.ts'],
  ['entry/src/main/ets/center/CenterError.ets', 'CenterError.ts'],
  ['entry/src/main/ets/center/Clock.ets', 'Clock.ts'],
  ['entry/src/main/ets/center/SensitiveCatalog.ets', 'SensitiveCatalog.ts'],
  ['entry/src/main/ets/feature/exam/ExamState.ets', 'ExamState.ts'],
  ['entry/src/main/ets/record/Writer.ets', 'Writer.ts'],
  ['entry/src/main/ets/engine/Hash.ets', 'Hash.ts'],
  ['entry/src/main/ets/engine/HashWorker.ets', 'HashWorker.ts'],
  ['entry/src/main/ets/task/CancelFlag.ets', 'CancelFlag.ts'],
  ['entry/src/main/ets/task/Contexts.ets', 'Contexts.ts'],
  ['entry/src/main/ets/task/RunnerRegistry.ets', 'RunnerRegistry.ts'],
  ['entry/src/main/ets/task/JobRunner.ets', 'JobRunner.ts'],
  ['entry/src/main/ets/task/JobQueue.ets', 'JobQueue.ts'],
  ['entry/src/test/TaskQueue.test.ets', 'TaskQueue.test.ts']
]

const problems = []
const read = (path) => readFileSync(resolve(root, path), 'utf8').replace(/\r\n/g, '\n')
const code = (text) => text.replace(/\/\*[\s\S]*?\*\/|\/\/.*$/gm, '')

for (const path of added) {
  const source = read(path)
  const body = code(source)
  if (source.includes('const DOMAIN') || source.includes('hilog')) {
    if (!source.includes('const DOMAIN: number = 0x4A59') || !source.includes("const TAG: string = 'Center'")) {
      problems.push(`${path} 的 hilog 域必须是 0x4A59，标签 Center`)
    }
  }
  if (body.includes('settleStoppedExam')) {
    problems.push(`${path} 经 Writer.settleExam 收口，不直接调用 settleStoppedExam`)
  }
  for (const banned of ['已安全', '云查杀已开启', '已防护', '已拦截', '人工智能引擎已防护', '正在扫描']) {
    if (source.includes(banned)) {
      problems.push(`${path} 出现了「${banned}」`)
    }
  }
  if (path.includes('/task/') && /from '\.\.\/(feature|pages)\//.test(source)) {
    problems.push(`${path} task 不 import feature 或页面`)
  }
  if (path.includes('/engine/') && /from '(\.\.\/(pages|task|system|cloud|feature)\/|@ohos\.net|@kit\.NetworkKit)/.test(source)) {
    problems.push(`${path} engine 不 import 页面、任务、系统端口和网络`)
  }
  if (body.includes('AppStorage') && !path.endsWith('JobQueue.ets')) {
    problems.push(`${path} 只有 JobQueue 在 UI 线程写 AppStorage`)
  }
}

const queue = code(read('entry/src/main/ets/task/JobQueue.ets'))
if ((queue.match(/AppStorage\./g) || []).length !== 1 || !queue.includes('AppStorage.setOrCreate<JobProgress>(key, progress)')) {
  problems.push('JobQueue 只在 AppStorageSink 里写 AppStorage')
}
if (!queue.includes("'center.job.light'") || !queue.includes("'center.job.heavy'")) {
  problems.push('进度键是 center.job.light 与 center.job.heavy')
}
if (/index\.json|Writer\.files|seq = [^\n]*nowIso/.test(queue) || !queue.includes('record.seq = Writer.nextSeq(rows)')) {
  problems.push('车道不直接改索引，seq 经 Writer 分配，不读时钟')
}

if ((queue.match(/Writer\.settleExam\(/g) || []).length !== 1 ||
  !/if \(end\.state === 'cancelled'\) \{\s*Writer\.settleExam\(job\.record\)/.test(queue)) {
  problems.push('JobQueue 只在作业记 cancelled 后调用一次 Writer.settleExam')
}
const runnerSource = code(read('entry/src/main/ets/task/JobRunner.ets'))
if ((runnerSource.match(/Writer\.settleExam\(/g) || []).length !== 1 ||
  !/if \(end\.state === 'failed'\) \{\s*Writer\.settleExam\(live\)/.test(runnerSource) ||
  !runnerSource.includes('isWorkerDown(err)')) {
  problems.push('JobRunner 只在 Runner 抛错或 Worker 起不来记 failed 时调用一次 Writer.settleExam')
}
const writerSource = code(read('entry/src/main/ets/record/Writer.ets'))
if (!/row\.summary = INTERRUPTED\n\s*stopped\.push\(row\)/.test(writerSource) ||
  !/Writer\.replaceNow\(INDEX_PATH, JSON\.stringify\(Writer\.plainIndex\(trimmed\)\)\)\n\s*for \(let i = 0; i < stopped\.length; i\+\+\) \{\n\s*Writer\.settleExamNow\(stopped\[i\]\)/.test(writerSource)) {
  problems.push('Writer.recover 在作业写成 interrupted 之后再收口体检')
}
if ((writerSource.match(/settleStoppedExam\(/g) || []).length !== 1) {
  problems.push('Writer 只在 settleExamNow 里调用 settleStoppedExam')
}

const contexts = read('entry/src/main/ets/task/Contexts.ets')
const expected = {
  ExamContext: 'access,base,cache,census,files,judge,open,posture',
  MalwareContext: 'base,census,files,grants,judge,open',
  CleanContext: 'base,cache,census,files,open',
  PermissionContext: 'access,base,census',
  AppsContext: 'base,census,grants,judge',
  ProtectContext: 'base,posture',
  FileToolContext: 'base,files,open',
  JobBase: 'cancel,clock,job,report,request'
}
const declared = {}
for (const m of code(contexts).matchAll(/export interface (\w+) \{([^}]*)\}/g)) {
  declared[m[1]] = [...m[2].matchAll(/^\s*(\w+):/gm)].map((f) => f[1]).sort().join(',')
}
for (const [name, fields] of Object.entries(expected)) {
  if (declared[name] !== fields) {
    problems.push(`Contexts ${name} 的字段应为 ${fields}，实际 ${declared[name]}`)
  }
  if (name !== 'JobBase' && !new RegExp(`interface ${name} \\{\\s*base: JobBase\\n`).test(contexts)) {
    problems.push(`${name} 第一项是 base: JobBase`)
  }
}
const contextNames = Object.keys(declared).filter((n) => n.endsWith('Context'))
if (contextNames.length !== 7) {
  problems.push(`上下文必须正好七种，实际 ${contextNames.join(',')}`)
}

const flag = code(read('entry/src/main/ets/task/CancelFlag.ets'))
if (!flag.includes('export const CANCEL_BYTES: number = 4') || !flag.includes('new SharedArrayBuffer(CANCEL_BYTES)')) {
  problems.push('CancelFlag 是 4 字节 SharedArrayBuffer')
}

const hash = code(read('entry/src/main/ets/engine/Hash.ets'))
if (!hash.includes('new ArrayBuffer(hashChunk)') || /statSync|readTextSync/.test(hash)) {
  problems.push('Hash 按 hashChunk 分块读取，不整文件读入')
}
const worker = code(read('entry/src/main/ets/engine/HashWorker.ets'))
if (!/@Concurrent\nfunction hashInWorker\(fd: number, cancel: SharedArrayBuffer\): HashResult \{\n\s*return hashFd\(/.test(worker)) {
  problems.push('哈希只在 @Concurrent 函数里做，收到的是 SharedArrayBuffer')
}
if ((worker.match(/hashFd\(/g) || []).length !== 1 || (worker.match(/new CryptoDigest\(\)/g) || []).length !== 1) {
  problems.push('HashWorker 不得在 UI 线程退回整文件哈希')
}
if (!worker.includes('new taskpool.Task(hashInWorker, fd, cancel)')) {
  problems.push('传给 TaskPool 的是取消标志的缓冲区本身')
}

if (problems.length > 0) {
  process.stderr.write(problems.join('\n') + '\n')
  process.exit(1)
}

const mocks = {
  'fs': `export default {
  readSync(fd, buffer, options) {
    const bag = globalThis.__fs;
    bag.reads++;
    if (bag.onRead) bag.onRead(bag.reads);
    if (bag.failRead) { const e = new Error('eio'); e.code = 13900005; throw e; }
    const data = bag.files.get(fd);
    const start = options.offset;
    const end = Math.min(data.length, start + options.length);
    if (end <= start) return 0;
    new Uint8Array(buffer).set(data.subarray(start, end));
    return end - start;
  },
  openSync() { throw new Error('unused'); }, statSync() { return { size: 0 }; }, writeSync() {}, closeSync() {},
  renameSync() {}, unlinkSync() {}, mkdirSync() {}, OpenMode: {}
};`,
  'crypto': `import { createHash } from 'node:crypto';
export default {
  createMd(alg) {
    if (alg !== 'SHA256') throw new Error('alg ' + alg);
    const h = createHash('sha256');
    return {
      updateSync(blob) { globalThis.__fs.updates.push(blob.data.length); h.update(blob.data); },
      digestSync() { return { data: new Uint8Array(h.digest()) }; }
    };
  }
};`,
  'arkts': `export const taskpool = {
  Task: class {
    constructor(fn, ...args) {
      const bag = globalThis.__pool;
      if (bag.failCreate) throw new Error('taskpool create failed');
      this.fn = fn; this.args = args; bag.tasks.push(this);
    }
  },
  execute(task) {
    const bag = globalThis.__pool;
    if (bag.failExecute) return Promise.reject(new Error('taskpool execute failed'));
    const args = structuredClone(task.args);
    return new Promise((resolve, reject) => setTimeout(() => {
      try { resolve(structuredClone(task.fn(...args))); } catch (e) { reject(e); }
    }, 0));
  }
};`
}
const modules = {
  '@ohos.file.fs': 'fs',
  '@ohos.security.cryptoFramework': 'crypto',
  '@kit.ArkTS': 'arkts'
}

function prepare(text) {
  return text.replace(/\r\n/g, '\n')
    .replace(/^import type [^;]*?from '[^']+'\n?/gms, '')
    .replace(/^@Concurrent\n/gm, '')
    .replace(/from '(@[^']+)'/g, (original, name) => {
      if (name === '@kit.PerformanceAnalysisKit') return "from './hilog-sdk.mjs'"
      return modules[name] ? `from './${modules[name]}-sdk.mjs'` : original
    })
    .replace(/from '(\.{1,2}\/[^']+)'/g, (original, path) => {
      if (path.endsWith('.mjs')) return original
      return `from './${path.split('/').at(-1)}.ts'`
    })
}

const dir = mkdtempSync(join(tmpdir(), 'task-queue-'))
try {
  for (const [name, body] of Object.entries(mocks)) {
    writeFileSync(join(dir, `${name}-sdk.mjs`), body + '\n')
  }
  writeFileSync(join(dir, 'hilog-sdk.mjs'), `export const hilog = {
  info(d, t, ...m) { (globalThis.__hilog ??= []).push(m.join(' ')); },
  warn(d, t, ...m) { (globalThis.__hilog ??= []).push(m.join(' ')); },
  error(d, t, ...m) { (globalThis.__hilog ??= []).push(m.join(' ')); }
};
`)
  for (const [from, to] of files) {
    writeFileSync(join(dir, to), prepare(read(from)))
  }
  writeFileSync(join(dir, 'main.ts'), `
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { runTaskQueueChecks } from './TaskQueue.test.ts';
import { CancelFlag } from './CancelFlag.ts';
import { HashWorker, isWorkerDown, WORKER_DOWN } from './HashWorker.ts';

await runTaskQueueChecks();

const MB = 1024 * 1024;
function fresh(size) {
  const data = randomBytes(size);
  globalThis.__fs = { files: new Map([[9, data]]), reads: 0, updates: [], onRead: null, failRead: false };
  globalThis.__pool = { tasks: [], failCreate: false, failExecute: false };
  return data;
}

let data = fresh(3 * MB + 123);
let flag = new CancelFlag();
let result = await new HashWorker().hash(9, flag.buffer);
assert.equal(result.sha256, createHash('sha256').update(data).digest('hex'), 'TaskPool 里算出的 SHA-256 正确');
assert.deepEqual(globalThis.__fs.updates, [MB, MB, MB, 123], '按 hashChunk 更新');
assert.equal(globalThis.__pool.tasks.length, 1);
assert.equal(globalThis.__pool.tasks[0].args[1], flag.buffer, '传给 TaskPool 的是 CancelFlag 的缓冲区本身');
assert.ok(globalThis.__pool.tasks[0].args[1] instanceof SharedArrayBuffer);

fresh(40 * MB);
flag = new CancelFlag();
globalThis.__fs.onRead = (reads) => { if (reads === 2) flag.cancel(); };
result = await new HashWorker().hash(9, flag.buffer);
assert.ok(result.cancelled, 'UI 线程置取消后 Worker 停止');
assert.equal(result.sha256, '');
assert.equal(globalThis.__fs.reads, 2, 'Worker 在下一个分块之前停止，不把整个文件哈希完');

fresh(4 * MB);
const copy = new CancelFlag();
const plain = new ArrayBuffer(4);
globalThis.__fs.onRead = (reads) => { if (reads === 1) { copy.cancel(); new Int32Array(plain)[0] = 1; } };
result = await new HashWorker().hash(9, plain);
assert.ok(!result.cancelled && globalThis.__fs.reads === 5, '对照：复制过去的普通缓冲区看不到取消');

fresh(MB);
globalThis.__pool.failCreate = true;
await assert.rejects(new HashWorker().hash(9, new CancelFlag().buffer),
  (err) => err.code === 'io' && err.raw.startsWith(WORKER_DOWN) && isWorkerDown(err), 'Task 建不起来时抛 io');
assert.equal(globalThis.__fs.reads, 0, 'Worker 起不来时不在 UI 线程哈希');

fresh(MB);
globalThis.__pool.failExecute = true;
await assert.rejects(new HashWorker().hash(9, new CancelFlag().buffer),
  (err) => err.code === 'io' && isWorkerDown(err), 'TaskPool 执行失败时抛 io');
assert.equal(globalThis.__fs.reads, 0, 'Worker 起不来时不在 UI 线程哈希');

fresh(2 * MB);
globalThis.__fs.failRead = true;
await assert.rejects(new HashWorker().hash(9, new CancelFlag().buffer),
  (err) => err.code === 'io' && err.raw === 'read:13900005' && !isWorkerDown(err), '单个文件读失败只让该条失败');

process.stdout.write('JobQueue, contexts, cancel and hash worker checks passed\\n');
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
