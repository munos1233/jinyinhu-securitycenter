import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../../..')
const read = name => readFileSync(resolve(root, 'entry/src/main/ets/pages', name + '.ets'), 'utf8').replaceAll('\r\n', '\n')
const apps = read('AppsView'), protect = read('ProtectView')
assert.doesNotMatch(apps, /bundleManager|@ohos\.file\.fs|立即处理/)
assert.match(apps, /disposition\.uninstall\(this\.viewing, bundleName\)/)
assert.match(apps, /scope: 'quick' = 'quick'/)
assert.match(apps, /focus: string = ''/)
assert.match(protect, /系统防护自检/)
assert.doesNotMatch(protect, /disposition|requestPermissionsFromUser|PosturePort/)
for (const name of ['P1', 'P2', 'P3']) assert.match(protect, new RegExp(`this\\.onOpen\\('${name}', ''\\)`))
const methods = (src, names) => names.map(name => {
  const match = src.match(new RegExp(`  (?:private )?(?:async )?${name}\\([^]*?\\n  \\}`))
  assert(match, `missing ${name}`)
  return match[0].replace('  private ', '  ')
}).join('\n')
const dir = mkdtempSync(join(tmpdir(), 'apps-pages-'))
try {
  writeFileSync(join(dir, 'harness.ts'), `
const LIST_PERMISSION = 'ohos.permission.GET_INSTALLED_BUNDLE_LIST';
let declined = false;
class AppsRequest { kind='apps'; scope='quick'; uris=[]; focus=''; }
const QUEUE_KEY='center.queue', DISPOSITION_KEY='center.disposition';
const abilityAccessCtrl = globalThis.abilityAccessCtrl;
const AppStorage = globalThis.AppStorage;
const Writer = globalThis.Writer, ResultStore = globalThis.ResultStore;
const getContext = () => ({});
export class Harness { rows=[]; viewing=''; message=''; working=false;
${methods(apps, ['read', 'reload', 'uninstall'])}
}
`)
  writeFileSync(join(dir, 'main.ts'), `
import assert from 'node:assert/strict';
const storage=new Map(); globalThis.AppStorage={get:(k)=>storage.get(k)};
let calls=0, invalidated=0, probed=0, request;
globalThis.abilityAccessCtrl={createAtManager:()=>({requestPermissionsFromUser:async()=>{calls++;return {authResults:[-1]};}})};
globalThis.Writer={loadIndex:()=>[]}; globalThis.ResultStore={read:()=>null};
const {Harness}=await import('./harness.ts');
const gate={bundles:()=>({status:'unsupported'}),invalidate(){invalidated++;},async probe(){probed++;}};
storage.set('center.gate',gate); let h=new Harness(); await h.read(); await h.read();
assert.equal(calls,1); assert.equal(h.message,'无法获取应用列表'); assert.equal(h.working,false);
gate.bundles=()=>({status:'ready'}); storage.set('center.queue',{enqueue:r=>(request=r,'job1')});
await h.read(); assert.deepEqual({...request},{kind:'apps',scope:'quick',uris:[],focus:''});
assert.equal(h.viewing,'job1');
let args; storage.set('center.disposition',{uninstall:async (...x)=>(args=x,{done:false,message:'卸载失败，返回码 42'})});
await h.uninstall('test.app'); assert.deepEqual(args,['job1','test.app']); assert.equal(h.message,'卸载失败，返回码 42');
process.stdout.write('Apps and protect page checks passed\\n');
`)
  const run = spawnSync(process.execPath, ['--experimental-strip-types', join(dir, 'main.ts')], { encoding: 'utf8' })
  process.stdout.write(run.stdout || '')
  process.stderr.write(run.stderr || '')
  if (run.status !== 0) process.exitCode = run.status === null ? 1 : run.status
} finally { rmSync(dir, { recursive: true, force: true }) }
