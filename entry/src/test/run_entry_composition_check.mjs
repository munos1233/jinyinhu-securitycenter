import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../../..')
const entry = readFileSync(resolve(root, 'entry/src/main/ets/entryability/EntryAbility.ets'), 'utf8').replaceAll('\r\n', '\n')
const onCreate = entry.match(/  onCreate\([^]*?\n  \}/)?.[0]
const foreground = entry.match(/  onForeground\([^]*?\n  \}/)?.[0]
const prepare = entry.match(/  private prepareCenter\([^]*?\n  \}/)?.[0]
assert(onCreate && foreground && prepare)
assert(onCreate.indexOf('LiveStore.prepare()') < onCreate.indexOf('this.prepareCenter()'))
assert(prepare.indexOf('CenterStore.prepare(') < prepare.indexOf('gate.probe()'))
assert(prepare.indexOf('gate.probe()') < prepare.indexOf('RunnerRegistry.registerAll(set)'))
assert.match(foreground, /this\.gate\.invalidate\(\)/)
assert.match(foreground, /center\.gate\.generation/)
assert.doesNotMatch(prepare, /\.enqueue\(/)
assert.match(prepare, /getRawFileContentSync\('default_rules\.json'\)/)
assert.equal(readFileSync(resolve(root,'entry/src/main/resources/rawfile/default_rules.json'),'utf8'),
  readFileSync(resolve(root,'entry/src/main/ets/rules/default_rules.json'),'utf8'))
const dir = mkdtempSync(join(tmpdir(), 'entry-composition-'))
try {
  writeFileSync(join(dir, 'harness.ts'), `
const { CenterStore, SandboxFiles, ProbedGate, SdkGateProbes, GatedBundleCensus, SdkBundleSource,
 AccessPort, SdkAccessSource, CachePort, SdkCacheSource, FileGrants, PreferencesGrantStore, SdkGrantPersist,
 nowIso, FileOpen, FsFileView, ParamPosturePort, SdkParamReader, SdkEl5Query, ReputationClient,
 LocalCloudConfig, HttpCloudTransport, readCancel, AppJudge, CenterSources, ExamRunner, MalwareRunner,
 CleanRunner, DuplicateFinder, LargeFileFinder, PermissionRunner, AppRunner, ProtectRunner, RunnerSet,
 CheckedInstaller, CenterDispositionPorts, FsOwnCache, Disposition, CenterPermissionPorts, PermissionActions,
 JobRunner, JobQueue, SystemClock, AppStorage, RunnerRegistry, util, hilog, Quarantine, FsByteStore,
 HuksQuarantineCipher, QuarantineBridge, CenterQuarantineGrants, QueueRoots } = globalThis;
const randomQuarantineId = () => '00000000000000000000000000000000';
const DOMAIN=0x4a59,TAG='SecurityCenter';
export class Harness { context; gate=null; generation=0; constructor(context){this.context=context;}
${prepare.replace('  private prepareCenter', '  prepareCenter')}
${foreground}
}
`)
  writeFileSync(join(dir,'main.ts'), `
import assert from 'node:assert/strict';
const events=[], storage=new Map(); let registered;
class Blank { constructor(...args){} async run(){} }
for(const name of 'SandboxFiles SdkGateProbes GatedBundleCensus SdkBundleSource AccessPort SdkAccessSource CachePort SdkCacheSource FileGrants PreferencesGrantStore SdkGrantPersist FileOpen FsFileView ParamPosturePort SdkParamReader SdkEl5Query ReputationClient LocalCloudConfig HttpCloudTransport AppJudge CenterSources ExamRunner MalwareRunner CleanRunner DuplicateFinder LargeFileFinder PermissionRunner AppRunner ProtectRunner CheckedInstaller CenterDispositionPorts FsOwnCache CenterPermissionPorts PermissionActions JobRunner JobQueue SystemClock Quarantine FsByteStore HuksQuarantineCipher QuarantineBridge CenterQuarantineGrants QueueRoots'.split(' ')) globalThis[name]=Blank;
globalThis.Disposition=class extends Blank { bindPermissions(){events.push('bind');} };
globalThis.RunnerSet=class {};
globalThis.ProbedGate=class { probe(){events.push('probe');return Promise.resolve();} invalidate(){events.push('invalidate');} };
globalThis.CenterStore={prepare(files,read){events.push('prepare');assert.equal(read(),'rules');}};
globalThis.RunnerRegistry={registerAll(set){events.push('register');registered=set;}};
globalThis.AppStorage={setOrCreate(k,v){storage.set(k,v);}};
globalThis.util={TextDecoder:{create(){return {decodeWithStream(bytes){return 'rules';}};}}};
globalThis.nowIso=()=>'';globalThis.readCancel=()=>false;globalThis.hilog={info(){},error(){}};
const {Harness}=await import('./harness.ts');
const context={filesDir:'/files',cacheDir:'/cache',abilityInfo:{bundleName:'self'},
  resourceManager:{getRawFileContentSync(name){if(name==='default_rules.json')return new Uint8Array([1]);throw Error('missing');}}};
let h=new Harness(context);h.prepareCenter();
assert(events.indexOf('prepare')<events.indexOf('probe'));assert(events.indexOf('probe')<events.indexOf('register'));
for(const key of ['exam','malware','clean','duplicate','largeFile','permission','apps','protect']) assert.equal(typeof registered[key],'function');
for(const key of ['center.gate','center.queue','center.permission','center.disposition','center.files','center.quarantine']) assert(storage.has(key));
h.onForeground();assert(events.includes('invalidate'));assert.equal(storage.get('center.gate.generation'),1);
process.stdout.write('Entry composition checks passed\\n');
`)
  const run=spawnSync(process.execPath,['--experimental-strip-types',join(dir,'main.ts')],{encoding:'utf8'})
  process.stdout.write(run.stdout || ''); process.stderr.write(run.stderr || '')
  if(run.status!==0) process.exitCode=run.status===null?1:run.status
} finally { rmSync(dir,{recursive:true,force:true}) }
