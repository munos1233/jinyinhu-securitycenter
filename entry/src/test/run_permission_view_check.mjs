import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../../..')
const read = path => readFileSync(resolve(root, path), 'utf8').replaceAll('\r\n', '\n')
const page = read('entry/src/main/ets/pages/PermissionView.ets')
assert.doesNotMatch(page, /@ohos\.file\.fs|bundleManager|requestPermissionsFromUser|revokeUserGrantedPermission/)
assert.match(page, /@StorageLink\('center\.gate\.generation'\)/)
assert.match(page, /disposition\.closePermission\(this\.viewing, line\.bundleName, line\.permission, this\.params\)/)
assert.doesNotMatch(page, /actions\.revoke\(/)
assert.match(page, /this\.currentRevision\(revision\)/)
assert.match(page, /Text\('最近 7 天没有使用记录'\)/)
assert.match(page, /if \(this\.usesAvailable\)/)
assert.match(page, /this\.grantsAvailable && count\.known/)
assert.match(page, /const DOMAIN: number = 0x4A59/)
assert.match(page, /const TAG: string = 'Center'/)

const prefix = page.slice(0, page.indexOf('@Component'))
const helpers = page.slice(page.indexOf('// Model helpers'))
const names = ['aboutToAppear', 'aboutToDisappear', 'onGate', 'onLight', 'start', 'load', 'loadCurrent', 'currentRevision', 'confirmClose', 'closePermission']
const methods = names.map(name => {
  const pattern = new RegExp(`  (?:private )?(?:async )?${name}\\([^]*?\\n  \\}`)
  const match = page.match(pattern)
  assert(match, `missing component method ${name}`)
  return match[0].replace('  private ', '  ')
})
const prepare = text => text.replaceAll('\r\n', '\n')
  .replaceAll("from '@kit.PerformanceAnalysisKit'", "from './hilog.mjs'")
  .replace(/from '(\.{1,2}\/[^']+)'/g, (original, path) => path.endsWith('.mjs')
    ? original : `from './${path.split('/').at(-1)}.ts'`)
const directory = mkdtempSync(join(tmpdir(), 'permission-view-'))
try {
  for (const file of ['center/CenterTypes', 'center/CenterLimits', 'center/Anomaly', 'center/SensitiveCatalog',
    'engine/RulePack', 'engine/Decide', 'engine/Heuristic', 'engine/LocalRuleEngine', 'engine/Lookalike', 'common/Theme']) {
    writeFileSync(join(directory, file.split('/').at(-1) + '.ts'), prepare(read('entry/src/main/ets/' + file + '.ets')))
  }
  writeFileSync(join(directory, 'hilog.mjs'), 'export const hilog = {info(){},warn(){},error(){}};')
  writeFileSync(join(directory, 'Writer.ts'), `export const state = { index: [] }; export const Writer = { loadIndex() { return state.index; } };`)
  writeFileSync(join(directory, 'ResultStore.ts'), `export const files = new Map(); export const ResultStore = { read(id) { return files.get(id) ?? null; } };`)
  writeFileSync(join(directory, 'HomeView.ts'), `export const QUEUE_KEY = 'center.queue';`)
  writeFileSync(join(directory, 'MalwareView.ts'), `export const DISPOSITION_KEY = 'center.disposition';`)
  writeFileSync(join(directory, 'PermissionView.ts'), prepare(prefix + '\nexport class Harness {\n' + `
  params = ''; light = { kind: 'permission', jobId: '', state: 'done' };
  viewing = ''; counts = []; blocks = []; selectedGroup = '相机'; banner = ''; missing = ''; notice = '';
  refreshing = false; working = false; canRevoke = false; grantsAvailable = false;
  usesAvailable = false; uses = []; alive = true; revision = 0; reconciled = ''; awaitingRequest = false; initialBundleRead = false; appeared = false;
` + methods.join('\n') + '\n}\n' + helpers))
  writeFileSync(join(directory, 'main.ts'), `
import assert from 'node:assert/strict';
import { Harness, permissionRequest, permissionStored, permissionCounts, permissionSelection, permissionLines,
  permissionBlocks, permissionStatus, permissionCanClose, permissionConfirmation, permissionName } from './PermissionView.ts';
import { RuleLoad } from './RulePack.ts';
import { state } from './Writer.ts';
import { files } from './ResultStore.ts';
const camera = 'ohos.permission.CAMERA'; const microphone = 'ohos.permission.MICROPHONE';
function fact(permission=camera, overrides={}) { return { bundleName: 'com.test.app', displayName: '测试应用',
  permission, label: '', group: permission===camera ? '相机' : '麦克风', sensitive: true, declared: true,
  grant: 'granted', fixed: false, tokenId: 999, source: 'unknown', ...overrides }; }
function record(id, kind='permission', seq=1, status='done') { return { jobId:id, kind, seq, state:status }; }
function hit(name='com.test.app', overrides={}) { return { fingerprint:{kind:'bundle', bundleName:name, label:name},
  verdict:{level:'suspicious', source:'trust', evidence:'trust'}, granted:[camera,microphone], action:'none', ...overrides }; }
const rules = new RuleLoad(); rules.heuristics = [{id:'test',permissions:[camera,microphone],reason:'组合',level:'suspicious'}];
const stored = permissionStored(JSON.stringify({facts:[fact(),fact(),fact(microphone),fact(camera,{bundleName:'com.other.app'})],uses:[],
  counts:['位置','相机','麦克风','通讯录','日历','短信','电话','媒体'].map(group=>({group,count:group==='相机'?23:0,known:true})),
  bundlesAvailable:true,usesAvailable:true}));
assert(stored); assert.equal(stored.counts[1].count,23); assert(stored.counts[1].known);
assert.deepEqual(permissionRequest('anomaly:exam-1'),{kind:'permission',scope:'quick',uris:[],focus:'anomaly:exam-1'});
assert.notEqual(permissionRequest('').focus,permissionRequest('anomaly:exam-1').focus);
assert.equal(permissionCounts(stored.facts)[1].count,2);
assert.equal(permissionCounts([fact(camera,{grant:'unknown'})])[1].known,false);
assert.equal(permissionStored('{bad'),null);
assert.equal(permissionStored(JSON.stringify({facts:[],uses:[],counts:stored.counts.map(row=>({group:row.group,count:row.count}))})).counts[1].known,false);
assert.equal(permissionSelection('sensitive','',stored,[],()=>null,rules).rows.length,0);
assert.equal(permissionSelection('相机','相机',stored,[],()=>null,rules).rows.length,2);
const otherStored = permissionStored(JSON.stringify({facts:[fact('ohos.permission.SYSTEM',{group:'其它',sensitive:false})],uses:[]}));
assert.equal(permissionSelection('其它','其它',otherStored,[],()=>null,rules).rows.length,1);
const unavailable = permissionStored(JSON.stringify({facts:[],uses:[],bundlesAvailable:false}));
assert.equal(permissionSelection('','',unavailable,[],()=>null,rules).missing,'无法获取应用列表');
const exam = {apps:[hit(), hit('com.official',{verdict:{evidence:'official',source:'local-rule'}}), hit('com.jinyinhu.securitycenter')]};
let selected = permissionSelection('anomaly:exam-1','',stored,[record('exam-1','exam')],()=>JSON.stringify(exam),rules);
assert.equal(selected.banner,'以下为该次体检的授权记录'); assert.equal(selected.rows.length,2);
assert(selected.rows.every(row=>row.bundleName==='com.test.app' && row.current===null));
assert.equal(permissionSelection('anomaly:exam-1','',stored,[record('exam-1','exam',1,'running')],()=>JSON.stringify(exam),rules).missing,'没有该次体检记录');
assert.equal(permissionSelection('anomaly:missing','',stored,[],()=>null,rules).missing,'没有该次体检记录');
selected = permissionSelection('com.test.app','',null,[record('old','exam')],()=>JSON.stringify(exam),rules);
assert.equal(selected.banner,'权限来自上次扫描，开关为当前状态'); assert.equal(selected.rows.length,2); assert(selected.knownBundle);
let line=permissionLines([fact()])[0]; line.userGrant=true; line.revokeVerified=true; line.current=fact(camera,{tokenId:88});
assert(permissionCanClose(line,true,false));
assert.equal(permissionStatus(line,true,true),'正在刷新授权'); assert(!permissionCanClose(line,true,true));
for (const [change,ready,status] of [[{tokenId:0},true,'无法读取授权'],[{grant:'unknown'},true,'状态未知'],
  [{grant:'denied'},true,'已关闭'],[{fixed:true},true,'受系统限制，无法关闭'],[{},false,'无法关闭此权限']]) {
  line.current=fact(camera,{tokenId:88,...change}); assert(!permissionCanClose(line,ready,false));
  assert.equal(permissionStatus(line,ready,false),status);
}
line.current=fact(camera,{tokenId:88}); line.userGrant=false; assert(!permissionCanClose(line,true,false));
line.userGrant=true; assert(permissionConfirmation(line).includes('测试应用')); assert(permissionConfirmation(line).includes('相机'));
assert(permissionConfirmation(line).includes('关闭后，该应用无法再次申请此权限，需到系统设置中重新开启'));
assert.equal(permissionName(camera,''),'相机'); assert.equal(permissionBlocks(permissionLines(stored.facts)).length,2);

line.verificationFailed=true; line.revokeVerified=false;
assert(!permissionCanClose(line,true,false)); assert.equal(permissionStatus(line,true,false),'无法读取授权');
line.verificationFailed=false; line.revokeVerified=true;
const app = new Map(); globalThis.AppStorage = {get(key){return app.get(key);}};
let dialog; globalThis.AlertDialog = {show(value){dialog=value;}};
const permissionJob = record('permission-1'); state.index=[permissionJob]; files.set(permissionJob.jobId,JSON.stringify(stored));
let resolveOld; let first=true;
const actions={ revokeReady(){return true;},grantsReady(){return true;},usesReady(){return true;},
  async exists(){return true;},async userGrant(){return true;},async canRevoke(){return true;},async reconcile(){},
  current(){ if(first){first=false;return new Promise(resolve=>{resolveOld=resolve;});} return Promise.resolve([fact(camera,{grant:'denied',tokenId:88})]); },
  revoke(){throw new Error('page must delegate action through Disposition');} };
app.set('center.permission',actions);
const h=new Harness(); h.viewing='permission-1'; h.params='相机';
const old=h.loadCurrent(false); await Promise.resolve();
app.set('center.queue',{enqueue(request){assert.equal(request.focus,'相机');return 'permission-2';}});
state.index.push(record('permission-2','permission',2,'queued'));
h.onGate(); assert.equal(h.refreshing,true); assert.equal(h.viewing,'permission-2');
resolveOld([fact(camera,{tokenId:999})]); await old; assert.equal(h.refreshing,true);
assert(h.blocks.every(block=>block.rows.every(row=>row.current===null)));
state.index[1].state='done'; files.set('permission-2',JSON.stringify({...stored,facts:[fact(camera,{grant:'denied'})]}));
h.light={kind:'permission',jobId:'permission-2',state:'done'}; h.onLight();
await new Promise(resolve=>setImmediate(resolve));
assert.equal(h.refreshing,false); assert.equal(h.blocks[0].rows[0].current.tokenId,88);
assert.equal(permissionStatus(h.blocks[0].rows[0],h.canRevoke,h.refreshing),'已关闭');
let called;
app.set('center.disposition',{async closePermission(...args){called=args;return {done:true,message:'已关闭'};}});
h.params='相机'; line.current=fact(camera,{tokenId:88}); h.canRevoke=true; h.refreshing=false;
h.confirmClose(line); assert(dialog.message.includes('测试应用')); dialog.secondaryButton.action();
await new Promise(resolve=>setImmediate(resolve));
assert.deepEqual(called,['permission-2','com.test.app',camera,'相机']);
let finishRevoke;
app.set('center.disposition',{closePermission(){return new Promise(resolve=>{finishRevoke=resolve;});}});
const interrupted=new Harness(); interrupted.viewing='permission-1'; interrupted.canRevoke=true;
const closing=interrupted.closePermission(line);
state.index.push(record('permission-3','permission',3,'queued')); interrupted.viewing='permission-3';
finishRevoke({done:true,message:'已关闭'}); await closing;
assert.equal(interrupted.refreshing,true); assert.equal(interrupted.canRevoke,false);
const waiting=new Harness(); waiting.awaitingRequest=true; waiting.light={kind:'permission',jobId:'other',state:'done'};
let released=false; let enqueued=false;
app.set('center.queue',{enqueue(request){assert(released);enqueued=true;return 'next-permission';}});
waiting.onLight(); assert.equal(enqueued,false); released=true;
await new Promise(resolve=>setImmediate(resolve)); assert(enqueued);
// A first bundle route keeps historical names, then reads current switches while its census is queued.
state.index=[record('scan-1','malware',1)]; files.set('scan-1',JSON.stringify({hits:[hit()]}));
let nextJob=0;
app.set('center.queue',{enqueue(request){const id='initial-'+(++nextJob); state.index.push(record(id,'permission',nextJob+10,'queued')); return id;}});
const firstActions={...actions, async current(bundle,names){return [fact(camera,{tokenId:77}),fact(microphone,{tokenId:77})];}};
app.set('center.permission',firstActions);
const firstOpen=new Harness(); firstOpen.params='com.test.app'; firstOpen.aboutToAppear();
await new Promise(resolve=>setImmediate(resolve));
assert.equal(state.index.find(row=>row.jobId===firstOpen.viewing).state,'queued');
assert.equal(firstOpen.banner,'权限来自上次扫描，开关为当前状态');
assert.equal(firstOpen.refreshing,false); assert(permissionCanClose(firstOpen.blocks[0].rows[0],firstOpen.canRevoke,false));
assert.equal(firstOpen.blocks[0].rows[0].current.tokenId,77);
// A foreground invalidation blocks the same fallback and invalidates an in-flight initial lookup.
let completeStale;
firstActions.current=()=>new Promise(resolve=>{completeStale=resolve;});
const inFlight=firstOpen.loadCurrent(true); await Promise.resolve();
firstOpen.onGate(); assert.equal(firstOpen.initialBundleRead,false); assert.equal(firstOpen.refreshing,true);
completeStale([fact(camera,{tokenId:999})]); await inFlight;
assert.equal(firstOpen.refreshing,true); assert.equal(firstOpen.canRevoke,false);
assert(firstOpen.blocks.every(block=>block.rows.every(row=>row.current===null)));
// No saved names still permits a fresh census lookup for an existing bundle on first open.
state.index=[];
app.set('center.permission',{...actions, async current(){return [fact(camera,{tokenId:78})];}});
const fromCurrent=new Harness(); fromCurrent.params='com.test.app'; fromCurrent.aboutToAppear();
await new Promise(resolve=>setImmediate(resolve));
assert.equal(fromCurrent.missing,''); assert.equal(fromCurrent.refreshing,false);
assert(permissionCanClose(fromCurrent.blocks[0].rows[0],fromCurrent.canRevoke,false));
// An existing closed permission result retains the regular wait-until-new-result rule.
state.index=[record('prior-permission')]; files.set('prior-permission',JSON.stringify(stored));
const prior=new Harness(); prior.params='com.test.app'; prior.aboutToAppear();
await new Promise(resolve=>setImmediate(resolve));
assert.equal(prior.refreshing,true); assert.equal(prior.canRevoke,false);
// A successful grant read with an unreliable flags read must still hide the action.
state.index=[permissionJob]; files.set(permissionJob.jobId,JSON.stringify(stored));
app.set('center.permission',{...actions, async current(){return [fact(camera,{tokenId:88})];},async canRevoke(){return false;}});
const flagsFailed=new Harness(); flagsFailed.viewing=permissionJob.jobId; flagsFailed.params='相机';
await flagsFailed.loadCurrent(false);
const flagsLine=flagsFailed.blocks[0].rows[0]; assert(!permissionCanClose(flagsLine,flagsFailed.canRevoke,false));
assert.equal(permissionStatus(flagsLine,flagsFailed.canRevoke,false),'无法读取授权');
let checkStarted; let finishCheck;
const started=new Promise(resolve=>{checkStarted=resolve;});
app.set('center.permission',{...actions, async current(){return [fact(camera,{tokenId:88})];},
  canRevoke(){checkStarted();return new Promise(resolve=>{finishCheck=resolve;});}});
const checkRace=new Harness(); checkRace.viewing=permissionJob.jobId; checkRace.params='相机';
const checking=checkRace.loadCurrent(false); await started;
checkRace.onGate(); assert(checkRace.refreshing); finishCheck(true); await checking;
assert.equal(checkRace.refreshing,true); assert.equal(checkRace.canRevoke,false);
assert(checkRace.blocks.every(block=>block.rows.every(row=>row.current===null)));
const before=h.revision; h.aboutToDisappear(); h.onGate(); assert.equal(h.revision,before+1);
process.stdout.write('PermissionView model, current-state actions and refresh race checks passed\\n');
`)
  const result = spawnSync(process.execPath, ['--experimental-strip-types', join(directory, 'main.ts')], { encoding: 'utf8' })
  process.stdout.write(result.stdout || '')
  process.stderr.write(result.stderr || '')
  assert.equal(result.status, 0)
} finally {
  rmSync(directory, { recursive: true, force: true })
}
