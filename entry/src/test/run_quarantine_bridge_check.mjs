import { spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
const root = resolve(dirname(fileURLToPath(import.meta.url)), '../../..')
const dir = mkdtempSync(join(tmpdir(),'quarantine-bridge-'))
try {
  const prep = text => text.replaceAll('\r\n','\n').replace(/from '(\.{1,2}\/[^']+)'/g,
    (all,path)=>`from './${path.split('/').at(-1)}.ts'`)
  for (const name of ['record/QuarantineBridge','center/CenterError']) {
    writeFileSync(join(dir,name.split('/').at(-1)+'.ts'),prep(readFileSync(resolve(root,'entry/src/main/ets',name+'.ets'),'utf8')))
  }
  writeFileSync(join(dir,'Quarantine.ts'),'export class Quarantine {}\n')
  writeFileSync(join(dir,'main.ts'),`
import assert from 'node:assert/strict';import {QuarantineBridge,grantedRoot} from './QuarantineBridge.ts';import {CenterError} from './CenterError.ts';
assert.equal(grantedRoot('/safe/dir/file',['/safe/dir']),'/safe/dir');
assert.equal(grantedRoot('/safe/dir-other/file',['/safe/dir']),'');
assert.equal(grantedRoot('file:///safe/dir/file',['file:///safe/dir']),'/safe/dir');
assert.equal(grantedRoot('/safe/dir/file',['/safe','/safe/dir']),'/safe/dir');
assert.equal(grantedRoot('content://file',['content://file']),'');
let calls=[];const box={async put(...args){calls.push(args);return {committed:true}},list(){return []},async restore(...a){calls.push(a);return null},async discard(){return null}};
let ready=false, failed=false;const gate={huks:()=>({status:ready?'ready':'unsupported'})};
const grants={async check(){if(failed)throw Error('bad')},persisted(){return [{uri:'/persist',persisted:true}]}};
const session={roots:id=>id==='job'?['/picked']:[]};const bridge=new QuarantineBridge(box,grants,gate,session);
let out=await bridge.put('/picked/a',1,'','', 'job');assert(out instanceof CenterError);assert.equal(calls.length,0);
ready=true;out=await bridge.put('/picked/a',1,'','', 'job');assert.equal(out.committed,true);assert.equal(calls[0][4],'/picked');
out=await bridge.put('/picked/a',1,'','','other');assert(out instanceof CenterError);assert.equal(out.code,'rejected-system-path');
out=await bridge.put('/persist/a',1,'','','other');assert.equal(out.committed,true);assert.equal(calls[1][4],'/persist');
failed=true;out=await bridge.put('/persist/a',1,'','','job');assert(out instanceof CenterError);assert.equal(calls.length,2);
ready=false;assert((await bridge.restore('q','/persist','')) instanceof CenterError);
process.stdout.write('Quarantine grant boundary checks passed\\n');
`)
  const run=spawnSync(process.execPath,['--experimental-strip-types',join(dir,'main.ts')],{encoding:'utf8'})
  process.stdout.write(run.stdout||'');process.stderr.write(run.stderr||'');if(run.status!==0)process.exitCode=run.status??1
} finally {rmSync(dir,{recursive:true,force:true})}
