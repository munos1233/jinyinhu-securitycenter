import { spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
const root=resolve(dirname(fileURLToPath(import.meta.url)),'../../..')
const dir=mkdtempSync(join(tmpdir(),'streaming-sha-'))
try {
  writeFileSync(join(dir,'sha.ts'),readFileSync(resolve(root,'entry/src/main/ets/record/StreamingSha256.ets'),'utf8'))
  writeFileSync(join(dir,'main.ts'),`
import assert from 'node:assert/strict';import {createHash,randomBytes} from 'node:crypto';import {StreamingSha256} from './sha.ts';
for(const n of [0,1,3,55,56,63,64,65,119,120,127,128,129,1024,65537]){
 const data=new Uint8Array(randomBytes(n)), expected=createHash('sha256').update(data).digest('hex');
 for(const chunk of [1,7,63,64,65,1000]){let d=new StreamingSha256();for(let i=0;i<n;i+=chunk)d.update(data.subarray(i,i+chunk));assert.equal(d.finish(),expected,'length '+n+' chunk '+chunk);assert.throws(()=>d.update(new Uint8Array()));}
}
process.stdout.write('Incremental SHA-256 checks passed\\n');
`)
  const run=spawnSync(process.execPath,['--experimental-strip-types',join(dir,'main.ts')],{encoding:'utf8'})
  process.stdout.write(run.stdout||'');process.stderr.write(run.stderr||'');if(run.status!==0)process.exitCode=run.status??1
} finally {rmSync(dir,{recursive:true,force:true})}
