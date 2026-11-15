import { spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
const root = resolve(dirname(fileURLToPath(import.meta.url)), '../../..')
const tempRoot = resolve(tmpdir())
const dir = mkdtempSync(join(tempRoot, 'huks-quarantine-'))
if (!resolve(dir).startsWith(tempRoot + sep)) throw new Error('unexpected temporary directory')
try {
  let source = readFileSync(resolve(root,'entry/src/main/ets/record/HuksQuarantineCipher.ets'),'utf8')
    .replace("from '@ohos.security.huks'", "from './huks.mjs'")
    .replace("from '@ohos.security.cryptoFramework'", "from './crypto.mjs'")
    .replace("from '@ohos.util'", "from './util.mjs'")
    .replace("from './Quarantine'", "from './Quarantine.ts'")
    .replace("from './StreamingSha256'", "from './StreamingSha256.ts'")
  writeFileSync(join(dir,'cipher.ts'),source)
  writeFileSync(join(dir,'StreamingSha256.ts'),readFileSync(resolve(root,'entry/src/main/ets/record/StreamingSha256.ets'),'utf8'))
  writeFileSync(join(dir,'crypto.mjs'),`import {randomBytes} from 'node:crypto'; export default {createRandom(){return {generateRandomSync(n){return {data:new Uint8Array(randomBytes(n))}}}}};`)
  writeFileSync(join(dir,'util.mjs'),`export default {Base64Helper: class { encodeToStringSync(b){return Buffer.from(b).toString('base64')} decodeSync(s){return new Uint8Array(Buffer.from(s,'base64'))} }};`)
  writeFileSync(join(dir,'huks.mjs'),`
import {randomBytes,createCipheriv,createDecipheriv} from 'node:crypto';
const keys=new Map(), sessions=new Map(); let next=1;
export const state={generated:0, aborted:0, failFinish:false};
const HuksTag={HUKS_TAG_ALGORITHM:1,HUKS_TAG_KEY_SIZE:2,HUKS_TAG_PURPOSE:3,HUKS_TAG_PADDING:4,HUKS_TAG_BLOCK_MODE:5,HUKS_TAG_NONCE:6,HUKS_TAG_ASSOCIATED_DATA:7,HUKS_TAG_AE_TAG:8};
const h={HuksTag,HuksKeyAlg:{HUKS_ALG_AES:20},HuksKeySize:{HUKS_AES_KEY_SIZE_256:256},HuksKeyPurpose:{HUKS_KEY_PURPOSE_ENCRYPT:1,HUKS_KEY_PURPOSE_DECRYPT:2},HuksKeyPadding:{HUKS_PADDING_NONE:0},HuksCipherMode:{HUKS_MODE_GCM:32},
 async isKeyItemExist(a){return keys.has(a)}, async generateKeyItem(a,o){if(keys.has(a))throw Error('already exists');keys.set(a,randomBytes(32));state.generated++},
 async initSession(a,o){if(!keys.has(a))throw Error('missing');let id=next++,p=new Map(o.properties.map(x=>[x.tag,x.value]));let cipher=p.get(3)===1?createCipheriv('aes-256-gcm',keys.get(a),p.get(6)):createDecipheriv('aes-256-gcm',keys.get(a),p.get(6));cipher.setAAD(p.get(7));if(p.get(3)!==1)cipher.setAuthTag(p.get(8));sessions.set(id,{cipher,encrypt:p.get(3)===1});return {handle:id}},
 async updateSession(id,o){return {outData:new Uint8Array(sessions.get(id).cipher.update(o.inData))}},
 async finishSession(id,o){if(state.failFinish)throw Error('failed');const session=sessions.get(id);let out=Buffer.concat([session.cipher.update(o.inData),session.cipher.final(),session.encrypt?session.cipher.getAuthTag():Buffer.alloc(0)]);
 sessions.delete(id);return {outData:new Uint8Array(out)}}, async abortSession(id){state.aborted++;sessions.delete(id)}}; export default h;`)
  writeFileSync(join(dir,'main.ts'),`
import assert from 'node:assert/strict'; import {createHash} from 'node:crypto'; import {mkdtempSync,openSync,closeSync,writeSync,readSync,unlinkSync,rmdirSync} from 'node:fs'; import {tmpdir} from 'node:os'; import {join} from 'node:path'; import {HuksQuarantineCipher} from './cipher.ts'; import {state} from './huks.mjs';
const c=new HuksQuarantineCipher(), plain=new Uint8Array([1,2,3,4]);
assert.equal(await c.decrypt('missing',256,plain,'',''),null);assert.equal(state.generated,0);
const one=await c.encrypt('alias',256,plain), two=await c.encrypt('alias',256,plain);
assert(one && two);assert.equal(state.generated,1);assert.notEqual(one.iv,two.iv);
assert.deepEqual(await c.decrypt('alias',256,one.bytes,one.iv,one.tag),plain);
const corrupt=one.bytes.slice();corrupt[0]^=1;assert.equal(await c.decrypt('alias',256,corrupt,one.iv,one.tag),null);
const large=new Uint8Array(200000);for(let i=0;i<large.length;i++)large[i]=i%251;
let chunks=[];let maxRead=0;
let streaming=await c.encryptStream('alias',256,large.length,{read(o,n){maxRead=Math.max(maxRead,n);return large.slice(o,o+Math.min(n,7000))}},{write(b){chunks.push(b.slice());return true}});
assert(streaming);assert(maxRead<=65536);assert.equal(streaming.sha256,createHash('sha256').update(large).digest('hex'));
const streamBytes=new Uint8Array(Buffer.concat(chunks.map(x=>Buffer.from(x))));assert.deepEqual(await c.decrypt('alias',256,streamBytes,streaming.iv,streaming.tag),large);
let restored=[];let digest=await c.decryptStream('alias',256,streamBytes.length,{read(o,n){return streamBytes.slice(o,o+Math.min(n,5000))}},{write(b){restored.push(b.slice());return true}},streaming.iv,streaming.tag);
assert.equal(digest,streaming.sha256);assert.deepEqual(new Uint8Array(Buffer.concat(restored.map(x=>Buffer.from(x)))),large);
const damaged=streamBytes.slice();damaged[0]^=1;assert.equal(await c.decryptStream('alias',256,damaged.length,{read(o,n){return damaged.slice(o,o+n)}},{write(){return true}},streaming.iv,streaming.tag),null);
const big=new Uint8Array(5*1024*1024+3);for(let i=0;i<big.length;i++)big[i]=i%239;
let maxOutput=0,total=0,bigSeal=await c.encryptStream('alias',256,big.length,{read(o,n){return big.subarray(o,o+n)}},{write(b){maxOutput=Math.max(maxOutput,b.length);total+=b.length;return true}});
assert(bigSeal);assert.equal(total,big.length);assert(maxOutput<=65536);assert.equal(bigSeal.sha256,createHash('sha256').update(big).digest('hex'));
if(process.env.HUKS_STRESS==='1'){
 const size=512*1024*1024, zeros=new Uint8Array(65536), temp=mkdtempSync(join(tmpdir(),'huks-stream-stress-'));let count=0,maxChunk=0,fd=openSync(join(temp,'cipher.bin'),'w+');
 try {
  let start=performance.now();const result=await c.encryptStream('alias',256,size,{read(o,n){return zeros.subarray(0,n)}},{write(b){count+=b.length;maxChunk=Math.max(maxChunk,b.length);return writeSync(fd,b)===b.length}});
  const expected=createHash('sha256');for(let i=0;i<size;i+=zeros.length)expected.update(zeros);const digest=expected.digest('hex');
  assert(result);assert.equal(count,size);assert(maxChunk<=65536);assert.equal(result.sha256,digest);
  let restored=0;const actual=await c.decryptStream('alias',256,size,{read(o,n){let buf=new Uint8Array(n);let got=readSync(fd,buf,0,n,o);return buf.subarray(0,got)}},{write(b){restored+=b.length;return true}},result.iv,result.tag);
  assert.equal(actual,digest);assert.equal(restored,size);
  process.stdout.write('512 MiB mock-HUKS round trip: '+Math.round((performance.now()-start)/1000)+' s, RSS '+Math.round(process.memoryUsage().rss/1048576)+' MiB\\n');
 } finally {closeSync(fd);unlinkSync(join(temp,'cipher.bin'));rmdirSync(temp)}
}
assert.equal(await c.encryptStream('alias',256,large.length,{read(){return null}},{write(){return true}}),null);
assert.equal(await c.encryptStream('alias',256,large.length,{read(o,n){return large.slice(o,o+n)}},{write(){return false}}),null);
const sealed=await c.encrypt('alias',256,large);assert(sealed);assert.deepEqual(await c.decrypt('alias',256,sealed.bytes,sealed.iv,sealed.tag),large);
sealed.bytes[100000]^=1;assert.equal(await c.decrypt('alias',256,sealed.bytes,sealed.iv,sealed.tag),null);
assert.equal(await c.decrypt('alias',256,one.bytes,one.iv,'AA=='),null);
assert.equal(await c.encrypt('alias',128,plain),null);
state.failFinish=true;assert.equal(await c.encrypt('alias',256,plain),null);assert(state.aborted>0);
process.stdout.write('HUKS cipher contract checks passed (mock HUKS)\\n');
`)
  const run=spawnSync(process.execPath,['--experimental-strip-types',join(dir,'main.ts')],{encoding:'utf8'})
  process.stdout.write(run.stdout||'');process.stderr.write(run.stderr||'');if(run.status!==0) process.exitCode=run.status??1
} finally {rmSync(dir,{recursive:true,force:true})}
