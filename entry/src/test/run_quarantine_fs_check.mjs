import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
const root=resolve(dirname(fileURLToPath(import.meta.url)),'../../..')
const src=readFileSync(resolve(root,'entry/src/main/ets/record/Quarantine.ets'),'utf8').replaceAll('\r\n','\n')
const part=src.slice(src.indexOf('export class FsByteStore'),src.indexOf('export class Quarantine'))
assert(part.includes('function readWhole') && part.includes('removeOriginal'))
const dir=mkdtempSync(join(tmpdir(),'quarantine-fs-'))
try {
  writeFileSync(join(dir,'main.ts'),`
import assert from 'node:assert/strict';
const quarantineQuota=512*1024*1024, BLOB_DIR='center/quarantine/blobs/';
function bytePath(root,path){return path.startsWith('/')?path:root+'/'+path}
function sha256Hex(data){return Array.from(data).join(',')}
const files=new Map(),fds=new Map(),orphans=new Map(),positions=new Map();let next=5,shortRead=false,shortWrite=false;
const fs={OpenMode:{READ_ONLY:0,WRITE_ONLY:1,READ_WRITE:2,CREATE:64,TRUNC:512,NOFOLLOW:131072},
 mkdirSync(){},fsyncSync(){},openSync(path,flags){if((flags&128)&&files.has(path))throw Error('exists');if(flags&64)files.set(path,new Uint8Array());if(!files.has(path))throw Error('missing');let fd=next++;fds.set(fd,path);positions.set(fd,0);return {fd}},
 closeSync(file){let fd=typeof file==='number'?file:file.fd;fds.delete(fd);orphans.delete(fd);positions.delete(fd)},
 statSync(fd){let data=orphans.get(fd)??files.get(fds.get(fd));return {size:data.length,ino:1n,isFile:()=>true,isSymbolicLink:()=>false}},
 lstatSync(path){let data=files.get(path);if(!data)throw Error('missing');return {size:data.length,ino:1n,isFile:()=>true,isSymbolicLink:()=>false}},
 readSync(fd,buffer,opts){if(shortRead)return 0;let data=orphans.get(fd)??files.get(fds.get(fd)), offset=opts?.offset??0,n=Math.min(buffer.byteLength,data.length-offset);new Uint8Array(buffer).set(data.slice(offset,offset+n));return n},
 writeSync(fd,buffer){let path=fds.get(fd),incoming=shortWrite?new Uint8Array([1]):new Uint8Array(buffer),old=orphans.get(fd)??files.get(path),pos=positions.get(fd),value=new Uint8Array(Math.max(old.length,pos+incoming.length));value.set(old);value.set(incoming,pos);positions.set(fd,pos+incoming.length);if(orphans.has(fd))orphans.set(fd,value);else files.set(path,value);return incoming.length},
 unlinkSync(path){let value=files.get(path);for(const [fd,p] of fds)if(p===path)orphans.set(fd,value);files.delete(path)}};
${part}
const store=new FsByteStore('/app'); const original=new Uint8Array([2,3,4]);files.set('/existing',original);
assert.equal(store.writeNew('/existing',new Uint8Array([9])),false);assert.deepEqual(files.get('/existing'),original);
shortWrite=true;assert.equal(store.writeNew('/new',original),false);assert.equal(files.has('/new'),false);
assert.equal(store.write('center/quarantine/blobs/id',original),false);shortWrite=false;
assert.equal(store.writeNew('/new',original),true);assert.deepEqual(files.get('/new'),original);
let fd=fs.openSync('/new',0).fd;assert.deepEqual(store.readFd(fd),original);shortRead=true;assert.equal(store.readFd(fd),null);shortRead=false;
let scratch=store.openAnonymous('0123456789abcdef0123456789abcdef');assert(scratch>=0);
assert(!files.has('/app/center/quarantine/tmp/0123456789abcdef0123456789abcdef'));
assert(store.writeBlob(scratch,original));assert.deepEqual(store.readFd(scratch),original);
assert(store.writeNewFromFd('/restored',scratch,original.length));assert.deepEqual(files.get('/restored'),original);
assert.equal(store.writeNewFromFd('/existing',scratch,original.length),false);assert.deepEqual(files.get('/existing'),original);
store.closeBlob(scratch);assert(!orphans.has(scratch));
const occupied='/app/center/quarantine/tmp/22222222222222222222222222222222';files.set(occupied,original);
assert.equal(store.openAnonymous('22222222222222222222222222222222'),-1);assert.deepEqual(files.get(occupied),original);
const large=new Uint8Array(2*1024*1024+7);for(let i=0;i<large.length;i++)large[i]=i%251;
assert(store.writeNew('/large',large));assert.deepEqual(files.get('/large'),large);
let scratch2=store.openAnonymous('11111111111111111111111111111111');assert(store.writeBlob(scratch2,large));
assert(store.writeNewFromFd('/restored-large',scratch2,large.length));assert.deepEqual(files.get('/restored-large'),large);store.closeBlob(scratch2);
process.stdout.write('Quarantine file I/O failure checks passed\\n');
`)
  const run=spawnSync(process.execPath,['--experimental-strip-types',join(dir,'main.ts')],{encoding:'utf8'})
  process.stdout.write(run.stdout||'');process.stderr.write(run.stderr||'');if(run.status!==0)process.exitCode=run.status??1
} finally {rmSync(dir,{recursive:true,force:true})}
