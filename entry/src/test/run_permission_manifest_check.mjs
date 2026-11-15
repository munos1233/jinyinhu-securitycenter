import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '../../..');
const P = 'ohos.permission.';

let failures = 0;
function check(ok, message) {
  if (!ok) {
    failures++;
    console.error(`FAIL ${message}`);
  }
}

function readJson5(path) {
  const text = readFileSync(path, 'utf8')
    .replace(/^\s*\/\/.*$/gm, '')
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/,(\s*[\]}])/g, '$1');
  return JSON.parse(text);
}

const module = readJson5(resolve(root, 'entry/src/main/module.json5')).module;
const requested = module.requestPermissions.map((p) => p.name);
const byName = new Map(module.requestPermissions.map((p) => [p.name, p]));

check(new Set(requested).size === requested.length, 'requestPermissions has duplicates');

const required = [
  'GET_BUNDLE_INFO',
  'GET_BUNDLE_INFO_PRIVILEGED',
  'INSTALL_BUNDLE',
  'GET_INSTALLED_BUNDLE_LIST',
  // Defined for `general` devices, so declared regardless of this module's deviceTypes.
  'GET_SENSITIVE_PERMISSIONS',
  'PERMISSION_USED_STATS',
  'STORAGE_MANAGER',
  'REMOVE_CACHE_FILES',
  'REVOKE_SENSITIVE_PERMISSIONS'
];
for (const name of required) {
  check(byName.has(P + name), `module.json5 missing ${name}`);
}

// user_grant permissions need a reason and usedScene or the HAP is rejected at build time.
const listPerm = byName.get(P + 'GET_INSTALLED_BUNDLE_LIST');
if (listPerm) {
  check(typeof listPerm.reason === 'string' && listPerm.reason.startsWith('$string:'),
    'GET_INSTALLED_BUNDLE_LIST needs a $string reason');
  check(Array.isArray(listPerm.usedScene?.abilities) && listPerm.usedScene.abilities.length > 0,
    'GET_INSTALLED_BUNDLE_LIST needs usedScene.abilities');
  const strings = JSON.parse(readFileSync(resolve(root, 'entry/src/main/resources/base/element/string.json'), 'utf8')).string;
  const key = listPerm.reason?.slice('$string:'.length);
  check(strings.some((s) => s.name === key), `string resource ${key} missing`);
}

const tracked = spawnSync('git', ['ls-files'], { cwd: root, encoding: 'utf8' }).stdout.split('\n');
const secrets = tracked.filter((f) => /\.(p12|p7b|cer|pem|key|jks)$/i.test(f) || /keystore|password|passwd/i.test(f));
check(secrets.length === 0, `signing material tracked in repo: ${secrets.join(', ')}`);

if (failures > 0) {
  console.error(`${failures} permission manifest check(s) failed`);
  process.exit(1);
}
console.log('permission manifest checks passed');
