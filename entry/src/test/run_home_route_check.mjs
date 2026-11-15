import { spawnSync } from 'node:child_process'
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../../..')
const INDEX = 'entry/src/main/ets/pages/Index.ets'
const HOME = 'entry/src/main/ets/pages/HomeView.ets'
const EXAM = 'entry/src/main/ets/pages/ExamView.ets'
const QUEUE = 'entry/src/main/ets/task/JobQueue.ets'

const problems = []
const read = (path) => readFileSync(resolve(root, path), 'utf8').replace(/\r\n/g, '\n')
const code = (text) => text.replace(/\/\*[\s\S]*?\*\/|\/\/.*$/gm, '')

const index = read(INDEX)
const home = read(HOME)
const exam = read(EXAM)
const indexCode = code(index)
const homeCode = code(home)
const examCode = code(exam)

if (!/pushPathByName\(route, params\)/.test(indexCode) || /pushPathByName\(\s*(\w+)\s*,\s*\1\s*\)/.test(indexCode)) {
  problems.push('打开方式是 pushPathByName(route, params)，禁止把路由名当作 params')
}
if (!/routeMap\(route: string, param: Object\)/.test(indexCode) || !/routeParams\(param\)/.test(indexCode)) {
  problems.push('routeMap 同时接收路由名和 params')
}
for (const route of ['home', 'exam', 'malware', 'job', 'P1', 'P2', 'P3', 'ledger', 'report', 'archive', 'device',
  'about']) {
  if (!indexCode.includes(`route === '${route}'`)) {
    problems.push(`routeMap 没有登记 ${route}`)
  }
}
if (!/PENDING_ROUTES\.indexOf\(route\) >= 0\)\s*\{\s*pendingPage\(\)/.test(indexCode)) {
  problems.push('占位路由只放占位 builder')
}
for (const page of ['AppsView', 'ProtectView']) {
  if (existsSync(resolve(root, `entry/src/main/ets/pages/${page}.ets`)) || indexCode.includes(page)) {
    problems.push(`本 issue 不新建 ${page}`)
  }
}
if (!/onOpen: \(route: string, params: string\) => void/.test(homeCode) ||
  !/onOpen: \(route: string, params: string\) => void/.test(examCode)) {
  problems.push('HomeView 和 ExamView 的 onOpen 传入路由名和 params 两个值')
}

for (const [name, text] of [['Index', index], ['HomeView', home], ['ExamView', exam]]) {
  for (const banned of ['已安全', '云查杀已开启', '已防护', '已拦截', '人工智能引擎已防护', '分数']) {
    if (text.includes(banned)) {
      problems.push(`${name} 出现了「${banned}」`)
    }
  }
  const body = code(text)
  if (/from '@ohos\.file\.fs'|@kit\.CoreFileKit|bundleManager|@ohos\.bundle|cryptoFramework|HashWorker|engine\/Hash/.test(body)) {
    problems.push(`${name} 是页面，不读盘、不调包管理、不做哈希`)
  }
  if (/from '\.\.\/(probe\/Registry|model\/ScanTask)'|ScanTask\.run/.test(body)) {
    problems.push(`${name} 不得在体检时调用 P1、P2、P3`)
  }
}
if ((homeCode.match(/'暂无风险'/g) || []).length !== 1 || !/return '暂无风险'/.test(homeCode)) {
  problems.push('「暂无风险」只能出自 ringText 的 clear')
}
if (/anomalyApps/.test(homeCode)) {
  problems.push('首页敏感人数禁止填 anomalyApps')
}
if (!/const TAG = 'HomeView'/.test(home)) {
  problems.push('不改 HomeView 现有的 hilog 标签')
}
if (!home.includes("this.groupTitle('系统防护自检')") || !/ForEach\(PROBE_IDS/.test(homeCode)) {
  problems.push('现有「系统防护自检」磁贴保留')
}
for (const route of ['malware', 'clean', 'permission', 'apps']) {
  if (!homeCode.includes(`'${route}')`)) {
    problems.push(`首页四格缺少 ${route}`)
  }
}
const heavyKey = read(QUEUE).match(/HEAVY_KEY: string = '([^']+)'/)
if (heavyKey === null || !homeCode.includes(`@StorageLink('${heavyKey[1]}')`) ||
  !examCode.includes(`@StorageLink('${heavyKey[1]}')`)) {
  problems.push('首页和体检页读 JobQueue 发布的重车道进度')
}
if (!exam.includes('const DOMAIN: number = 0x4A59') || !exam.includes("const TAG: string = 'Center'")) {
  problems.push('ExamView 的 hilog 域必须是 0x4A59，标签 Center')
}
if (/Button\(/.test(examCode) || /处理/.test(exam.replaceAll('待处理', ''))) {
  problems.push('体检页没有处理按钮')
}
if (/from '\.\.\/(feature\/(malware|clean|permission|apps|protect)|record\/(Disposition|Quarantine|TrustList))/.test(homeCode + examCode)) {
  problems.push('首页和体检页不处理条目')
}

if (problems.length > 0) {
  process.stderr.write(problems.join('\n') + '\n')
  process.exit(1)
}

/** 去掉 import、@Entry/@Component 的 struct 和全局 @Builder，只留顶层纯函数与类。 */
function stripUi(text) {
  let out = text.replace(/^import[\s\S]*?from '[^']+';?\n/gm, '')
  for (;;) {
    const m = out.match(/^((?:@\w+(?:\([^)]*\))?\n)+)(?:export )?(?:struct|function) \w+\([^)]*\)\s*\{|^((?:@\w+(?:\([^)]*\))?\n)+)(?:export )?struct \w+\s*\{/m)
    if (m === null) {
      return out
    }
    const start = m.index
    let i = start + m[0].length
    let depth = 1
    while (depth > 0 && i < out.length) {
      const c = out[i]
      if (c === "'" || c === '"' || c === '`') {
        i++
        while (i < out.length && out[i] !== c) {
          i += out[i] === '\\' ? 2 : 1
        }
      } else if (c === '/' && out[i + 1] === '/') {
        while (i < out.length && out[i] !== '\n') i++
      } else if (c === '{') {
        depth++
      } else if (c === '}') {
        depth--
      }
      i++
    }
    out = out.slice(0, start) + out.slice(i)
  }
}

const hilogStub = 'const hilog = { error() {}, info() {}, warn() {} };\n'
const themeStub = "const Theme = new Proxy({}, { get: (t, k) => String(k) });\n"
const files = [
  ['entry/src/main/ets/center/CenterTypes.ets', 'CenterTypes.ts', (t) => t],
  ['entry/src/main/ets/feature/exam/ExamState.ets', 'ExamState.ts', (t) => t
    .replace(/import \{ hilog \} from '@kit\.PerformanceAnalysisKit';?\n/, hilogStub)
    .replace(/^import type [\s\S]*?from '[^']+';?\n/m, '')],
  [HOME, 'HomeView.ts', (t) => "import { homeExam } from './ExamState.ts';\n" + hilogStub + themeStub + stripUi(t)],
  [EXAM, 'ExamView.ts', (t) =>
    "import { NOT_RUN, examNotes, examReportOf, ringText } from './HomeView.ts';\n" + hilogStub + themeStub +
    stripUi(t)],
  [INDEX, 'Index.ts', (t) => "const probeName = (id) => 'probe ' + id;\n" + stripUi(t)],
  ['entry/src/test/HomeRoute.test.ets', 'HomeRoute.test.ts', (t) => t
    .replace(/^import type [\s\S]*?from '[^']+'\n/gm, '')
    .replace(/from '\.\.\/main\/ets\/pages\/(\w+)'/g, "from './$1.ts'")]
]

const dir = mkdtempSync(join(tmpdir(), 'home-route-'))
try {
  for (const [from, to, prep] of files) {
    writeFileSync(join(dir, to), prep(read(from)))
  }
  writeFileSync(join(dir, 'main.ts'),
    "import { runHomeRouteChecks } from './HomeRoute.test.ts';\nrunHomeRouteChecks();\nprocess.stdout.write('Index, HomeView and ExamView checks passed\\n');\n")
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
