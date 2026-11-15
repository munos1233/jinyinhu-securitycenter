import { spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../../..')
const INDEX = 'entry/src/main/ets/pages/Index.ets'
const CLEAN = 'entry/src/main/ets/pages/CleanView.ets'
const QUARANTINE = 'entry/src/main/ets/pages/QuarantineView.ets'
const BOX = 'entry/src/main/ets/record/Quarantine.ets'
const HOME = 'entry/src/main/ets/pages/HomeView.ets'
const problems = []
const read = (path) => readFileSync(resolve(root, path), 'utf8').replace(/\r\n/g, '\n')
const code = (text) => text.replace(/\/\*[\s\S]*?\*\/|\/\/.*$/gm, '')

const index = read(INDEX)
const clean = read(CLEAN)
const quarantine = read(QUARANTINE)
const box = read(BOX)
const indexCode = code(index)
const cleanCode = code(clean)
const quarantineCode = code(quarantine)

for (const [name, text] of [['CleanView', clean], ['QuarantineView', quarantine]]) {
  if (!text.includes('const DOMAIN: number = 0x4A59;') || !text.includes("const TAG: string = 'Center';")) {
    problems.push(`${name} 的 hilog 域必须是 0x4A59，标签 Center`)
  }
  for (const banned of ['已安全', '云查杀已开启', '已防护', '已拦截', '人工智能引擎已防护', '病毒', '分数', '已完成',
    '仅统计了本应用缓存', '没有垃圾', '清空全部']) {
    if (text.includes(banned)) {
      problems.push(`${name} 出现了「${banned}」`)
    }
  }
  const body = code(text)
  if (/@ohos\.file\.fs|fileIo|bundleManager|@ohos\.bundle|cryptoFramework|HashWorker|engine\/Hash'|subtractPart|CleanMath/.test(body)) {
    problems.push(`${name} 不读盘、不调包管理、不做哈希，也不自己减字节`)
  }
  if (/from '\.\.\/(feature|probe|system)\//.test(body)) {
    problems.push(`${name} 不 import 功能模块、探针和系统端口`)
  }
  if (/Writer\.(commit|saveIndex|replaceText|exclusive|settleExam)|ResultStore\.save|from '\.\.\/record\/Quarantine'/.test(body)) {
    problems.push(`${name} 写盘只经 Disposition 或隔离区桌面，不直接改结果文件`)
  }
  if (/state === 'done'/.test(body)) {
    problems.push(`${name} 不用 JobRecord.state===done 判断扫完`)
  }
  const coreFile = text.match(/import \{([^}]*)\} from '@kit\.CoreFileKit'/)
  if (coreFile !== null && coreFile[1].trim() !== 'picker') {
    problems.push(`${name} 从 CoreFileKit 只取选择器`)
  }
}

if (!/Text\(VIEW_ONLY\)/.test(cleanCode) || !/const VIEW_ONLY: string = '仅查看，不删除'/.test(clean)) {
  problems.push('重复文件页和大文件页要写「仅查看，不删除」')
}
if (!/if \(showsProcess\(this\.params\)\) \{\s*Button\('立即处理'\)/.test(cleanCode) ||
  !/Button\('开始'\)/.test(cleanCode)) {
  problems.push('清理页是开始和立即处理；查看页不出现立即处理')
}
if (!/this\.onOpen\('clean', target\)/.test(cleanCode) || !/'重复文件'/.test(clean) || !/'大文件'/.test(clean)) {
  problems.push('没有授权时重复文件和大文件入口仍在')
}
const appear = cleanCode.match(/aboutToAppear\(\): void \{([\s\S]*?)\n  \}/)
if (appear === null || /enqueue\(/.test(appear[1])) {
  problems.push('打开清理页不入队')
}
if (!/disposition\.clearCache\(this\.look\.jobId/.test(cleanCode) ||
  !/disposition\.quarantine\(this\.look\.jobId/.test(cleanCode)) {
  problems.push('字节变化只调用 Disposition 的清缓存和隔离')
}
if (!/pickDirectory\(false\)/.test(cleanCode) || !/directoryGranted\(this\.currentGrants\(\)\)/.test(cleanCode)) {
  problems.push('没有授权时点进重复文件或大文件要先选择目录')
}
if (!/Text\('全选'\)/.test(cleanCode) || !/Text\('取消全选'\)/.test(cleanCode) ||
  !/selectCategory\(this\.selected, sectionKeys\(section\),/.test(cleanCode)) {
  problems.push('全选和取消全选只改当前这一类')
}

const boxAppear = quarantineCode.match(/aboutToAppear\(\): void \{([\s\S]*?)\n  \}/)
if (boxAppear === null || /discard|restore|removeRow|unlink/.test(boxAppear[1])) {
  problems.push('打开隔离区不自动删除，也不自动再删源文件')
}
if (!/deleteConfirm\(row\.name, row\.size\)/.test(quarantineCode) || !/discardCall\(desk, id\)/.test(quarantineCode)) {
  problems.push('删除要第二次确认，确认后才 discard')
}
if (!/restoreCall\(desk, row\.entry, this\.grants, choose\)/.test(quarantineCode) ||
  !/this\.pickRestore\(row\)/.test(quarantineCode)) {
  problems.push('隔离区要能恢复；原路径不行时另选目录')
}
if (!/status = OPEN/.test(quarantineCode) || !/const OPEN: string = '未完成'/.test(quarantine) ||
  !/const KEPT: string = '副本已保存，原文件仍在'/.test(quarantine)) {
  problems.push('committed=false 的状态是未完成，说明副本已保存、原文件仍在')
}
const discard = code(box).match(/discard\(id: string\): CenterError \| null \{([\s\S]*?)\n  \}/)
if (discard === null || /found\.from/.test(discard[1]) || !/BLOB_DIR \+ found\.stored/.test(discard[1])) {
  problems.push('删除隔离项只去掉清单和密文，不删除原文件')
}

const routeMap = indexCode.match(/routeMap\(route: string, param: Object\) \{([\s\S]*?)\n {2}\}/)
if (routeMap === null) {
  problems.push('Index 没有 routeMap')
} else {
  const body = routeMap[1]
  if (!/route === 'clean'\) \{\s*CleanView\(\{\s*params: routeParams\(param\),/.test(body)) {
    problems.push('clean 打开 CleanView，params 用 routeParams')
  }
  if (!/route === 'quarantine'\) \{\s*QuarantineView\(\)/.test(body)) {
    problems.push('quarantine 打开 QuarantineView')
  }
  for (const route of ['home', 'exam', 'malware', 'job', 'ledger', 'report', 'archive', 'device', 'about']) {
    if (!body.includes(`route === '${route}'`)) {
      problems.push(`不重写 routeMap 里的 ${route}`)
    }
  }
  if (!body.includes("route === 'P1' || route === 'P2' || route === 'P3'")) {
    problems.push('不重写 P1 P2 P3')
  }
  for (const page of ['AppsView', 'ProtectView']) {
    if (!body.includes(page)) {
      problems.push(`页面路由缺少 ${page}`)
    }
  }
  if (!/PENDING_ROUTES\.indexOf\(route\) >= 0\)\s*\{\s*pendingPage\(\)/.test(body)) {
    problems.push('其余占位路由不动')
  }
}
const pending = indexCode.match(/PENDING_ROUTES: string\[\] = \[([^\]]*)\]/)
if (pending === null || pending[1].replace(/\s/g, '') !== '') {
  problems.push('软件和防护路由应为真实页面')
}

if (problems.length > 0) {
  process.stderr.write(problems.join('\n') + '\n')
  process.exit(1)
}

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

const hilogStub = "const hilog = { error(domain, tag, message, extra) { const bag = globalThis; if (!Array.isArray(bag.__centerHilog)) { bag.__centerHilog = []; } bag.__centerHilog.push(String(message) + ' ' + String(extra ?? '')); }, info() {}, warn() {} };\n"
const themeStub = "const Theme = new Proxy({}, { get: (t, k) => String(k) });\n"
const files = [
  ['entry/src/main/ets/center/CenterError.ets', 'CenterError.ts', (t) => t],
  ['entry/src/main/ets/feature/exam/ExamState.ets', 'ExamState.ts', (t) => t
    .replace(/import \{ hilog \} from '@kit\.PerformanceAnalysisKit';?\n/, "const hilog = { error() {}, info() {}, warn() {} };\n")
    .replace(/^import type [\s\S]*?from '[^']+';?\n/m, '')],
  [HOME, 'HomeView.ts', (t) => "import { homeExam } from './ExamState.ts';\nconst hilog = { error() {}, info() {}, warn() {} };\n" +
    themeStub + stripUi(t)],
  ['entry/src/main/ets/pages/MalwareView.ets', 'MalwareView.ts', (t) =>
    "import { examReportOf } from './HomeView.ts';\n" + hilogStub + themeStub + stripUi(t)],
  [CLEAN, 'CleanView.ts', (t) =>
    "import { formatBytes } from './HomeView.ts';\nimport { UNFINISHED, UNREADABLE, jobStateLine } from './MalwareView.ts';\n" +
    hilogStub + themeStub + stripUi(t)],
  [QUARANTINE, 'QuarantineView.ts', (t) =>
    "import { formatBytes } from './HomeView.ts';\nimport { fileNameOf } from './CleanView.ts';\n" +
    hilogStub + themeStub + stripUi(t)],
  ['entry/src/test/CleanPages.test.ets', 'CleanPages.test.ts', (t) => t
    .replace(/^import type [\s\S]*?from '[^']+'\n/gm, '')
    .replace(/import \{ CenterError \} from '\.\.\/main\/ets\/center\/CenterError'\n/, "import { CenterError } from './CenterError.ts';\n")
    .replace(/from '\.\.\/main\/ets\/pages\/(\w+)'/g, "from './$1.ts'")]
]

const dir = mkdtempSync(join(tmpdir(), 'clean-pages-'))
try {
  for (const [from, to, prep] of files) {
    writeFileSync(join(dir, to), prep(read(from)))
  }
  writeFileSync(join(dir, 'main.ts'),
    "import { runCleanPagesChecks } from './CleanPages.test.ts';\nrunCleanPagesChecks();\nprocess.stdout.write('CleanView and QuarantineView checks passed\\n');\n")
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
