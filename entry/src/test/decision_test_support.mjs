// Decide 新增运行时依赖后，所有既有证书与规则检查仍使用同一份源码。
export const decisionFiles = [
  ['entry/src/main/ets/engine/LocalRuleEngine.ets', 'LocalRuleEngine.ts'],
  ['entry/src/main/ets/engine/Lookalike.ets', 'Lookalike.ts'],
  ['entry/src/main/ets/engine/Heuristic.ets', 'Heuristic.ts']
]

const modules = ['Decide', 'LocalRuleEngine', 'Lookalike', 'Heuristic', 'RulePack',
  'Anomaly', 'CenterTypes', 'CenterLimits']

export function prepareDecisionSource(source) {
  return source.replace(/\r\n/g, '\n')
    .replace(/import \{ hilog \} from '@kit\.PerformanceAnalysisKit';\n/g,
      'const hilog = { error(domain, tag, message) { globalThis.__centerHilog ??= []; globalThis.__centerHilog.push(String(message)); }, info() {}, warn() {} };\n')
    .replace(/from '(\.{1,2}\/[^']+)'/g, (original, path) => {
      const name = path.split('/').at(-1)
      return modules.includes(name) ? `from './${name}.ts'` : original
    })
}
