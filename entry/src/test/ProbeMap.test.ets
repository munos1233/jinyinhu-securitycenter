import type { CheckStatus } from '../main/ets/center/CenterTypes'
import type {
  EvidenceKind, ProbeId, ProbeResult, ProofLevel, Verdict
} from '../main/ets/probe/ProbeTypes'
import { toCheck } from '../main/ets/center/ProbeMap'

function require(value: boolean, message: string): void {
  if (!value) {
    throw new Error(message)
  }
}

export function probeResult(id: ProbeId, verdict: Verdict, level: ProofLevel,
  kinds: EvidenceKind[], phrase: string = '暂未发现异常'): ProbeResult {
  return { probeId: id, verdict: verdict, phrase: phrase, level: level, imageRole: '',
    evidences: kinds.map((kind: EvidenceKind) => ({ kind: kind, text: '', raw: '', at: '' })), createdAt: '' }
}

function expected(id: ProbeId, verdict: Verdict, level: ProofLevel, kinds: EvidenceKind[]): CheckStatus {
  if (id === 'P1') {
    if (level !== 'L2' || (kinds.indexOf('cmd-transcript') < 0 && kinds.indexOf('sidecar-state') < 0)) {
      return 'unverified'
    }
  }
  if (id === 'P2') {
    for (let kind of kinds) {
      if (kind !== 'errno') {
        return 'unverified'
      }
    }
  }
  if (verdict === 'hit') {
    return 'risk'
  }
  if (verdict === 'passive') {
    return 'unverified'
  }
  if ((id === 'P2' && kinds.length === 0) || (id === 'P3' && level !== 'L2')) {
    return 'unverified'
  }
  return 'ok'
}

function checkResult(run: ProbeResult, status: CheckStatus): void {
  let before = JSON.stringify(run)
  let check = toCheck(run.probeId, run)
  require(check.status === status, run.probeId + '/' + run.verdict + '/' + run.level + ' 映射状态错误')
  require(check.detail === run.phrase && !check.countsTowardState && check.source === 'probe' &&
    check.group === 'protect' && check.action.route === run.probeId && check.action.params === '',
    '原始短语、独立自检身份和路由必须保留，不能参与体检状态')
  require(JSON.stringify(run) === before, 'ProbeMap 不能修改结果、verdict 或证据')
  require(JSON.stringify(toCheck(run.probeId, run)) === JSON.stringify(check), '同一输入必须产生相同映射')
}

export function runProbeMapChecks(): void {
  let ids: ProbeId[] = ['P1', 'P2', 'P3']
  let verdicts: Verdict[] = ['hit', 'blocked', 'passive']
  let levels: ProofLevel[] = ['L1', 'L2', 'L3']
  let evidenceSets: EvidenceKind[][] = [[], ['errno'], ['source-ref'], ['cmd-transcript'],
    ['sidecar-state'], ['bundle-state'], ['hilog-line'], ['errno', 'source-ref'],
    ['errno', 'cmd-transcript'], ['cmd-transcript', 'sidecar-state']]
  for (let id of ids) {
    for (let verdict of verdicts) {
      for (let level of levels) {
        for (let kinds of evidenceSets) {
          checkResult(probeResult(id, verdict, level, kinds), expected(id, verdict, level, kinds))
        }
      }
    }
    let absent = toCheck(id, undefined)
    let empty = toCheck(id, null)
    require(absent.status === 'unverified' && empty.status === 'unverified' &&
      absent.detail === '' && empty.detail === '' && !absent.countsTowardState && !empty.countsTowardState,
      '没有结果对象时必须为未验证，详情为空且不参与状态')
  }
  checkResult(probeResult('P1', 'blocked', 'L1', ['source-ref']), 'unverified')
  checkResult(probeResult('P1', 'blocked', 'L2', ['sidecar-state']), 'ok')
  checkResult(probeResult('P1', 'hit', 'L2', ['cmd-transcript']), 'risk')
  checkResult(probeResult('P2', 'blocked', 'L1', ['errno']), 'ok')
  checkResult(probeResult('P2', 'hit', 'L2', ['errno', 'source-ref']), 'unverified')
  checkResult(probeResult('P3', 'passive', 'L2', ['source-ref']), 'unverified')
  checkResult(probeResult('P3', 'blocked', 'L2', ['source-ref']), 'ok')
  let mismatch = toCheck('P1', probeResult('P2', 'blocked', 'L2', ['cmd-transcript']))
  require(mismatch.status === 'unverified', '不能把另一探针的结果当成本探针的证据')
}
