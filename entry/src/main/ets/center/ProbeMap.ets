import type { CheckItem, CheckStatus } from './CenterTypes'
import type { Evidence, ProbeResult } from '../probe/ProbeTypes'

export function toCheck(probeId: string, result: ProbeResult | null | undefined): CheckItem {
  let status: CheckStatus = 'unverified'
  if (result !== undefined && result !== null && result.probeId === probeId) {
    if (probeId === 'P1') {
      let sidecar = result.evidences.some((evidence: Evidence): boolean =>
        evidence.kind === 'cmd-transcript' || evidence.kind === 'sidecar-state')
      if (sidecar && result.level === 'L2') {
        if (result.verdict === 'hit') {
          status = 'risk'
        } else if (result.verdict === 'blocked') {
          status = 'ok'
        }
      }
    } else if (probeId === 'P2') {
      let errnoOnly = result.evidences.every((evidence: Evidence): boolean => evidence.kind === 'errno')
      if (errnoOnly && result.verdict === 'blocked' && result.evidences.length > 0) {
        status = 'ok'
      } else if (errnoOnly && result.verdict === 'hit') {
        status = 'risk'
      }
    } else if (probeId === 'P3') {
      if (result.verdict === 'hit') {
        status = 'risk'
      } else if (result.verdict === 'blocked' && result.level === 'L2') {
        status = 'ok'
      }
    }
  }
  return {
    id: probeId, title: probeId, group: 'protect', status: status, kind: 'state', source: 'probe',
    detail: result === undefined || result === null ? '' : result.phrase,
    action: { route: probeId, params: '' }, countsTowardState: false
  }
}
