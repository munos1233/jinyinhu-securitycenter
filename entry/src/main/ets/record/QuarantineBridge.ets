import { CenterError } from '../center/CenterError'
import type { FileGrant, QuarantineEntry } from '../center/CenterTypes'
import type { SystemGate } from '../system/SystemGate'
import type { QuarantineDoor } from './Disposition'
import { Quarantine } from './Quarantine'

export interface QuarantineGrants {
  persisted(): FileGrant[]
  check(): Promise<void>
}

export interface SessionRoots {
  roots(jobId: string): string[]
}

/** Only paths covered by an active persisted grant or this job's picker are accepted. */
export class QuarantineBridge implements QuarantineDoor {
  private box: Quarantine
  private grants: QuarantineGrants
  private gate: SystemGate
  private session: SessionRoots

  constructor(box: Quarantine, grants: QuarantineGrants, gate: SystemGate, session: SessionRoots) {
    this.box = box
    this.grants = grants
    this.gate = gate
    this.session = session
  }

  async put(from: string, size: number, sha256: string, reason: string, jobId: string): Promise<CenterError | QuarantineEntry> {
    if (this.gate.huks().status !== 'ready') return new CenterError('unsupported', 'huks')
    try {
      await this.grants.check()
    } catch (err) {
      return new CenterError('unsupported', 'file-grant')
    }
    let roots = this.session.roots(jobId).slice()
    for (let grant of this.grants.persisted()) roots.push(grant.uri)
    let root = grantedRoot(from, roots)
    if (root.length === 0) return new CenterError('rejected-system-path', from)
    return await this.box.put(from, size, sha256, reason, root, true)
  }

  list(): QuarantineEntry[] | null { return this.box.list() }
  async restore(id: string, root: string, choose: string): Promise<CenterError | null> {
    if (this.gate.huks().status !== 'ready') return new CenterError('unsupported', 'huks')
    return await this.box.restore(id, rootPath(root), choose)
  }
  async discard(id: string): Promise<CenterError | null> { return await this.box.discard(id) }
}

export function grantedRoot(from: string, roots: string[]): string {
  let target = rootPath(from)
  if (!target.startsWith('/')) return ''
  let best = ''
  for (let uri of roots) {
    let root = rootPath(uri)
    if (!root.startsWith('/')) continue
    while (root.length > 1 && root.endsWith('/')) root = root.substring(0, root.length - 1)
    if ((target === root || target.startsWith(root === '/' ? '/' : root + '/')) && root.length > best.length) best = root
  }
  return best
}

function rootPath(uri: string): string {
  return uri.startsWith('file:///') ? uri.substring('file://'.length) : uri
}
