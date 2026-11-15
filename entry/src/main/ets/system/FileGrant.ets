import type { BusinessError } from '@ohos.base';
import fileShare from '@ohos.fileshare';
import { common } from '@kit.AbilityKit';
import { preferences } from '@kit.ArkData';
import { hilog } from '@kit.PerformanceAnalysisKit';
import { CenterError } from '../center/CenterError';
import type { FileGrant, FileSource } from '../center/CenterTypes';
import type { InstallerOpen } from '../engine/InstallerScan';
import { grantsKey, preferencesName } from '../record/CenterStore';
import type { GateRefusal, SystemGate } from './SystemGate';

const DOMAIN: number = 0x4A59
const TAG: string = 'Center'

/** 201：权限被拒；202：非系统应用；801：本设备没有该接口。 */
const REFUSED: string[] = ['201', '202', '801']

/** preferences `center.grants` 里的 JSON 文本。没有则为空串。 */
export interface GrantStore {
  load(): string
  save(text: string): void
}

/** 系统的授权持久化。重启后要先激活才能再读。 */
export interface GrantPersist {
  persist(uri: string): Promise<void>
  activate(uri: string): Promise<void>
  release(uri: string): Promise<void>
}

class Grant implements FileGrant {
  uri: string = ''
  displayName: string = ''
  persisted: boolean = false
  at: string = ''
}

/**
 * 选择器给的 uri 只给当次作业用，不落盘。
 * 只有 persistFileGrant() 为 ready、并且用户点了「记住此目录」，才写入 center.grants。
 */
export class FileGrants implements FileSource {
  private gate: SystemGate
  private refusal: GateRefusal
  private store: GrantStore
  private system: GrantPersist
  private now: () => string

  constructor(gate: SystemGate, refusal: GateRefusal, store: GrantStore, system: GrantPersist, now: () => string) {
    this.gate = gate
    this.refusal = refusal
    this.store = store
    this.system = system
    this.now = now
  }

  picked(uri: string, displayName: string): FileGrant {
    return grantOf(uri, displayName, false, this.now())
  }

  async remember(uri: string, displayName: string): Promise<FileGrant> {
    let gate = this.gate.persistFileGrant()
    if (gate.status !== 'ready') {
      throw new CenterError('unsupported', gate.reason)
    }
    if (typeof uri !== 'string' || uri.length === 0) {
      throw new CenterError('io', 'persistPermission:empty-uri')
    }
    try {
      await this.system.persist(uri)
    } catch (err) {
      throw this.failed('persistPermission', err as Object)
    }
    let grant = grantOf(uri, displayName, true, this.now())
    let rows = this.read().filter((row: FileGrant): boolean => row.uri !== uri)
    rows.push(grant)
    this.write(rows)
    return grant
  }

  /** 持久化不可用时不读旧目录，每次都要重新选。 */
  persisted(): FileGrant[] {
    if (this.gate.persistFileGrant().status !== 'ready') {
      return []
    }
    return this.read()
  }

  forget(uri: string): void {
    let rows = this.read()
    let kept = rows.filter((row: FileGrant): boolean => row.uri !== uri)
    if (kept.length === rows.length) {
      return
    }
    this.write(kept)
    this.system.release(uri).catch((err: Object): void => {
      hilog.warn(DOMAIN, TAG, 'grant release failed: %{public}s', codeOf(err))
    })
  }

  /**
   * 激活并用 FileOpen 打开每一条已记住的目录。打不开的删掉，返回被删的 uri。
   * 返回非空时，摘要写「授权已失效」。
   */
  async check(open: InstallerOpen): Promise<string[]> {
    let gone: string[] = []
    let rows = this.persisted()
    for (let i = 0; i < rows.length; i++) {
      let uri = rows[i].uri
      try {
        await this.system.activate(uri)
      } catch (err) {
        let failed = this.failed('activatePermission', err as Object)
        if (failed.code === 'unsupported') {
          return gone
        }
        this.forget(uri)
        gone.push(uri)
        continue
      }
      let opened = open.open(uri, rootOf(uri), false, rows)
      if (opened instanceof CenterError) {
        hilog.warn(DOMAIN, TAG, 'grant open failed: %{public}s', opened.code)
        this.forget(uri)
        gone.push(uri)
        continue
      }
      open.release(opened)
    }
    return gone
  }

  private read(): FileGrant[] {
    let text = ''
    try {
      text = this.store.load()
    } catch (err) {
      hilog.error(DOMAIN, TAG, 'grant store unreadable: %{public}s', codeOf(err as Object))
      return []
    }
    if (typeof text !== 'string' || text.length === 0) {
      return []
    }
    let parsed: Object
    try {
      parsed = JSON.parse(text) as Object
    } catch (err) {
      hilog.error(DOMAIN, TAG, 'grant store not json')
      return []
    }
    if (!(parsed instanceof Array)) {
      hilog.error(DOMAIN, TAG, 'grant store not array')
      return []
    }
    let out: FileGrant[] = []
    let rows = parsed as FileGrant[]
    for (let i = 0; i < rows.length; i++) {
      let row = rows[i]
      if (row === null || typeof row !== 'object' || typeof row.uri !== 'string' || row.uri.length === 0 ||
        row.persisted !== true) {
        continue
      }
      if (out.some((seen: FileGrant): boolean => seen.uri === row.uri)) {
        continue
      }
      out.push(grantOf(row.uri, typeof row.displayName === 'string' ? row.displayName : '', true,
        typeof row.at === 'string' ? row.at : ''))
    }
    return out
  }

  private write(rows: FileGrant[]): void {
    this.store.save(JSON.stringify(rows))
    this.gate.invalidate()
  }

  private failed(api: string, err: Object): CenterError {
    let code = codeOf(err)
    let raw = api + ':' + code
    hilog.error(DOMAIN, TAG, 'grant %{public}s failed: %{public}s', api, code)
    if (REFUSED.indexOf(code) >= 0) {
      this.refusal.refuse('persistFileGrant', raw)
      return new CenterError('unsupported', raw)
    }
    return new CenterError('io', raw)
  }
}

export function rootOf(uri: string): string {
  return uri.startsWith('file:///') ? uri.substring('file://'.length) : uri
}

function grantOf(uri: string, displayName: string, persisted: boolean, at: string): Grant {
  let grant = new Grant()
  grant.uri = uri
  grant.displayName = displayName
  grant.persisted = persisted
  grant.at = at
  return grant
}

function codeOf(err: Object): string {
  try {
    let code = (err as BusinessError).code
    if (code !== undefined && code !== null) {
      return String(code)
    }
  } catch (e) {
  }
  return 'error'
}

class Missing extends Error {
  code: number = 801
}

function policyOf(uri: string): fileShare.PolicyInfo[] {
  return [{ uri: uri, operationMode: fileShare.OperationMode.READ_MODE }]
}

export class SdkGrantPersist implements GrantPersist {
  async persist(uri: string): Promise<void> {
    if (typeof fileShare.persistPermission !== 'function') {
      throw new Missing('missing:persistPermission')
    }
    await fileShare.persistPermission(policyOf(uri))
  }

  async activate(uri: string): Promise<void> {
    if (typeof fileShare.activatePermission !== 'function') {
      throw new Missing('missing:activatePermission')
    }
    await fileShare.activatePermission(policyOf(uri))
  }

  async release(uri: string): Promise<void> {
    if (typeof fileShare.revokePermission !== 'function') {
      throw new Missing('missing:revokePermission')
    }
    await fileShare.revokePermission(policyOf(uri))
  }
}

export class PreferencesGrantStore implements GrantStore {
  private pref: preferences.Preferences

  constructor(ctx: common.Context) {
    this.pref = preferences.getPreferencesSync(ctx, { name: preferencesName })
  }

  load(): string {
    let value = this.pref.getSync(grantsKey, '')
    return typeof value === 'string' ? value : ''
  }

  save(text: string): void {
    this.pref.putSync(grantsKey, text)
    this.pref.flush().catch((err: Object): void => {
      hilog.error(DOMAIN, TAG, 'grant store flush failed: %{public}s', codeOf(err))
    })
  }
}
