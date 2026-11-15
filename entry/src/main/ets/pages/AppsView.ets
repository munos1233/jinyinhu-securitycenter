import abilityAccessCtrl from '@ohos.abilityAccessCtrl'
import type { Permissions } from '@ohos.abilityAccessCtrl'
import type { common } from '@kit.AbilityKit'
import { Theme } from '../common/Theme'
import type { BundleRow, JobProgress, JobRecord, JobRequest } from '../center/CenterTypes'
import type { Disposition } from '../record/Disposition'
import { ResultStore } from '../record/ResultStore'
import { Writer } from '../record/Writer'
import type { SystemGate } from '../system/SystemGate'
import type { JobQueue } from '../task/JobQueue'
import { QUEUE_KEY } from './HomeView'
import { DISPOSITION_KEY } from './MalwareView'

const LIST_PERMISSION: Permissions = 'ohos.permission.GET_INSTALLED_BUNDLE_LIST'
let declined: boolean = false

class AppsRequest implements JobRequest {
  kind: 'apps' = 'apps'
  scope: 'quick' = 'quick'
  uris: string[] = []
  focus: string = ''
}

@Component
export struct AppsView {
  @StorageLink('center.job.light') @Watch('onProgress') light: JobProgress = {
    jobId: '', kind: 'apps', lane: 'light', state: 'done', done: 0, total: 0, message: ''
  }
  @State rows: BundleRow[] = []
  @State viewing: string = ''
  @State message: string = '尚未读取应用列表'
  @State working: boolean = false

  aboutToAppear(): void {
    let latest: JobRecord | null = null
    for (let job of Writer.loadIndex()) {
      if (job.kind === 'apps' && (latest === null || job.seq >= latest.seq)) latest = job
    }
    if (latest !== null) {
      this.viewing = latest.jobId
      this.reload()
    }
  }

  onProgress(): void {
    if (this.light.kind === 'apps' && this.light.jobId === this.viewing) this.reload()
  }

  build() {
    Column() {
      Text(this.message).fontSize(14).fontColor(Theme.muted).width('100%').padding(16)
      Button('读取应用列表').enabled(!this.working).onClick(() => this.read())
      Scroll() {
        Column() {
          ForEach(this.rows, (row: BundleRow) => {
            Row() {
              Column() {
                Text(row.bundleName).fontSize(16).fontColor(Theme.text)
                Text(row.verdict.reason).fontSize(12).fontColor(Theme.muted)
                Text(levelText(row)).fontSize(12).fontColor(Theme.muted)
              }.layoutWeight(1).alignItems(HorizontalAlign.Start)
              Button('卸载').enabled(!this.working).onClick(() => this.confirm(row))
            }.width('100%').padding(12).backgroundColor(Theme.card).margin({ bottom: 8 })
          }, (row: BundleRow) => row.bundleName)
        }.width('100%').padding(16)
      }.layoutWeight(1).width('100%')
    }.width('100%').height('100%').backgroundColor(Theme.page)
  }

  private async read(): Promise<void> {
    let gate = AppStorage.get<SystemGate>('center.gate')
    if (gate === undefined) {
      this.message = '无法获取应用列表'
      return
    }
    if (gate.bundles().status !== 'ready') {
      if (declined) {
        this.message = '无法获取应用列表'
        return
      }
      this.working = true
      try {
        let result = await abilityAccessCtrl.createAtManager().requestPermissionsFromUser(
          getContext(this) as common.UIAbilityContext, [LIST_PERMISSION])
        if (result.authResults.length === 0 || result.authResults[0] !== 0) {
          declined = true
          this.message = '无法获取应用列表'
          return
        }
        gate.invalidate()
        await gate.probe()
      } catch (err) {
        this.message = '无法获取应用列表'
        return
      } finally {
        this.working = false
      }
    }
    let queue = AppStorage.get<JobQueue>(QUEUE_KEY)
    if (queue === undefined || gate.bundles().status !== 'ready') {
      this.message = '无法获取应用列表'
      return
    }
    let jobId = queue.enqueue(new AppsRequest())
    if (jobId.length === 0) {
      this.message = '正在扫描'
      return
    }
    this.viewing = jobId
    this.rows = []
    this.message = '正在读取应用列表'
  }

  private reload(): void {
    let job = Writer.loadIndex().find((item: JobRecord): boolean => item.jobId === this.viewing && item.kind === 'apps')
    if (job === undefined) return
    if (job.state === 'queued' || job.state === 'running') {
      this.message = '正在读取应用列表'
      return
    }
    let text = ResultStore.read(job.jobId)
    if (text === null) {
      this.rows = []
      this.message = job.summary.length > 0 ? job.summary : '无法获取应用列表'
      return
    }
    try {
      let rows = JSON.parse(text) as BundleRow[]
      if (!(rows instanceof Array)) throw new Error('bad result')
      this.rows = rows
      this.message = job.summary.length > 0 ? job.summary : '应用 ' + rows.length.toString() + ' 项'
    } catch (err) {
      this.rows = []
      this.message = '无法获取应用列表'
    }
  }

  private confirm(row: BundleRow): void {
    AlertDialog.show({ title: '卸载应用', message: '确认卸载 ' + row.bundleName + '？',
      primaryButton: { value: '取消', action: () => {} },
      secondaryButton: { value: '确认卸载', action: () => { this.uninstall(row.bundleName) } } })
  }

  private async uninstall(bundleName: string): Promise<void> {
    let disposition = AppStorage.get<Disposition>(DISPOSITION_KEY)
    if (disposition === undefined) { this.message = '暂不支持'; return }
    this.working = true
    try {
      let result = await disposition.uninstall(this.viewing, bundleName)
      this.reload()
      if (!result.done) this.message = result.message
    } catch (err) {
      this.message = '卸载失败'
    } finally {
      this.working = false
    }
  }
}

function levelText(row: BundleRow): string {
  if (row.verdict.level === 'risk') return '风险'
  if (row.verdict.level === 'suspicious') return '可疑'
  if (row.verdict.level === 'unknown') return '未知'
  return '正常'
}
