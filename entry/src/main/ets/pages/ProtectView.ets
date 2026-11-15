import { Theme } from '../common/Theme'
import type { JobProgress, JobRecord, JobRequest, ProtectFact } from '../center/CenterTypes'
import { RulePack } from '../engine/RulePack'
import { ResultStore } from '../record/ResultStore'
import { Writer } from '../record/Writer'
import type { JobQueue } from '../task/JobQueue'
import { QUEUE_KEY } from './HomeView'

export interface RuleDisplay {
  cloudVersion: string
  publicKeyPresent: boolean
}

class ProtectRequest implements JobRequest {
  kind: 'protect' = 'protect'
  scope: 'quick' = 'quick'
  uris: string[] = []
  focus: string = ''
}

@Component
export struct ProtectView {
  params: string = ''
  onOpen: (route: string, params: string) => void = () => {}
  @StorageLink('center.job.light') @Watch('onProgress') light: JobProgress = {
    jobId: '', kind: 'protect', lane: 'light', state: 'done', done: 0, total: 0, message: ''
  }
  @State viewing: string = ''
  @State facts: ProtectFact[] = []
  @State message: string = '尚未检测'
  @State localVersion: string = 'none'
  @State cloudVersion: string = '无法读取'
  @State keyText: string = '未知'
  private scroller: Scroller = new Scroller()

  aboutToAppear(): void {
    this.localVersion = RulePack.active().rulesVersion
    let rules = AppStorage.get<RuleDisplay>('center.rules.display')
    if (rules !== undefined) {
      this.cloudVersion = rules.cloudVersion.length > 0 ? rules.cloudVersion : '无法读取'
      this.keyText = rules.publicKeyPresent ? '存在' : '不存在'
    }
    this.start()
    if (this.params === 'rules') setTimeout((): void => { this.scroller.scrollEdge(Edge.Bottom) }, 100)
  }

  onProgress(): void {
    if (this.light.kind === 'protect' && this.light.jobId === this.viewing) this.reload()
  }

  build() {
    Scroll(this.scroller) {
      Column() {
        Text(this.message).fontSize(14).fontColor(Theme.muted).width('100%').margin({ bottom: 12 })
        ForEach(this.facts, (fact: ProtectFact) => {
          Column() {
            Text(factTitle(fact.id)).fontSize(16).fontColor(Theme.text).width('100%')
            Text(fact.detail).fontSize(14).fontColor(Theme.muted).width('100%').margin({ top: 5 })
          }.width('100%').padding(16).backgroundColor(Theme.card).margin({ bottom: 8 })
        }, (fact: ProtectFact) => fact.id)
        Column() {
          Text('系统防护自检').fontSize(16).fontColor(Theme.text).width('100%')
          Row() {
            Button('P1').onClick(() => this.onOpen('P1', ''))
            Button('P2').margin({ left: 8 }).onClick(() => this.onOpen('P2', ''))
            Button('P3').margin({ left: 8 }).onClick(() => this.onOpen('P3', ''))
          }.margin({ top: 8 })
        }.width('100%').padding(16).backgroundColor(Theme.card).margin({ bottom: 8 })
        Column() {
          Text('规则版本').fontSize(16).fontColor(Theme.text).width('100%')
          Text('本地版本：' + this.localVersion).fontSize(14).fontColor(Theme.muted).width('100%')
          Text('云版本：' + this.cloudVersion).fontSize(14).fontColor(Theme.muted).width('100%')
          Text('公钥：' + this.keyText).fontSize(14).fontColor(Theme.muted).width('100%')
        }.width('100%').padding(16).backgroundColor(Theme.card)
      }.width('100%').padding(16)
    }.width('100%').height('100%').backgroundColor(Theme.page)
  }

  private start(): void {
    let queue = AppStorage.get<JobQueue>(QUEUE_KEY)
    if (queue === undefined) { this.message = '暂不支持'; return }
    let id = queue.enqueue(new ProtectRequest())
    if (id.length === 0) { this.message = '正在检测'; return }
    this.viewing = id
    this.message = '正在检测'
  }

  private reload(): void {
    let job = Writer.loadIndex().find((row: JobRecord): boolean => row.jobId === this.viewing && row.kind === 'protect')
    if (job === undefined || job.state === 'queued' || job.state === 'running') return
    let text = ResultStore.read(job.jobId)
    if (text === null) { this.message = '暂不支持'; return }
    try {
      let facts = JSON.parse(text) as ProtectFact[]
      if (!(facts instanceof Array)) throw new Error('bad result')
      this.facts = facts
      this.message = job.state === 'done' ? '系统状态' : '检测未完成'
    } catch (err) {
      this.message = '暂不支持'
    }
  }
}

function factTitle(id: string): string {
  if (id === 'pure-mode') return '纯净模式'
  if (id === 'lockdown') return '锁定模式'
  if (id === 'el5') return '文件加密服务'
  return id
}
