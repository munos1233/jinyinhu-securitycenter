import { hilog } from '@kit.PerformanceAnalysisKit'
import { centerErrorMessage } from '../center/CenterError'
import { laneOf } from '../center/CenterLimits'
import type {
  JobKind, JobProgress, JobRecord, JobRequest, JobState, Lane, ScanScope
} from '../center/CenterTypes'
import { Writer } from '../record/Writer'
import type { SystemGate } from '../system/SystemGate'
import { CancelFlag } from './CancelFlag'
import type { Clock, JobBase } from './Contexts'
import { JobEnd } from './JobRunner'
import type { JobRunner } from './JobRunner'

const DOMAIN: number = 0x4A59
const TAG: string = 'Center'

export const LIGHT_KEY: string = 'center.job.light'
export const HEAVY_KEY: string = 'center.job.heavy'

/** 路由参数里的页面定位。jobId 不得等于其中任何一个。 */
const RESERVED: string[] = [
  'quick', 'full', 'custom', 'rules', 'sensitive',
  '位置', '相机', '麦克风', '通讯录', '日历', '短信', '电话', '媒体', '其它'
]
const ANOMALY_PREFIX: string = 'anomaly:'
const ID_TRIES: number = 16

export interface ProgressSink {
  publish(key: string, progress: JobProgress): void
}

export class AppStorageSink implements ProgressSink {
  publish(key: string, progress: JobProgress): void {
    AppStorage.setOrCreate<JobProgress>(key, progress)
  }
}

/** 把 work 排到 UI 线程上执行。 */
export type UiPost = (work: () => void) => void

export function postToUi(work: () => void): void {
  setTimeout(work, 0)
}

export type JobIdSource = (seq: number) => string

class QueueRequest implements JobRequest {
  kind: JobKind = 'exam'
  scope: ScanScope = 'quick'
  uris: string[] = []
  focus: string = ''
}

class QueueRecord implements JobRecord {
  jobId: string = ''
  seq: number = 0
  kind: JobKind = 'exam'
  lane: Lane = 'heavy'
  startedAt: string = ''
  finishedAt: string = ''
  state: JobState = 'queued'
  itemCount: number = 0
  riskCount: number = 0
  summary: string = ''
  resultFile: string = ''
}

class Progress implements JobProgress {
  jobId: string = ''
  kind: JobKind = 'exam'
  lane: Lane = 'heavy'
  state: JobState = 'queued'
  done: number = 0
  total: number = 0
  message: string = ''
}

class Job {
  record: QueueRecord = new QueueRecord()
  request: QueueRequest = new QueueRequest()
  flag: CancelFlag = new CancelFlag()
  gate: Promise<void> = Promise.resolve()
  processed: number = 0
  total: number = 0
  message: string = ''
}

class LaneQueue {
  waiting: Job[] = []
  running: Job | null = null
}

/**
 * 轻、重两条车道。同一车道同时只跑一个作业，轻车道不等待重车道。
 * 索引只经 Writer 写：入队写 queued，开始写 running，收尾写终态。
 */
export class JobQueue {
  private runner: JobRunner
  private gate: SystemGate
  private clock: Clock
  private sink: ProgressSink
  private post: UiPost
  private idOf: JobIdSource
  private light: LaneQueue = new LaneQueue()
  private heavy: LaneQueue = new LaneQueue()

  constructor(runner: JobRunner, gate: SystemGate, clock: Clock, sink: ProgressSink = new AppStorageSink(),
    post: UiPost = postToUi, idOf: JobIdSource = randomJobId) {
    this.runner = runner
    this.gate = gate
    this.clock = clock
    this.sink = sink
    this.post = post
    this.idOf = idOf
  }

  /**
   * 相同请求仍在 queued 或 running 时返回已有 jobId。同 kind 但请求不同时返回空串，不入队，不动那条作业。
   */
  enqueue(request: JobRequest): string {
    let normal = normalizeRequest(request)
    let active = this.find(normal.kind)
    if (active !== null) {
      return sameRequest(active.request, normal) ? active.record.jobId : ''
    }
    let job = new Job()
    job.request = normal
    if (this.gate.stale()) {
      job.gate = this.gate.probe().catch((err: Error) => {
        hilog.error(DOMAIN, TAG, 'gate probe before enqueue failed: %{public}s', err.message)
      })
    }
    job.record = this.admit(normal)
    let lane = this.laneFor(job.record.lane)
    lane.waiting.push(job)
    this.publish(job)
    this.pump(lane)
    return job.record.jobId
  }

  /** 把该作业的 CancelFlag 设为 1。还在排队的直接记 cancelled，itemCount 为 0。 */
  cancel(jobId: string): boolean {
    if (jobId.length === 0) {
      return false
    }
    let lanes: LaneQueue[] = [this.light, this.heavy]
    for (let l = 0; l < lanes.length; l++) {
      let lane = lanes[l]
      if (lane.running !== null && lane.running.record.jobId === jobId) {
        lane.running.flag.cancel()
        return true
      }
      for (let i = 0; i < lane.waiting.length; i++) {
        let job = lane.waiting[i]
        if (job.record.jobId !== jobId) {
          continue
        }
        lane.waiting.splice(i, 1)
        job.flag.cancel()
        this.settle(job, stoppedBeforeStart())
        return true
      }
    }
    return false
  }

  /** 同 kind 正在 queued 或 running 的请求。页面据此写明正在跑的是哪一档。 */
  active(kind: JobKind): JobRequest | null {
    let job = this.find(kind)
    if (job === null) {
      return null
    }
    return copyRequest(job.request)
  }

  private find(kind: JobKind): Job | null {
    let lane = this.laneFor(laneOf(kind))
    if (lane.running !== null && lane.running.request.kind === kind) {
      return lane.running
    }
    for (let i = 0; i < lane.waiting.length; i++) {
      if (lane.waiting[i].request.kind === kind) {
        return lane.waiting[i]
      }
    }
    return null
  }

  private laneFor(lane: Lane): LaneQueue {
    return lane === 'light' ? this.light : this.heavy
  }

  private admit(request: QueueRequest): QueueRecord {
    let record = new QueueRecord()
    record.kind = request.kind
    record.lane = laneOf(request.kind)
    record.state = 'queued'
    record.startedAt = this.clock.nowIso()
    Writer.exclusive(() => {
      let rows = Writer.loadIndex()
      record.seq = Writer.nextSeq(rows)
      record.jobId = this.freshId(record.seq, rows)
      rows.push(copyRecord(record))
      Writer.saveIndex(rows)
    })
    return record
  }

  private freshId(seq: number, rows: JobRecord[]): string {
    for (let i = 0; i < ID_TRIES; i++) {
      let id = this.idOf(seq)
      if (isJobId(id) && !taken(rows, id)) {
        return id
      }
    }
    return randomJobId(seq)
  }

  private pump(lane: LaneQueue): void {
    if (lane.running !== null || lane.waiting.length === 0) {
      return
    }
    let job = lane.waiting.shift() as Job
    lane.running = job
    this.drive(job).catch((err: Error) => {
      hilog.error(DOMAIN, TAG, 'lane %{public}s drive failed: %{public}s', job.record.lane, err.message)
    }).then(() => {
      lane.running = null
      this.pump(lane)
    })
  }

  private async drive(job: Job): Promise<void> {
    await job.gate
    if (job.flag.cancelled()) {
      this.settle(job, stoppedBeforeStart())
      return
    }
    job.record.state = 'running'
    this.store(job.record)
    this.publish(job)
    let end: JobEnd
    try {
      end = await this.runner.run(this.baseOf(job), job.record, () => job.processed)
    } catch (err) {
      end = new JobEnd()
      end.state = 'failed'
      end.itemCount = job.processed
      end.summary = centerErrorMessage('io')
    }
    this.settle(job, end)
  }

  private baseOf(job: Job): JobBase {
    let base: JobBase = {
      job: copyRecord(job.record),
      request: copyRequest(job.request),
      cancel: job.flag,
      clock: this.clock,
      report: (done: number, total: number, message: string): void => {
        job.processed = done
        job.total = total
        job.message = message
        this.publish(job)
      }
    }
    return base
  }

  private settle(job: Job, end: JobEnd): void {
    job.record.state = end.state
    job.record.itemCount = end.itemCount
    job.record.riskCount = end.riskCount
    job.record.summary = end.summary
    job.record.finishedAt = this.clock.nowIso()
    job.message = end.summary
    this.store(job.record)
    if (end.state === 'cancelled') {
      Writer.settleExam(job.record)
    }
    this.publish(job)
  }

  private store(record: QueueRecord): void {
    Writer.exclusive(() => {
      let rows = Writer.loadIndex()
      let found = false
      for (let i = 0; i < rows.length; i++) {
        if (rows[i].jobId === record.jobId) {
          rows[i] = copyRecord(record)
          found = true
        }
      }
      if (!found) {
        rows.push(copyRecord(record))
      }
      Writer.saveIndex(rows)
    })
  }

  /** 快照现在取，写 AppStorage 排到 UI 线程。Worker 不写 AppStorage。 */
  private publish(job: Job): void {
    let progress = new Progress()
    progress.jobId = job.record.jobId
    progress.kind = job.record.kind
    progress.lane = job.record.lane
    progress.state = job.record.state
    progress.done = job.processed
    progress.total = job.total
    progress.message = job.message
    let key = job.record.lane === 'light' ? LIGHT_KEY : HEAVY_KEY
    this.post(() => {
      this.sink.publish(key, progress)
    })
  }
}

export function randomJobId(seq: number): string {
  let hex = ''
  for (let i = 0; i < 8; i++) {
    hex += Math.floor(Math.random() * 16).toString(16)
  }
  return 'job-' + seq.toString() + '-' + hex
}

export function isJobId(id: string): boolean {
  if (id.length === 0 || id.indexOf(ANOMALY_PREFIX) === 0) {
    return false
  }
  return RESERVED.indexOf(id) < 0
}

/** 去掉空串、去重、按 UTF-8 字节序排序。UTF-8 字节序与码点序一致。 */
export function normalizeUris(uris: string[]): string[] {
  let kept: string[] = []
  for (let i = 0; i < uris.length; i++) {
    if (uris[i].length > 0 && kept.indexOf(uris[i]) < 0) {
      kept.push(uris[i])
    }
  }
  kept.sort(utf8Compare)
  return kept
}

export function utf8Compare(a: string, b: string): number {
  let i = 0
  let j = 0
  while (i < a.length && j < b.length) {
    let x = a.codePointAt(i) as number
    let y = b.codePointAt(j) as number
    if (x !== y) {
      return x < y ? -1 : 1
    }
    i += x > 0xFFFF ? 2 : 1
    j += y > 0xFFFF ? 2 : 1
  }
  let restA = a.length - i
  let restB = b.length - j
  if (restA === restB) {
    return 0
  }
  return restA < restB ? -1 : 1
}

/** kind、scope、focus 全等，uris 规范化后逐项全等。 */
export function sameRequest(left: JobRequest, right: JobRequest): boolean {
  if (left.kind !== right.kind || left.scope !== right.scope || left.focus !== right.focus) {
    return false
  }
  let a = normalizeUris(left.uris)
  let b = normalizeUris(right.uris)
  if (a.length !== b.length) {
    return false
  }
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) {
      return false
    }
  }
  return true
}

function normalizeRequest(request: JobRequest): QueueRequest {
  let normal = new QueueRequest()
  normal.kind = request.kind
  normal.scope = request.scope
  normal.uris = normalizeUris(request.uris)
  normal.focus = request.focus
  return normal
}

function copyRequest(request: JobRequest): QueueRequest {
  let copy = new QueueRequest()
  copy.kind = request.kind
  copy.scope = request.scope
  copy.uris = request.uris.slice()
  copy.focus = request.focus
  return copy
}

function copyRecord(record: JobRecord): QueueRecord {
  let copy = new QueueRecord()
  copy.jobId = record.jobId
  copy.seq = record.seq
  copy.kind = record.kind
  copy.lane = record.lane
  copy.startedAt = record.startedAt
  copy.finishedAt = record.finishedAt
  copy.state = record.state
  copy.itemCount = record.itemCount
  copy.riskCount = record.riskCount
  copy.summary = record.summary
  copy.resultFile = record.resultFile
  return copy
}

function taken(rows: JobRecord[], id: string): boolean {
  for (let i = 0; i < rows.length; i++) {
    if (rows[i].jobId === id) {
      return true
    }
  }
  return false
}

function stoppedBeforeStart(): JobEnd {
  let end = new JobEnd()
  end.state = 'cancelled'
  end.itemCount = 0
  end.summary = centerErrorMessage('cancelled')
  return end
}
