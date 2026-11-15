import { hilog } from '@kit.PerformanceAnalysisKit';
import { Theme } from '../common/Theme';
import type {
  BundleRow,
  JobKind,
  JobProgress,
  JobRecord,
  JobState,
  Lane,
  ProtectFact,
  ScanHit
} from '../center/CenterTypes';
import { ResultStore } from '../record/ResultStore';
import { Writer } from '../record/Writer';
import { examReportOf, ringText } from './HomeView';
import { UNFINISHED, UNREADABLE, jobStateLine, scanReportOf, scanSummary } from './MalwareView';

const DOMAIN: number = 0x4A59;
const TAG: string = 'Center';
const SCANNING: string = '正在扫描';

export class RiskLine {
  title: string = '';
  detail: string = '';
}

export class JobLook {
  title: string = '作业结果';
  running: boolean = false;
  /** 作业状态那一句在最前，然后是报告自己的完成情况和 note。 */
  lines: string[] = [];
  risks: RiskLine[] = [];
  done: number = 0;
  total: number = 0;
}

class IdleProgress implements JobProgress {
  jobId: string = '';
  kind: JobKind = 'malware';
  lane: Lane = 'heavy';
  state: JobState = 'done';
  done: number = 0;
  total: number = 0;
  message: string = '';
}

class NotedReport {
  complete: boolean = false;
  note: string = '';
}

class NotedShape {
  complete: boolean = false;
  note: string = '';
  hits: Object[] = [];
}

class PermissionShape {
  facts: Object[] = [];
}

@Component
export struct JobResultView {
  jobId: string = '';
  @StorageLink('center.job.heavy') @Watch('onProgress') heavy: JobProgress = new IdleProgress();
  @StorageLink('center.job.light') @Watch('onProgress') light: JobProgress = new IdleProgress();
  @State look: JobLook = new JobLook();

  aboutToAppear(): void {
    this.reload();
  }

  onProgress(): void {
    if (this.heavy.jobId === this.jobId || this.light.jobId === this.jobId) {
      this.reload();
    }
  }

  build() {
    Scroll() {
      Column() {
        Column() {
          Text(this.look.title)
            .fontSize(20)
            .fontWeight(FontWeight.Medium)
            .fontColor(Theme.text)
          if (this.look.running) {
            Progress({ value: this.look.done, total: this.look.total > 0 ? this.look.total : 1, type: ProgressType.Linear })
              .width('100%')
              .color(Theme.accent)
              .margin({ top: 12 })
          }
          ForEach(this.look.lines, (line: string) => {
            Text(line)
              .fontSize(14)
              .fontColor(Theme.muted)
              .margin({ top: 6 })
          }, (line: string) => line)
        }
        .width('100%')
        .padding(20)
        .alignItems(HorizontalAlign.Start)
        .borderRadius(20)
        .backgroundColor(Theme.card)

        if (this.look.risks.length > 0) {
          Text('风险')
            .width('100%')
            .fontSize(14)
            .fontColor(Theme.muted)
            .padding({ left: 12, top: 16, bottom: 8 })
          Column() {
            ForEach(this.look.risks, (risk: RiskLine) => {
              Column() {
                Text(risk.title)
                  .fontSize(16)
                  .fontColor(Theme.danger)
                if (risk.detail.length > 0) {
                  Text(risk.detail)
                    .fontSize(12)
                    .fontColor(Theme.muted)
                    .margin({ top: 2 })
                }
              }
              .width('100%')
              .alignItems(HorizontalAlign.Start)
              .padding({ left: 16, right: 16, top: 10, bottom: 10 })
            }, (risk: RiskLine) => risk.title + risk.detail)
          }
          .width('100%')
          .borderRadius(20)
          .backgroundColor(Theme.card)
        }
      }
      .width('100%')
      .padding({ left: 16, right: 16, top: 8, bottom: 32 })
      .alignItems(HorizontalAlign.Start)
    }
    .width('100%')
    .height('100%')
    .align(Alignment.TopStart)
    .scrollBar(BarState.Off)
    .backgroundColor(Theme.page)
  }

  private reload(): void {
    let record = findRecord(Writer.loadIndex(), this.jobId);
    let text: string | null = null;
    if (record !== null && record.state !== 'queued' && record.state !== 'running') {
      text = ResultStore.read(record.jobId);
    }
    let live = record !== null && record.lane === 'light' ? this.light : this.heavy;
    this.look = jobLook(record, text, live);
  }
}

function findRecord(records: JobRecord[], jobId: string): JobRecord | null {
  if (jobId.length === 0) {
    return null;
  }
  for (let i = 0; i < records.length; i++) {
    if (records[i].jobId === jobId) {
      return records[i];
    }
  }
  return null;
}

export function kindTitle(kind: JobKind): string {
  if (kind === 'exam') {
    return '体检';
  }
  if (kind === 'malware') {
    return '应用信誉';
  }
  if (kind === 'clean') {
    return '清理';
  }
  if (kind === 'duplicate') {
    return '重复文件';
  }
  if (kind === 'large-file') {
    return '大文件';
  }
  if (kind === 'permission') {
    return '权限';
  }
  if (kind === 'apps') {
    return '软件';
  }
  return '防护';
}

function parseObject(text: string | null): Object | null {
  if (text === null) {
    return null;
  }
  try {
    let parsed = JSON.parse(text) as Object;
    return parsed !== null && typeof parsed === 'object' ? parsed : null;
  } catch (err) {
    return null;
  }
}

/** 清理和文件工具：complete 为 false 且 note 为空是写漏，显示「本次扫描未完成」并打 hilog。 */
export function notedLines(complete: boolean, note: string): string[] {
  if (note.length > 0) {
    return [note];
  }
  if (complete) {
    return [];
  }
  hilog.error(DOMAIN, TAG, 'job result incomplete without note');
  return [UNFINISHED];
}

function notedOf(parsed: Object | null): NotedReport | null {
  if (parsed === null || parsed instanceof Array) {
    return null;
  }
  let value = parsed as NotedShape;
  if (typeof value.complete !== 'boolean' || !(value.hits instanceof Array)) {
    return null;
  }
  let noted = new NotedReport();
  noted.complete = value.complete;
  noted.note = typeof value.note === 'string' ? value.note : '';
  return noted;
}

function hitRisks(hits: ScanHit[]): RiskLine[] {
  let out: RiskLine[] = [];
  for (let i = 0; i < hits.length; i++) {
    let hit = hits[i];
    if (hit === null || typeof hit !== 'object' || hit.action !== 'none' || hit.verdict.level !== 'risk') {
      continue;
    }
    let line = new RiskLine();
    line.title = hit.displayName.length > 0 ? hit.displayName : hit.fingerprint.id;
    line.detail = hit.verdict.reason;
    out.push(line);
  }
  return out;
}

/** 解析不出来时返回 false，由调用方写「无法读取该结果」。 */
function fillReport(look: JobLook, kind: JobKind, text: string | null): boolean {
  if (kind === 'exam') {
    let exam = examReportOf(text);
    if (exam === null) {
      return false;
    }
    look.lines.push(ringText(exam.state));
    if (exam.appsComplete !== true) {
      look.lines.push(UNFINISHED);
    }
    for (let i = 0; i < exam.items.length; i++) {
      let item = exam.items[i];
      if (item.status === 'risk' && item.id !== 'exam.malware.apps') {
        let line = new RiskLine();
        line.title = item.title;
        line.detail = item.detail;
        look.risks.push(line);
      }
    }
    look.risks = look.risks.concat(hitRisks(exam.apps));
    return true;
  }
  if (kind === 'malware') {
    let scan = scanReportOf(text);
    if (scan === null) {
      return false;
    }
    look.lines = look.lines.concat(scanSummary(scan));
    look.risks = hitRisks(scan.hits);
    return true;
  }
  let parsed = parseObject(text);
  if (kind === 'clean' || kind === 'duplicate' || kind === 'large-file') {
    let noted = notedOf(parsed);
    if (noted === null) {
      return false;
    }
    look.lines = look.lines.concat(notedLines(noted.complete, noted.note));
    return true;
  }
  if (kind === 'permission') {
    if (parsed === null || parsed instanceof Array || !((parsed as PermissionShape).facts instanceof Array)) {
      return false;
    }
    return true;
  }
  if (!(parsed instanceof Array)) {
    return false;
  }
  if (kind === 'apps') {
    let rows = parsed as BundleRow[];
    for (let i = 0; i < rows.length; i++) {
      let row = rows[i];
      if (row !== null && typeof row === 'object' && row.verdict !== null && typeof row.verdict === 'object' &&
        row.verdict.level === 'risk') {
        let line = new RiskLine();
        line.title = row.bundleName;
        line.detail = row.verdict.reason;
        look.risks.push(line);
      }
    }
    return true;
  }
  let facts = parsed as ProtectFact[];
  for (let i = 0; i < facts.length; i++) {
    let fact = facts[i];
    if (fact !== null && typeof fact === 'object' && fact.status === 'risk') {
      let line = new RiskLine();
      line.title = fact.id;
      line.detail = fact.detail;
      look.risks.push(line);
    }
  }
  return true;
}

/**
 * 不用 JobRecord.state===done 判断扫完。体检读 state 和 appsComplete，其余读报告里的 complete。
 * 中断、失败、取消先写作业状态那一句，再列已经写下的风险。
 */
export function jobLook(record: JobRecord | null, text: string | null, live: JobProgress): JobLook {
  let look = new JobLook();
  if (record === null) {
    look.lines.push(UNREADABLE);
    return look;
  }
  look.title = kindTitle(record.kind);
  if (record.state === 'queued' || record.state === 'running') {
    look.running = true;
    let mine = live.jobId === record.jobId;
    look.lines.push(mine && live.message.length > 0 ? live.message : SCANNING);
    look.done = mine ? live.done : 0;
    look.total = mine ? live.total : 0;
    return look;
  }
  let stop = jobStateLine(record.state);
  if (stop.length > 0) {
    look.lines.push(stop);
  }
  if (!fillReport(look, record.kind, text)) {
    hilog.error(DOMAIN, TAG, 'job result unreadable');
    look.lines = stop.length > 0 ? [stop, UNREADABLE] : [UNREADABLE];
    look.risks = [];
  }
  return look;
}
