import { hilog } from '@kit.PerformanceAnalysisKit';
import { Theme } from '../common/Theme';
import { StatusLine } from '../components/UiParts';
import type {
  CheckItem,
  ExamReport,
  ExamState,
  ExamSummary,
  JobKind,
  JobProgress,
  JobRecord,
  JobRequest,
  JobState,
  Lane,
  ScanScope
} from '../center/CenterTypes';
import { homeExam } from '../feature/exam/ExamState';
import type { HomeCandidate } from '../feature/exam/ExamState';
import { LiveStore, ScanProgress } from '../model/LiveStore';
import { PROBE_IDS, ProbeTone, probeName, probeTone, toneLabel, visibleRun } from '../model/ProbeStatus';
import { ANOMALY_PHRASE, NO_ANOMALY_PHRASE, SYSTEM_REJECT_PHRASE } from '../probe/ProbeTypes';
import { ProbeShelf, emptyProbeShelf } from '../probe/ProbeTypes';
import { ResultStore } from '../record/ResultStore';
import { Writer } from '../record/Writer';
import type { JobQueue } from '../task/JobQueue';
import { DoppelUninstall } from './DoppelUninstall';
import { Finding, Findings } from '../report/Findings';

const DOMAIN = 0x4A59;
const TAG = 'HomeView';
const HERO_SIZE: number = 168;

/** 组合根把 JobQueue 放在这个 AppStorage 键下。没有时首页不能开始体检。 */
export const QUEUE_KEY: string = 'center.queue';
export const NOT_RUN: string = '尚未体检';
export const NOT_CHECKED: string = '尚未检测';
const PROTECT_IDS: string[] = ['exam.protect.pure-mode', 'exam.protect.lockdown', 'exam.protect.el5'];
const APPS_ID: string = 'exam.malware.apps';
const OFFLINE: string = '未联网';
const NO_CLOUD: string = '云端暂无结果';
const UNCONFIRMED: string = '部分应用暂无法确认';

export class HomeLook {
  running: boolean = false;
  /** 正在跑的体检，或首页采用的那份。点圆环进体检页用它。 */
  openId: string = '';
  state: ExamState = 'not-run';
  headline: string = NOT_RUN;
  notes: string[] = [];
  numbers: string[] = [];
  protect: string = NOT_CHECKED;
  busy: string = '';
  done: number = 0;
  total: number = 0;
}

class IdleProgress implements JobProgress {
  jobId: string = '';
  kind: JobKind = 'exam';
  lane: Lane = 'heavy';
  state: JobState = 'done';
  done: number = 0;
  total: number = 0;
  message: string = '';
}

class ExamRequest implements JobRequest {
  kind: JobKind = 'exam';
  scope: ScanScope = 'quick';
  uris: string[] = [];
  focus: string = '';
}

class Candidate implements HomeCandidate {
  record: JobRecord;
  report: ExamReport | null;

  constructor(record: JobRecord, report: ExamReport | null) {
    this.record = record;
    this.report = report;
  }
}

@Component
export struct HomeView {
  @StorageLink('probeShelf') probeShelf: ProbeShelf = emptyProbeShelf();
  @StorageLink('findings') findings: Finding[] = [];
  @StorageLink('scanProgress') scanProgress: ScanProgress = new ScanProgress();
  @StorageLink('statusLine') statusLine: string = '';
  @StorageLink('center.job.heavy') @Watch('onHeavy') heavy: JobProgress = new IdleProgress();
  @State look: HomeLook = new HomeLook();
  onOpen: (route: string, params: string) => void = (route: string, params: string) => {
    hilog.info(DOMAIN, TAG, 'open %{public}s', route);
  };

  aboutToAppear(): void {
    this.reload();
  }

  onHeavy(): void {
    this.reload();
  }

  build() {
    Scroll() {
      Column() {
        Text('安全中心')
          .width('100%')
          .fontSize(30)
          .fontWeight(FontWeight.Bold)
          .fontColor(Theme.text)
          .padding({ left: 24, right: 24, top: 24 })

        this.hero()

        this.featureGrid()

        DoppelUninstall()

        this.groupTitle('系统防护自检')
        Row() {
          ForEach(PROBE_IDS, (id: string) => {
            this.checkTile(id)
          }, (id: string) => id + probeTone(this.probeShelf, id))
        }
        .width('100%')
        .padding({ top: 8, bottom: 8 })
        .borderRadius(20)
        .backgroundColor(Theme.card)
        .shadow({ radius: 24, color: '#0A141619', offsetY: 6 })

        this.groupTitle('安全管理')
        Column() {
          this.listRow($r('sys.symbol.doc_text_badge_clock_fill'), Theme.danger, '风险记录', this.recordHint(), 'ledger', true)
          this.listRow($r('sys.symbol.doc_text_badge_checkmark_fill'), Theme.accent, '安全报告', '检测概览与系统镜像', 'report', true)
          this.listRow($r('sys.symbol.folder_fill'), Theme.warn, '记录导入导出', '导出检测记录，或导入已有报告', 'archive', true)
          this.listRow($r('sys.symbol.phone_fill'), Theme.muted, '设备信息', this.deviceHint(), 'device', true)
          this.listRow($r('sys.symbol.info_circle_fill'), Theme.ok, '安全说明', '检测范围、威胁与组件清单', 'about', false)
        }
        .width('100%')
        .borderRadius(20)
        .backgroundColor(Theme.card)
        .shadow({ radius: 24, color: '#0A141619', offsetY: 6 })

        StatusLine({ text: this.statusLine })
          .margin({ top: 8 })
      }
      .width('100%')
      .padding({ left: 16, right: 16, bottom: 32 })
      .alignItems(HorizontalAlign.Start)
    }
    .width('100%')
    .height('100%')
    .align(Alignment.TopStart)
    .scrollBar(BarState.Off)
    .backgroundColor(Theme.page)
  }

  @Builder
  hero() {
    Column() {
      Stack({ alignContent: Alignment.Center }) {
        Column()
          .width(HERO_SIZE)
          .height(HERO_SIZE)
          .borderRadius(HERO_SIZE / 2)
          .backgroundColor(this.heroSoft())
        Column()
          .width(HERO_SIZE - 28)
          .height(HERO_SIZE - 28)
          .borderRadius((HERO_SIZE - 28) / 2)
          .backgroundColor(Theme.page)
        Column()
          .width(HERO_SIZE - 56)
          .height(HERO_SIZE - 56)
          .borderRadius((HERO_SIZE - 56) / 2)
          .border({ width: 8, color: this.heroColor() })
          .backgroundColor(this.heroSoft())
        if (this.look.running) {
          Progress({ value: this.look.done, total: this.look.total > 0 ? this.look.total : 4, type: ProgressType.Ring })
            .width(HERO_SIZE)
            .height(HERO_SIZE)
            .style({ strokeWidth: 6 })
            .color(Theme.accent)
            .backgroundColor(Color.Transparent)
        }
      }
      .width(HERO_SIZE)
      .height(HERO_SIZE)
      .onClick(() => {
        this.openExam();
      })

      Text(this.look.headline)
        .fontSize(22)
        .fontWeight(FontWeight.Medium)
        .fontColor(this.look.running ? Theme.text : this.heroColor())
        .margin({ top: 20 })

      ForEach(this.look.notes, (note: string) => {
        Text(note)
          .fontSize(14)
          .fontColor(Theme.muted)
          .margin({ top: 6 })
      }, (note: string) => note)

      ForEach(this.look.numbers, (line: string) => {
        Text(line)
          .fontSize(14)
          .fontColor(Theme.text)
          .margin({ top: 6 })
      }, (line: string) => line)

      if (this.look.busy.length > 0) {
        Text(this.look.busy)
          .fontSize(13)
          .fontColor(Theme.accent)
          .margin({ top: 6 })
      }

      Button(this.look.running ? '体检中…' : '开始体检')
        .type(ButtonType.Capsule)
        .width(200)
        .height(40)
        .fontSize(16)
        .fontWeight(FontWeight.Medium)
        .fontColor(Theme.onAccent)
        .backgroundColor(Theme.accent)
        .enabled(!this.look.running)
        .opacity(this.look.running ? 0.4 : 1)
        .margin({ top: 24 })
        .onClick(() => {
          this.startExam();
        })
    }
    .width('100%')
    .alignItems(HorizontalAlign.Center)
    .padding({ top: 24, bottom: 16 })
  }

  @Builder
  featureGrid() {
    Column() {
      Row() {
        this.featureTile($r('sys.symbol.doc_text_badge_checkmark_fill'), '应用信誉', 'malware')
        this.featureTile($r('sys.symbol.folder_fill'), '清理', 'clean')
        this.featureTile($r('sys.symbol.hand_tap_fill'), '权限', 'permission')
        this.featureTile($r('sys.symbol.phone_fill'), '软件', 'apps')
      }
      .width('100%')
      .padding({ top: 8, bottom: 8 })

      Divider()
        .color(Theme.line)
        .strokeWidth(0.5)
        .margin({ left: 16, right: 16 })

      Row() {
        SymbolGlyph($r('sys.symbol.lock_shield_fill'))
          .fontSize(22)
          .fontColor([Theme.accent])
        Text('防护')
          .fontSize(16)
          .fontColor(Theme.text)
          .margin({ left: 12 })
        Text(this.look.protect)
          .layoutWeight(1)
          .fontSize(13)
          .fontColor(Theme.muted)
          .textAlign(TextAlign.End)
          .maxLines(1)
          .textOverflow({ overflow: TextOverflow.Ellipsis })
          .margin({ left: 12 })
        SymbolGlyph($r('sys.symbol.chevron_right'))
          .fontSize(18)
          .fontColor([Theme.line])
      }
      .width('100%')
      .height(56)
      .padding({ left: 16, right: 16 })
      .alignItems(VerticalAlign.Center)
      .onClick(() => {
        this.onOpen('protect', '');
      })
    }
    .width('100%')
    .borderRadius(20)
    .backgroundColor(Theme.card)
    .shadow({ radius: 24, color: '#0A141619', offsetY: 6 })
  }

  @Builder
  featureTile(icon: Resource, title: string, route: string) {
    Column() {
      Stack() {
        SymbolGlyph(icon)
          .fontSize(26)
          .fontColor([Theme.accent])
      }
      .width(48)
      .height(48)
      .borderRadius(12)
      .backgroundColor(Theme.accentSoft)

      Text(title)
        .fontSize(14)
        .fontColor(Theme.text)
        .maxLines(1)
        .margin({ top: 10 })
    }
    .layoutWeight(1)
    .padding({ top: 12, bottom: 12 })
    .alignItems(HorizontalAlign.Center)
    .onClick(() => {
      this.onOpen(route, '');
    })
  }

  @Builder
  groupTitle(title: string) {
    Text(title)
      .width('100%')
      .fontSize(14)
      .fontColor(Theme.muted)
      .padding({ left: 12, top: 16, bottom: 8 })
  }

  @Builder
  checkTile(id: string) {
    Column() {
      Stack() {
        if (id === 'P1') {
          SymbolGlyph($r('sys.symbol.arrow_down_shield'))
            .fontSize(26)
            .fontColor([Theme.accent])
        } else if (id === 'P2') {
          SymbolGlyph($r('sys.symbol.lock_shield_fill'))
            .fontSize(26)
            .fontColor([Theme.accent])
        } else {
          SymbolGlyph($r('sys.symbol.hand_tap_fill'))
            .fontSize(26)
            .fontColor([Theme.accent])
        }
      }
      .width(48)
      .height(48)
      .borderRadius(12)
      .backgroundColor(Theme.accentSoft)

      Text(probeName(id))
        .fontSize(14)
        .fontColor(Theme.text)
        .maxLines(1)
        .margin({ top: 10 })
      Text(this.tileText(id))
        .fontSize(12)
        .fontColor(this.tileTone(id))
        .maxLines(1)
        .margin({ top: 4 })
    }
    .layoutWeight(1)
    .padding({ top: 12, bottom: 12 })
    .alignItems(HorizontalAlign.Center)
    .onClick(() => {
      this.onOpen(id, '');
    })
  }

  @Builder
  listRow(icon: Resource, color: string, title: string, hint: string, route: string, divided: boolean) {
    Column() {
      Row() {
        SymbolGlyph(icon)
          .fontSize(22)
          .fontColor([Theme.accent])
        Column()
          .width(6)
          .height(6)
          .borderRadius(3)
          .backgroundColor(color)
          .margin({ left: 8 })

        Column() {
          Text(title)
            .fontSize(16)
            .fontColor(Theme.text)
          Text(hint)
            .fontSize(12)
            .fontColor(Theme.muted)
            .maxLines(1)
            .textOverflow({ overflow: TextOverflow.Ellipsis })
            .margin({ top: 2 })
        }
        .layoutWeight(1)
        .alignItems(HorizontalAlign.Start)
        .margin({ left: 12 })

        SymbolGlyph($r('sys.symbol.chevron_right'))
          .fontSize(18)
          .fontColor([Theme.line])
      }
      .width('100%')
      .height(64)
      .padding({ left: 16, right: 16 })
      .alignItems(VerticalAlign.Center)

      if (divided) {
        Divider()
          .color(Theme.line)
          .strokeWidth(0.5)
          .margin({ left: 64, right: 16 })
      }
    }
    .width('100%')
    .onClick(() => {
      this.onOpen(route, '');
    })
  }

  private reload(): void {
    this.look = homeLook(loadExamRows(), this.heavy);
  }

  private startExam(): void {
    if (this.look.running) {
      return;
    }
    let queue = AppStorage.get<JobQueue>(QUEUE_KEY);
    if (queue === undefined) {
      hilog.error(DOMAIN, TAG, 'exam queue not ready');
      LiveStore.setStatus('暂不支持');
      return;
    }
    let jobId = queue.enqueue(examRequest());
    this.reload();
    if (jobId.length > 0) {
      this.onOpen('exam', jobId);
    }
  }

  private openExam(): void {
    if (this.look.openId.length > 0) {
      this.onOpen('exam', this.look.openId);
    }
  }

  private heroColor(): string {
    if (this.look.running) {
      return Theme.accent;
    }
    return stateColor(this.look.state);
  }

  private heroSoft(): string {
    if (this.look.running) {
      return Theme.accentSoft;
    }
    if (this.look.state === 'risk') {
      return Theme.dangerSoft;
    }
    if (this.look.state === 'incomplete') {
      return Theme.warnSoft;
    }
    if (this.look.state === 'clear') {
      return Theme.okSoft;
    }
    return Theme.accentSoft;
  }

  private tileText(id: string): string {
    if (this.scanProgress.running && this.scanProgress.probeId === id) {
      return '检测中';
    }
    let run = visibleRun(this.probeShelf, id);
    if (run !== undefined && (run.phrase === SYSTEM_REJECT_PHRASE || run.phrase === ANOMALY_PHRASE ||
      run.phrase === NO_ANOMALY_PHRASE)) {
      return run.phrase;
    }
    return toneLabel(probeTone(this.probeShelf, id));
  }

  private tileTone(id: string): string {
    if (this.scanProgress.running && this.scanProgress.probeId === id) {
      return Theme.accent;
    }
    let tone = probeTone(this.probeShelf, id);
    if (tone === 'none') {
      return Theme.muted;
    }
    return toneColor(tone);
  }

  private recordHint(): string {
    let count = this.findings.length >= 0 ? Findings.list().length : 0;
    if (count === 0) {
      return '暂无记录';
    }
    return count.toString() + ' 条检测记录';
  }

  private deviceHint(): string {
    return this.probeShelf.boardUdid.length > 0 ? '设备已登记' : '设备未登记';
  }
}

function loadExamRows(): HomeCandidate[] {
  let rows: HomeCandidate[] = [];
  let records = Writer.loadIndex();
  for (let i = 0; i < records.length; i++) {
    if (records[i].kind !== 'exam') {
      continue;
    }
    let settled = records[i].state !== 'queued' && records[i].state !== 'running';
    let report = settled ? examReportOf(ResultStore.read(records[i].jobId)) : null;
    rows.push(new Candidate(records[i], report));
  }
  return rows;
}

function stateColor(state: ExamState): string {
  if (state === 'risk') {
    return Theme.danger;
  }
  if (state === 'incomplete') {
    return Theme.warn;
  }
  if (state === 'clear') {
    return Theme.ok;
  }
  return Theme.accent;
}

function toneColor(tone: ProbeTone): string {
  if (tone === 'risk') {
    return Theme.danger;
  }
  if (tone === 'note' || tone === 'fault') {
    return Theme.warn;
  }
  if (tone === 'safe') {
    return Theme.ok;
  }
  return Theme.accent;
}

function tileColor(id: string): string {
  if (id === 'P1') {
    return '#0A59F7';
  }
  if (id === 'P2') {
    return '#00A6A6';
  }
  return '#F7931E';
}

export function examRequest(): JobRequest {
  return new ExamRequest();
}

/** 圆环只有四句，不带数字。 */
export function ringText(state: ExamState): string {
  if (state === 'risk') {
    return '有风险';
  }
  if (state === 'incomplete') {
    return '未完成';
  }
  if (state === 'clear') {
    return '暂无风险';
  }
  return NOT_RUN;
}

/** 结果文件解析不成 ExamReport 时为 null，不当作空的通过。 */
export function examReportOf(text: string | null): ExamReport | null {
  if (text === null) {
    return null;
  }
  let parsed: ExamReport;
  try {
    parsed = JSON.parse(text) as ExamReport;
  } catch (err) {
    return null;
  }
  if (parsed === null || typeof parsed !== 'object') {
    return null;
  }
  if (parsed.state !== 'not-run' && parsed.state !== 'risk' && parsed.state !== 'incomplete' &&
    parsed.state !== 'clear') {
    return null;
  }
  if (!(parsed.items instanceof Array) || !(parsed.apps instanceof Array) || parsed.summary === null ||
    typeof parsed.summary !== 'object') {
    return null;
  }
  let summary = parsed.summary;
  summary.riskApps = typeof summary.riskApps === 'number' ? summary.riskApps : 0;
  summary.suspiciousApps = typeof summary.suspiciousApps === 'number' ? summary.suspiciousApps : 0;
  summary.cleanableBytes = typeof summary.cleanableBytes === 'number' ? summary.cleanableBytes : 0;
  summary.cleanableKnown = summary.cleanableKnown === true;
  summary.cleanableNote = typeof summary.cleanableNote === 'string' ? summary.cleanableNote : '';
  summary.sensitiveApps = typeof summary.sensitiveApps === 'number' ? summary.sensitiveApps : 0;
  summary.sensitiveKnown = summary.sensitiveKnown === true;
  parsed.skipped = typeof parsed.skipped === 'number' ? parsed.skipped : 0;
  parsed.advice = typeof parsed.advice === 'number' ? parsed.advice : 0;
  return parsed;
}

function findItem(items: CheckItem[], id: string): CheckItem | null {
  for (let i = 0; i < items.length; i++) {
    if (items[i].id === id) {
      return items[i];
    }
  }
  return null;
}

function hasText(text: string, part: string): boolean {
  return text.indexOf(part) >= 0;
}

/** 第 8 节写在圆环下方的附加句。不改圆环。 */
export function examNotes(report: ExamReport): string[] {
  let notes: string[] = [];
  let apps = findItem(report.items, APPS_ID);
  if (report.state === 'clear') {
    notes.push('本次只检查了已安装应用');
    if (report.skipped > 0) {
      notes.push('另有 ' + report.skipped.toString() + ' 项暂无法检查');
    }
    if (report.advice > 0) {
      notes.push('有 ' + report.advice.toString() + ' 条建议');
    }
    if (report.summary.suspiciousApps > 0) {
      notes.push('发现 ' + report.summary.suspiciousApps.toString() + ' 个可疑应用');
    }
    if (apps !== null && apps.status === 'ok' && hasText(apps.detail, OFFLINE)) {
      notes.push('部分应用未联网，结果来自本地');
    }
    if (apps !== null && apps.status === 'ok' && hasText(apps.detail, NO_CLOUD)) {
      notes.push('部分应用云端暂无结果');
    }
  }
  if (apps !== null && hasText(apps.detail, UNCONFIRMED)) {
    notes.push(UNCONFIRMED);
  }
  return notes;
}

export function formatBytes(bytes: number): string {
  let units: string[] = ['B', 'KB', 'MB', 'GB', 'TB'];
  let value = bytes > 0 ? bytes : 0;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value = value / 1024;
    unit++;
  }
  if (unit === 0) {
    return Math.round(value).toString() + ' B';
  }
  return (Math.round(value * 10) / 10).toString() + ' ' + units[unit];
}

/** 圆环之外的三句数字。标志为 false 的那句不出现，不显示 0。 */
export function summaryLines(summary: ExamSummary): string[] {
  let lines: string[] = [];
  lines.push('风险应用 ' + summary.riskApps.toString() + ' 个');
  if (summary.cleanableKnown) {
    let line = '可清理 ' + formatBytes(summary.cleanableBytes);
    if (summary.cleanableNote.length > 0) {
      line += '，' + summary.cleanableNote;
    }
    lines.push(line);
  }
  if (summary.sensitiveKnown) {
    lines.push(summary.sensitiveApps.toString() + ' 个应用持有敏感权限');
  }
  return lines;
}

/** 第五行只读这份体检里的纯净模式、lockdown、el5。 */
export function protectLine(items: CheckItem[]): string {
  let ok = 0;
  let risk = 0;
  let other = 0;
  let seen = 0;
  for (let i = 0; i < PROTECT_IDS.length; i++) {
    let item = findItem(items, PROTECT_IDS[i]);
    if (item === null) {
      continue;
    }
    seen++;
    if (item.status === 'ok') {
      ok++;
    } else if (item.status === 'risk') {
      risk++;
    } else {
      other++;
    }
  }
  if (seen === 0) {
    return NOT_CHECKED;
  }
  return '正常 ' + ok.toString() + ' · 有风险 ' + risk.toString() + ' · 暂不支持 ' + other.toString();
}

function active(state: JobState): boolean {
  return state === 'queued' || state === 'running';
}

function runningExamId(rows: HomeCandidate[], heavy: JobProgress): string {
  if (heavy.kind === 'exam' && heavy.jobId.length > 0 && active(heavy.state)) {
    return heavy.jobId;
  }
  for (let i = 0; i < rows.length; i++) {
    if (rows[i].record.kind === 'exam' && active(rows[i].record.state)) {
      return rows[i].record.jobId;
    }
  }
  return '';
}

function reportOf(rows: HomeCandidate[], jobId: string): ExamReport | null {
  for (let i = 0; i < rows.length; i++) {
    if (rows[i].record.jobId === jobId) {
      return rows[i].report;
    }
  }
  return null;
}

/**
 * 首页顶部。体检在 queued 或 running 时只显示这条作业的 message。
 * 否则圆环、附加句、三句数字和第五行都来自 homeExam() 采用的同一份。
 */
export function homeLook(rows: HomeCandidate[], heavy: JobProgress): HomeLook {
  let look = new HomeLook();
  let running = runningExamId(rows, heavy);
  if (running.length > 0) {
    look.running = true;
    look.openId = running;
    look.headline = heavy.jobId === running ? heavy.message : '';
    look.done = heavy.jobId === running ? heavy.done : 0;
    look.total = heavy.jobId === running ? heavy.total : 0;
    return look;
  }
  if (heavy.kind !== 'exam' && heavy.jobId.length > 0 && active(heavy.state)) {
    look.busy = heavy.message;
  }
  let picked = homeExam(rows);
  if (picked.jobId.length === 0) {
    return look;
  }
  let report = reportOf(rows, picked.jobId);
  if (report === null) {
    return look;
  }
  look.openId = picked.jobId;
  look.state = report.state;
  look.headline = ringText(report.state);
  if (picked.banner.length > 0) {
    look.notes.push(picked.banner);
  }
  let extra = examNotes(report);
  for (let i = 0; i < extra.length; i++) {
    look.notes.push(extra[i]);
  }
  look.numbers = summaryLines(report.summary);
  look.protect = protectLine(report.items);
  return look;
}
