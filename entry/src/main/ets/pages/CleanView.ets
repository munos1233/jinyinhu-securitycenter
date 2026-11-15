import { hilog } from '@kit.PerformanceAnalysisKit';
import { common } from '@kit.AbilityKit';
import { picker } from '@kit.CoreFileKit';
import { Theme } from '../common/Theme';
import type {
  CacheRow,
  CleanReport,
  FileGrant,
  FileHit,
  FileSource,
  FileToolReport,
  JobKind,
  JobProgress,
  JobRecord,
  JobRequest,
  JobState,
  Lane,
  ScanScope
} from '../center/CenterTypes';
import type { Disposition, DispositionResult } from '../record/Disposition';
import { ResultStore } from '../record/ResultStore';
import { Writer } from '../record/Writer';
import type { JobQueue } from '../task/JobQueue';
import { QUEUE_KEY, formatBytes } from './HomeView';
import { DISPOSITION_KEY, UNFINISHED, UNREADABLE, busyText, jobStateLine } from './MalwareView';

const DOMAIN: number = 0x4A59;
const TAG: string = 'Center';

const OTHER_CACHE: string = '无法读取其他应用缓存';
const NO_DIR: string = '请先选择目录';
const NO_CACHE: string = '没有缓存';
const NO_INSTALLER: string = '没有安装包';
const NOT_SCANNED: string = '尚未扫描';
const SCANNING: string = '正在扫描';
const UNSUPPORTED: string = '暂不支持';
const VIEW_ONLY: string = '仅查看，不删除';
const CACHE_PREFIX: string = 'cache:';
const FILE_PREFIX: string = 'file:';

/** 组合根把 FileGrants 放在这个键下。没有持久授权时，重复文件和大文件先选择目录。 */
export const FILES_KEY: string = 'center.files';

export interface DirectoryChoice extends FileSource {
  remember(uri: string, displayName: string): Promise<FileGrant>;
}

export class CleanLine {
  key: string = '';
  title: string = '';
  detail: string = '';
  bytes: number = 0;
}

export class CleanSection {
  id: string = '';
  title: string = '';
  rows: CleanLine[] = [];
  placeholder: string = '';
  selectable: boolean = false;
}

export class CleanPageLook {
  jobId: string = '';
  viewOnly: boolean = false;
  showTools: boolean = false;
  running: boolean = false;
  settled: boolean = false;
  headline: string = NOT_SCANNED;
  lines: string[] = [];
  sections: CleanSection[] = [];
  defaultKeys: string[] = [];
  done: number = 0;
  total: number = 0;
}

export class ByteCount {
  bytes: number = 0;
  count: number = 0;
}

class IdleProgress implements JobProgress {
  jobId: string = '';
  kind: JobKind = 'clean';
  lane: Lane = 'heavy';
  state: JobState = 'queued';
  done: number = 0;
  total: number = 0;
  message: string = '';
}

class CleanRequest implements JobRequest {
  kind: JobKind = 'clean';
  scope: ScanScope = 'quick';
  uris: string[] = [];
  focus: string = '';
}

@Component
export struct CleanView {
  params: string = '';
  onOpen: (route: string, params: string) => void = (route: string, params: string) => {
    hilog.info(DOMAIN, TAG, 'clean open %{public}s', route);
  };
  @StorageLink('center.job.heavy') @Watch('onHeavy') heavy: JobProgress = new IdleProgress();
  @State viewing: string = '';
  @State look: CleanPageLook = new CleanPageLook();
  @State selected: string[] = [];
  @State picked: string[] = [];
  @State notice: string = '';
  @State working: boolean = false;

  aboutToAppear(): void {
    let record = pickCleanJob(Writer.loadIndex(), this.params, '');
    this.viewing = record === null ? '' : record.jobId;
    this.reload(true);
    this.ensureDirectory();
  }

  onHeavy(): void {
    if (this.heavy.jobId === this.viewing ||
      (this.heavy.kind === cleanKind(this.params) && this.viewing.length === 0)) {
      if (this.viewing.length === 0 && this.heavy.jobId.length > 0) {
        this.viewing = this.heavy.jobId;
      }
      this.reload(false);
    }
  }

  build() {
    Column() {
      Scroll() {
        Column() {
          this.header()
          if (this.look.viewOnly) {
            Text(VIEW_ONLY)
              .fontSize(14)
              .fontColor(Theme.muted)
              .margin({ top: 12 })
          }
          ForEach(this.look.sections, (section: CleanSection) => {
            this.sectionBlock(section)
          }, (section: CleanSection) => section.id + ':' + section.rows.length.toString() + ':' + section.placeholder)
          if (this.look.showTools) {
            this.toolLink('重复文件', 'duplicate')
            this.toolLink('大文件', 'large')
          }
        }
        .width('100%')
        .padding({ left: 16, right: 16, top: 8, bottom: 24 })
        .alignItems(HorizontalAlign.Start)
      }
      .layoutWeight(1)
      .width('100%')
      .align(Alignment.TopStart)
      .scrollBar(BarState.Off)

      this.bottomBar()
    }
    .width('100%')
    .height('100%')
    .backgroundColor(Theme.page)
  }

  @Builder
  header() {
    Column() {
      if (!this.look.viewOnly && this.look.settled) {
        Text(selectedLine(this.look.sections, this.selected))
          .fontSize(20)
          .fontWeight(FontWeight.Medium)
          .fontColor(Theme.text)
      } else {
        Text(this.look.headline)
          .fontSize(20)
          .fontWeight(FontWeight.Medium)
          .fontColor(Theme.text)
      }
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
      if (this.notice.length > 0) {
        Text(this.notice)
          .fontSize(14)
          .fontColor(Theme.accent)
          .margin({ top: 6 })
      }
    }
    .width('100%')
    .padding(20)
    .alignItems(HorizontalAlign.Start)
    .borderRadius(20)
    .backgroundColor(Theme.card)
  }

  @Builder
  sectionBlock(section: CleanSection) {
    Column() {
      Row() {
        Text(section.title)
          .fontSize(14)
          .fontColor(Theme.muted)
          .layoutWeight(1)
        if (section.selectable && section.rows.length > 0) {
          Text('全选')
            .fontSize(13)
            .fontColor(Theme.accent)
            .margin({ right: 12 })
            .onClick(() => {
              this.selected = selectCategory(this.selected, sectionKeys(section), true);
            })
          Text('取消全选')
            .fontSize(13)
            .fontColor(Theme.accent)
            .onClick(() => {
              this.selected = selectCategory(this.selected, sectionKeys(section), false);
            })
        }
      }
      .width('100%')
      .padding({ left: 12, right: 12, top: 16, bottom: 8 })

      Column() {
        if (section.placeholder.length > 0) {
          Text(section.placeholder)
            .fontSize(14)
            .fontColor(Theme.text)
            .padding({ left: 16, right: 16, top: 12, bottom: 12 })
        }
        if (section.id === 'need-dir') {
          Text('选择目录')
            .fontSize(14)
            .fontColor(Theme.accent)
            .padding({ left: 16, right: 16, bottom: 12 })
            .onClick(() => {
              this.pickDirectory(false);
            })
        }
        ForEach(section.rows, (row: CleanLine) => {
          this.lineRow(section, row)
        }, (row: CleanLine) => row.key + (this.selected.indexOf(row.key) >= 0 ? '1' : '0'))
      }
      .width('100%')
      .borderRadius(20)
      .backgroundColor(Theme.card)
    }
    .width('100%')
  }

  @Builder
  lineRow(section: CleanSection, row: CleanLine) {
    Row() {
      if (section.selectable) {
        Checkbox({ name: row.key })
          .select(this.selected.indexOf(row.key) >= 0)
          .onChange((value: boolean) => {
            this.selected = selectCategory(this.selected, [row.key], value);
          })
          .margin({ right: 8 })
      }
      Column() {
        Text(row.title)
          .fontSize(16)
          .fontColor(Theme.text)
        if (row.detail.length > 0) {
          Text(row.detail)
            .fontSize(12)
            .fontColor(Theme.muted)
            .margin({ top: 2 })
        }
      }
      .layoutWeight(1)
      .alignItems(HorizontalAlign.Start)
      Text(formatBytes(row.bytes))
        .fontSize(13)
        .fontColor(Theme.muted)
        .margin({ left: 8 })
    }
    .width('100%')
    .padding({ left: 16, right: 16, top: 10, bottom: 10 })
  }

  @Builder
  toolLink(title: string, target: string) {
    Text(title)
      .width('100%')
      .fontSize(16)
      .fontColor(Theme.text)
      .padding(16)
      .margin({ top: 12 })
      .borderRadius(20)
      .backgroundColor(Theme.card)
      .onClick(() => {
        this.onOpen('clean', target);
      })
  }

  @Builder
  bottomBar() {
    Row() {
      Button('开始')
        .type(ButtonType.Capsule)
        .layoutWeight(1)
        .height(40)
        .fontColor(Theme.onAccent)
        .backgroundColor(Theme.accent)
        .enabled(!this.working)
        .onClick(() => {
          this.start();
        })
      if (showsProcess(this.params)) {
        Button('立即处理')
          .type(ButtonType.Capsule)
          .layoutWeight(1)
          .height(40)
          .margin({ left: 12 })
          .fontColor(Theme.onAccent)
          .backgroundColor(Theme.danger)
          .enabled(selectedTotal(this.look.sections, this.selected).count > 0 && !this.working)
          .opacity(selectedTotal(this.look.sections, this.selected).count > 0 && !this.working ? 1 : 0.4)
          .onClick(() => {
            this.confirmProcess();
          })
      }
    }
    .width('100%')
    .padding({ left: 16, right: 16, top: 8, bottom: 16 })
    .backgroundColor(Theme.page)
  }

  private reload(reset: boolean): void {
    let record = pickCleanJob(Writer.loadIndex(), this.params, this.viewing);
    let text: string | null = null;
    if (record !== null && settled(record.state)) {
      text = ResultStore.read(record.jobId);
    }
    let priorId = this.look.jobId;
    let priorDefaults = this.look.defaultKeys.length;
    this.look = cleanPageLook(this.params, record, text, this.heavy);
    if (reset || this.look.jobId !== priorId || (priorDefaults === 0 && this.look.defaultKeys.length > 0)) {
      this.selected = this.look.defaultKeys.slice();
    } else {
      let live = liveKeys(this.look.sections);
      let keep: string[] = [];
      for (let i = 0; i < this.selected.length; i++) {
        if (live.indexOf(this.selected[i]) >= 0) {
          keep.push(this.selected[i]);
        }
      }
      this.selected = keep;
    }
  }

  private ensureDirectory(): void {
    if (!viewOnly(this.params)) {
      return;
    }
    if (directoryGranted(this.currentGrants())) {
      return;
    }
    this.pickDirectory(false);
  }

  private currentGrants(): FileGrant[] {
    let files = AppStorage.get<FileSource>(FILES_KEY);
    if (files === undefined) {
      return [];
    }
    return files.persisted();
  }

  private start(): void {
    if (viewOnly(this.params) && !directoryGranted(this.currentGrants()) && this.picked.length === 0) {
      this.pickDirectory(true);
      return;
    }
    this.enqueue(this.picked);
  }

  private pickDirectory(thenStart: boolean): void {
    let options = new picker.DocumentSelectOptions();
    options.maxSelectNumber = 1;
    let view = new picker.DocumentViewPicker(getContext(this) as common.UIAbilityContext);
    view.select(options).then((uris: string[]) => {
      if (uris.length === 0) {
        return;
      }
      this.picked = uris.slice();
      this.keepDirectory(uris[0]).then(() => {
        if (thenStart) {
          this.enqueue(this.picked);
        }
      });
    }).catch((err: Error) => {
      hilog.warn(DOMAIN, TAG, 'clean picker failed: %{public}s', err.message);
    });
  }

  private keepDirectory(uri: string): Promise<void> {
    let port = AppStorage.get<DirectoryChoice>(FILES_KEY);
    if (port === undefined) {
      return Promise.resolve();
    }
    return port.remember(uri, fileNameOf(uri)).then(() => {
    }).catch((err: Error) => {
      hilog.warn(DOMAIN, TAG, 'clean grant failed: %{public}s', err.message);
      this.notice = UNSUPPORTED;
    });
  }

  private enqueue(uris: string[]): void {
    let queue = AppStorage.get<JobQueue>(QUEUE_KEY);
    if (queue === undefined) {
      hilog.error(DOMAIN, TAG, 'clean queue not ready');
      this.notice = UNSUPPORTED;
      return;
    }
    let request = cleanRequest(this.params, uris);
    let jobId = queue.enqueue(request);
    if (jobId.length === 0) {
      this.notice = busyText(queue.active(request.kind));
      return;
    }
    this.notice = '';
    this.viewing = jobId;
    this.reload(true);
  }

  private confirmProcess(): void {
    if (!showsProcess(this.params)) {
      return;
    }
    let total = selectedTotal(this.look.sections, this.selected);
    if (total.count === 0) {
      return;
    }
    AlertDialog.show({
      title: '立即处理',
      message: confirmText(total.bytes, total.count),
      primaryButton: {
        value: '取消',
        action: () => {
        }
      },
      secondaryButton: {
        value: '确认',
        fontColor: Theme.danger,
        action: () => {
          this.process();
        }
      }
    });
  }

  /** 清缓存和隔离都走 Disposition。本页不改体检字节。 */
  private async process(): Promise<void> {
    if (!showsProcess(this.params)) {
      return;
    }
    let disposition = AppStorage.get<Disposition>(DISPOSITION_KEY);
    if (disposition === undefined) {
      hilog.error(DOMAIN, TAG, 'clean disposition not ready');
      this.notice = UNSUPPORTED;
      return;
    }
    this.working = true;
    let messages: string[] = [];
    let keys = this.selected.slice();
    for (let i = 0; i < keys.length; i++) {
      let key = keys[i];
      let result: DispositionResult | null = null;
      if (key.indexOf(CACHE_PREFIX) === 0) {
        result = await disposition.clearCache(this.look.jobId, key.substring(CACHE_PREFIX.length));
      } else if (key.indexOf(FILE_PREFIX) === 0) {
        result = await disposition.quarantine(this.look.jobId, key.substring(FILE_PREFIX.length));
      }
      if (result !== null && !result.done && result.message.length > 0 && messages.indexOf(result.message) < 0) {
        messages.push(result.message);
      }
    }
    this.working = false;
    this.reload(true);
    this.notice = messages.join('、');
  }
}

export function fileNameOf(path: string): string {
  let slash = path.lastIndexOf('/');
  let name = slash >= 0 ? path.substring(slash + 1) : path;
  return name.length > 0 ? name : path;
}

export function cacheKey(bundleName: string): string {
  return CACHE_PREFIX + bundleName;
}

export function fileKey(uri: string): string {
  return FILE_PREFIX + uri;
}

/** cache、installer、residue 和空串都是主清理。residue 与 installer 同义。 */
export function cleanKind(params: string): JobKind {
  if (params === 'duplicate') {
    return 'duplicate';
  }
  if (params === 'large') {
    return 'large-file';
  }
  return 'clean';
}

export function viewOnly(params: string): boolean {
  return params === 'duplicate' || params === 'large';
}

export function showsProcess(params: string): boolean {
  return !viewOnly(params);
}

export function cleanRequest(params: string, uris: string[]): JobRequest {
  let request = new CleanRequest();
  request.kind = cleanKind(params);
  request.scope = uris.length > 0 ? 'custom' : 'quick';
  request.uris = uris.slice();
  request.focus = '';
  return request;
}

export function directoryGranted(rows: FileGrant[]): boolean {
  for (let i = 0; i < rows.length; i++) {
    if (rows[i].persisted && rows[i].uri.length > 0) {
      return true;
    }
  }
  return false;
}

/** 只勾选缓存。不读文件里的 selected。 */
export function defaultSelection(report: CleanReport): string[] {
  let keys: string[] = [];
  for (let i = 0; i < report.caches.length; i++) {
    keys.push(cacheKey(report.caches[i].bundleName));
  }
  return keys;
}

export function sectionKeys(section: CleanSection): string[] {
  let keys: string[] = [];
  for (let i = 0; i < section.rows.length; i++) {
    keys.push(section.rows[i].key);
  }
  return keys;
}

export function liveKeys(sections: CleanSection[]): string[] {
  let keys: string[] = [];
  for (let s = 0; s < sections.length; s++) {
    let rows = sectionKeys(sections[s]);
    for (let i = 0; i < rows.length; i++) {
      keys.push(rows[i]);
    }
  }
  return keys;
}

/** 只改 keys 里的勾选，其它类保持不动。 */
export function selectCategory(selected: string[], keys: string[], on: boolean): string[] {
  let next: string[] = [];
  for (let i = 0; i < selected.length; i++) {
    if (keys.indexOf(selected[i]) < 0) {
      next.push(selected[i]);
    }
  }
  if (on) {
    for (let i = 0; i < keys.length; i++) {
      next.push(keys[i]);
    }
  }
  return next;
}

export function selectedTotal(sections: CleanSection[], selected: string[]): ByteCount {
  let total = new ByteCount();
  for (let s = 0; s < sections.length; s++) {
    if (!sections[s].selectable) {
      continue;
    }
    let rows = sections[s].rows;
    for (let i = 0; i < rows.length; i++) {
      if (selected.indexOf(rows[i].key) >= 0) {
        total.bytes += rows[i].bytes;
        total.count++;
      }
    }
  }
  return total;
}

export function selectedLine(sections: CleanSection[], selected: string[]): string {
  let total = selectedTotal(sections, selected);
  return '已选 ' + total.bytes.toString() + ' 字节（' + formatBytes(total.bytes) + '）';
}

export function confirmText(bytes: number, count: number): string {
  return '确认处理 ' + count.toString() + ' 条，共 ' + bytes.toString() + ' 字节（' + formatBytes(bytes) +
    '）。缓存会直接清除，安装包会进隔离区。';
}

export function cachePlaceholder(report: CleanReport): string {
  if (report.caches.length > 0) {
    return '';
  }
  if (report.note.indexOf(OTHER_CACHE) >= 0) {
    return '';
  }
  if (!report.complete) {
    return '';
  }
  return NO_CACHE;
}

export function installerPlaceholder(report: CleanReport): string {
  if (packageHits(report).length > 0) {
    return '';
  }
  if (report.note.indexOf(NO_DIR) >= 0) {
    return NO_DIR;
  }
  if (!report.complete) {
    return '';
  }
  return NO_INSTALLER;
}

export function pickCleanJob(records: JobRecord[], params: string, viewing: string): JobRecord | null {
  let kind = cleanKind(params);
  if (viewing.length > 0) {
    let named = findKind(records, viewing, kind);
    if (named !== null) {
      return named;
    }
  }
  let latest: JobRecord | null = null;
  for (let i = 0; i < records.length; i++) {
    if (records[i].kind === kind && (latest === null || records[i].seq >= latest.seq)) {
      latest = records[i];
    }
  }
  return latest;
}

export function cleanPageLook(params: string, record: JobRecord | null, text: string | null,
  heavy: JobProgress): CleanPageLook {
  let look = new CleanPageLook();
  look.viewOnly = viewOnly(params);
  look.showTools = showsProcess(params);
  if (record === null) {
    return look;
  }
  look.jobId = record.jobId;
  if (!settled(record.state)) {
    look.running = true;
    let live = heavy.jobId === record.jobId;
    look.headline = live && heavy.message.length > 0 ? heavy.message : SCANNING;
    look.done = live ? heavy.done : 0;
    look.total = live ? heavy.total : 0;
    return look;
  }
  if (look.viewOnly) {
    let tool = fileToolOf(text);
    if (tool === null) {
      hilog.error(DOMAIN, TAG, 'file tool result unreadable');
      look.headline = UNREADABLE;
      return look;
    }
    look.settled = true;
    look.headline = params === 'large' ? '大文件' : '重复文件';
    look.lines = notedLines(record.state, tool.note, tool.complete, 'file tool result incomplete without note');
    look.sections = toolSections(params, tool);
    return look;
  }
  let report = cleanReportOf(text);
  if (report === null) {
    hilog.error(DOMAIN, TAG, 'clean result unreadable');
    look.headline = UNREADABLE;
    return look;
  }
  look.settled = true;
  look.headline = '清理';
  look.lines = notedLines(record.state, report.note, report.complete, 'clean result incomplete without note');
  look.sections = cleanSections(report);
  look.defaultKeys = defaultSelection(report);
  return look;
}

function settled(state: JobState): boolean {
  return state !== 'queued' && state !== 'running';
}

function findKind(records: JobRecord[], jobId: string, kind: JobKind): JobRecord | null {
  for (let i = 0; i < records.length; i++) {
    if (records[i].jobId === jobId && records[i].kind === kind) {
      return records[i];
    }
  }
  return null;
}

function notedLines(state: JobState, note: string, complete: boolean, missing: string): string[] {
  let lines: string[] = [];
  let stop = jobStateLine(state);
  if (stop.length > 0) {
    lines.push(stop);
  }
  if (note.length > 0) {
    lines.push(note);
  } else if (!complete) {
    hilog.error(DOMAIN, TAG, '%{public}s', missing);
    lines.push(UNFINISHED);
  }
  return lines;
}

function cleanSections(report: CleanReport): CleanSection[] {
  let out: CleanSection[] = [];
  let caches = cacheLines(report.caches);
  if (caches.length > 0) {
    out.push(makeSection('cache', '缓存', caches, '', true));
  } else {
    let text = cachePlaceholder(report);
    if (text.length > 0) {
      out.push(makeSection('cache', '缓存', [], text, true));
    }
  }
  let residue = hitLines(hitsOf(report, 'residue'));
  let installed = hitLines(hitsOf(report, 'installer'));
  let placeholder = installerPlaceholder(report);
  if (placeholder === NO_DIR) {
    out.push(makeSection('need-dir', '安装包', [], NO_DIR, true));
    return out;
  }
  if (residue.length > 0 || (placeholder === NO_INSTALLER && installed.length === 0)) {
    out.push(makeSection('residue', '安装包', residue, residue.length === 0 ? placeholder : '', true));
  }
  if (installed.length > 0) {
    out.push(makeSection('installer', '已安装应用的安装包', installed, '', true));
  } else if (residue.length > 0 && report.complete) {
    out.push(makeSection('installer', '已安装应用的安装包', [], NO_INSTALLER, true));
  }
  return out;
}

function toolSections(params: string, report: FileToolReport): CleanSection[] {
  let title = params === 'large' ? '大文件' : '重复文件';
  return [makeSection('files', title, hitLines(report.hits), '', false)];
}

function makeSection(id: string, title: string, rows: CleanLine[], placeholder: string,
  selectable: boolean): CleanSection {
  let section = new CleanSection();
  section.id = id;
  section.title = title;
  section.rows = rows;
  section.placeholder = placeholder;
  section.selectable = selectable;
  return section;
}

function cacheLines(rows: CacheRow[]): CleanLine[] {
  let out: CleanLine[] = [];
  for (let i = 0; i < rows.length; i++) {
    let line = new CleanLine();
    line.key = cacheKey(rows[i].bundleName);
    line.title = rows[i].displayName.length > 0 ? rows[i].displayName : rows[i].bundleName;
    line.bytes = rows[i].cacheBytes;
    line.detail = '';
    out.push(line);
  }
  return out;
}

function hitLines(rows: FileHit[]): CleanLine[] {
  let out: CleanLine[] = [];
  for (let i = 0; i < rows.length; i++) {
    let line = new CleanLine();
    line.key = fileKey(rows[i].uri);
    line.title = rows[i].name.length > 0 ? rows[i].name : fileNameOf(rows[i].uri);
    line.bytes = rows[i].size;
    line.detail = rows[i].reason;
    out.push(line);
  }
  return out;
}

function packageHits(report: CleanReport): FileHit[] {
  return hitsOf(report, 'residue').concat(hitsOf(report, 'installer'));
}

function hitsOf(report: CleanReport, clazz: 'residue' | 'installer'): FileHit[] {
  let out: FileHit[] = [];
  for (let i = 0; i < report.hits.length; i++) {
    if (report.hits[i].clazz === clazz) {
      out.push(report.hits[i]);
    }
  }
  return out;
}

export function cleanReportOf(text: string | null): CleanReport | null {
  if (text === null) {
    return null;
  }
  let parsed: CleanReport;
  try {
    parsed = JSON.parse(text) as CleanReport;
  } catch (err) {
    return null;
  }
  if (parsed === null || typeof parsed !== 'object' || !(parsed.caches instanceof Array) ||
    !(parsed.hits instanceof Array) || typeof parsed.complete !== 'boolean') {
    return null;
  }
  parsed.note = typeof parsed.note === 'string' ? parsed.note : '';
  return parsed;
}

export function fileToolOf(text: string | null): FileToolReport | null {
  if (text === null) {
    return null;
  }
  let parsed: FileToolReport;
  try {
    parsed = JSON.parse(text) as FileToolReport;
  } catch (err) {
    return null;
  }
  if (parsed === null || typeof parsed !== 'object' || !(parsed.hits instanceof Array) ||
    typeof parsed.complete !== 'boolean') {
    return null;
  }
  parsed.note = typeof parsed.note === 'string' ? parsed.note : '';
  if (!(parsed.groups instanceof Array)) {
    parsed.groups = [];
  }
  return parsed;
}
