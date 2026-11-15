import { hilog } from '@kit.PerformanceAnalysisKit';
import { Theme } from '../common/Theme';
import type {
  ActionRef,
  CheckGroup,
  CheckItem,
  CheckStatus,
  ExamReport,
  ExamState,
  JobKind,
  JobProgress,
  JobRecord,
  JobState,
  Lane
} from '../center/CenterTypes';
import { ResultStore } from '../record/ResultStore';
import { Writer } from '../record/Writer';
import { NOT_RUN, examNotes, examReportOf, ringText } from './HomeView';

const DOMAIN: number = 0x4A59;
const TAG: string = 'Center';
const UNREADABLE: string = '无法读取该结果';
const STOPPED: string = '本次体检未完成';

const GROUP_ORDER: CheckGroup[] = ['threat', 'protect', 'rules', 'permission', 'clean'];
const SECTION_TITLES: string[] = ['待处理', '建议', '正常', '暂不支持'];

export type ExamSection = 'pending' | 'advice' | 'normal' | 'unsupported';

const SECTION_ORDER: ExamSection[] = ['pending', 'advice', 'normal', 'unsupported'];

export class SectionLook {
  title: string = '';
  items: CheckItem[] = [];
}

export class GroupLook {
  group: CheckGroup = 'threat';
  title: string = '';
  sections: SectionLook[] = [];
}

export class ExamLook {
  running: boolean = false;
  state: ExamState = 'not-run';
  headline: string = NOT_RUN;
  notes: string[] = [];
  groups: GroupLook[] = [];
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

class Target implements ActionRef {
  route: string = '';
  params: string = '';
}

@Component
export struct ExamView {
  jobId: string = '';
  onOpen: (route: string, params: string) => void = (route: string, params: string) => {
    hilog.info(DOMAIN, TAG, 'exam open %{public}s', route);
  };
  @StorageLink('center.job.heavy') @Watch('onHeavy') heavy: JobProgress = new IdleProgress();
  @State look: ExamLook = new ExamLook();

  aboutToAppear(): void {
    this.reload();
  }

  onHeavy(): void {
    if (this.heavy.jobId === this.jobId) {
      this.reload();
    }
  }

  build() {
    Scroll() {
      Column() {
        Column() {
          Text(this.look.headline)
            .fontSize(22)
            .fontWeight(FontWeight.Medium)
            .fontColor(this.look.running ? Theme.text : stateColor(this.look.state))
          if (this.look.running) {
            Progress({ value: this.look.done, total: this.look.total > 0 ? this.look.total : 4, type: ProgressType.Linear })
              .width('100%')
              .color(Theme.accent)
              .margin({ top: 12 })
          }
          ForEach(this.look.notes, (note: string) => {
            Text(note)
              .fontSize(14)
              .fontColor(Theme.muted)
              .margin({ top: 6 })
          }, (note: string) => note)
        }
        .width('100%')
        .padding(20)
        .alignItems(HorizontalAlign.Start)
        .borderRadius(20)
        .backgroundColor(Theme.card)

        ForEach(this.look.groups, (group: GroupLook) => {
          this.groupBlock(group)
        }, (group: GroupLook) => group.group)
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

  @Builder
  groupBlock(group: GroupLook) {
    Column() {
      Text(group.title)
        .width('100%')
        .fontSize(14)
        .fontColor(Theme.muted)
        .padding({ left: 12, top: 16, bottom: 8 })
      Column() {
        ForEach(group.sections, (section: SectionLook) => {
          Text(section.title)
            .width('100%')
            .fontSize(13)
            .fontColor(Theme.muted)
            .padding({ left: 16, top: 12, bottom: 4 })
          ForEach(section.items, (item: CheckItem) => {
            this.itemRow(item)
          }, (item: CheckItem) => item.id + item.status)
        }, (section: SectionLook) => group.group + section.title)
      }
      .width('100%')
      .padding({ bottom: 8 })
      .borderRadius(20)
      .backgroundColor(Theme.card)
    }
    .width('100%')
  }

  @Builder
  itemRow(item: CheckItem) {
    Row() {
      Column() {
        Text(item.title)
          .fontSize(16)
          .fontColor(Theme.text)
        if (item.detail.length > 0) {
          Text(item.detail)
            .fontSize(12)
            .fontColor(Theme.muted)
            .margin({ top: 2 })
        }
      }
      .layoutWeight(1)
      .alignItems(HorizontalAlign.Start)

      Text(statusLabel(item.status))
        .fontSize(13)
        .fontColor(statusColor(item.status))
        .margin({ left: 12 })
      SymbolGlyph($r('sys.symbol.chevron_right'))
        .fontSize(18)
        .fontColor([Theme.line])
        .margin({ left: 4 })
    }
    .width('100%')
    .padding({ left: 16, right: 16, top: 10, bottom: 10 })
    .alignItems(VerticalAlign.Center)
    .onClick(() => {
      let target = itemTarget(item, this.jobId);
      if (target.route.length > 0) {
        this.onOpen(target.route, target.params);
      }
    })
  }

  private reload(): void {
    let record = findRecord(Writer.loadIndex(), this.jobId);
    let report: ExamReport | null = null;
    if (record !== null && record.state !== 'queued' && record.state !== 'running') {
      report = examReportOf(ResultStore.read(this.jobId));
      if (report === null) {
        hilog.error(DOMAIN, TAG, 'exam result unreadable');
      }
    }
    this.look = examLook(this.jobId, record, report, this.heavy);
  }
}

function findRecord(records: JobRecord[], jobId: string): JobRecord | null {
  if (jobId.length === 0) {
    return null;
  }
  for (let i = 0; i < records.length; i++) {
    if (records[i].jobId === jobId && records[i].kind === 'exam') {
      return records[i];
    }
  }
  return null;
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

function statusColor(status: CheckStatus): string {
  if (status === 'risk') {
    return Theme.danger;
  }
  if (status === 'unknown' || status === 'attention') {
    return Theme.warn;
  }
  if (status === 'ok') {
    return Theme.ok;
  }
  return Theme.muted;
}

export function statusLabel(status: CheckStatus): string {
  if (status === 'ok') {
    return '正常';
  }
  if (status === 'risk') {
    return '有风险';
  }
  if (status === 'unknown') {
    return '暂无法确认';
  }
  if (status === 'attention') {
    return '建议留意';
  }
  if (status === 'unverified') {
    return '未验证';
  }
  return '暂不支持';
}

export function groupTitle(group: CheckGroup): string {
  if (group === 'threat') {
    return '应用信誉';
  }
  if (group === 'protect') {
    return '系统防护';
  }
  if (group === 'rules') {
    return '规则';
  }
  if (group === 'permission') {
    return '权限';
  }
  return '清理';
}

/** 组内四截。不在这四种组合里的项按 kind 退回待处理或建议，并打 hilog。 */
export function examSection(item: CheckItem): ExamSection {
  if (item.kind === 'state' && (item.status === 'risk' || item.status === 'unknown')) {
    return 'pending';
  }
  if (item.kind === 'advice' && (item.status === 'attention' || item.status === 'unknown')) {
    return 'advice';
  }
  if (item.status === 'ok') {
    return 'normal';
  }
  if (item.status === 'unverified' || item.status === 'unsupported') {
    return 'unsupported';
  }
  hilog.error(DOMAIN, TAG, 'exam item %{public}s has %{public}s on %{public}s', item.id, item.status, item.kind);
  return item.kind === 'state' ? 'pending' : 'advice';
}

export function examGroups(items: CheckItem[]): GroupLook[] {
  let groups: GroupLook[] = [];
  for (let g = 0; g < GROUP_ORDER.length; g++) {
    let look = new GroupLook();
    look.group = GROUP_ORDER[g];
    look.title = groupTitle(GROUP_ORDER[g]);
    for (let s = 0; s < SECTION_ORDER.length; s++) {
      let section = new SectionLook();
      section.title = SECTION_TITLES[s];
      for (let i = 0; i < items.length; i++) {
        if (items[i].group === GROUP_ORDER[g] && examSection(items[i]) === SECTION_ORDER[s]) {
          section.items.push(items[i]);
        }
      }
      if (section.items.length > 0) {
        look.sections.push(section);
      }
    }
    if (look.sections.length > 0) {
      groups.push(look);
    }
  }
  return groups;
}

/** 进信誉页时 params 是这次体检的 jobId，不是路由名。 */
export function itemTarget(item: CheckItem, jobId: string): ActionRef {
  let target = new Target();
  target.route = item.action.route;
  target.params = item.action.route === 'malware' ? jobId : item.action.params;
  return target;
}

export function examLook(jobId: string, record: JobRecord | null, report: ExamReport | null,
  heavy: JobProgress): ExamLook {
  let look = new ExamLook();
  if (jobId.length === 0) {
    return look;
  }
  let live = heavy.kind === 'exam' && heavy.jobId === jobId &&
    (heavy.state === 'queued' || heavy.state === 'running');
  if (live || (record !== null && (record.state === 'queued' || record.state === 'running'))) {
    look.running = true;
    look.headline = heavy.jobId === jobId ? heavy.message : '';
    look.done = heavy.jobId === jobId ? heavy.done : 0;
    look.total = heavy.jobId === jobId ? heavy.total : 0;
    return look;
  }
  if (record === null || report === null) {
    look.headline = UNREADABLE;
    return look;
  }
  look.state = report.state;
  look.headline = ringText(report.state);
  if (record.state !== 'done') {
    look.notes.push(STOPPED);
  }
  let notes = examNotes(report);
  for (let i = 0; i < notes.length; i++) {
    look.notes.push(notes[i]);
  }
  look.groups = examGroups(report.items);
  return look;
}
