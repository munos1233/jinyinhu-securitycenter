import { hilog } from '@kit.PerformanceAnalysisKit';
import { Theme } from '../common/Theme';
import { Anomaly } from '../center/Anomaly';
import { groupOf, isSensitive } from '../center/SensitiveCatalog';
import type { ExamReport, JobKind, JobProgress, JobRecord, JobRequest, JobState, Lane, PermissionFact, ScanHit, ScanReport, UseFact } from '../center/CenterTypes';
import { RulePack } from '../engine/RulePack';
import type { RuleLoad } from '../engine/RulePack';
import type { Disposition } from '../record/Disposition';
import { DISPOSITION_KEY } from './MalwareView';
import type { PermissionActions } from '../record/PermissionActions';
import { ResultStore } from '../record/ResultStore';
import { Writer } from '../record/Writer';
import type { JobQueue } from '../task/JobQueue';
import { QUEUE_KEY } from './HomeView';

const DOMAIN: number = 0x4A59;
const TAG: string = 'Center';
export const PERMISSION_ACTIONS_KEY: string = 'center.permission';
export const PERMISSION_GROUPS: string[] = ['位置', '相机', '麦克风', '通讯录', '日历', '短信', '电话', '媒体'];
const REFRESHING: string = '正在刷新授权';

export class PermissionStored {
  facts: PermissionFact[] = [];
  uses: UseFact[] = [];
  counts: PermissionCount[] = [];
  bundlesAvailable: boolean = true;
  usesAvailable: boolean = false;
}

export class PermissionCount {
  group: string = '';
  count: number = 0;
  known: boolean = false;
}

export class PermissionLine {
  key: string = '';
  bundleName: string = '';
  displayName: string = '';
  permission: string = '';
  label: string = '';
  group: string = '';
  sensitiveCount: number = 0;
  countKnown: boolean = false;
  current: PermissionFact | null = null;
  userGrant: boolean = false;
  revokeVerified: boolean = false;
  verificationFailed: boolean = false;
}

export class PermissionBlock {
  permission: string = '';
  label: string = '';
  rows: PermissionLine[] = [];
}

export class PermissionSelection {
  rows: PermissionLine[] = [];
  banner: string = '';
  missing: string = '';
  knownBundle: boolean = false;
}

class PermissionProgress implements JobProgress {
  jobId: string = '';
  kind: JobKind = 'permission';
  lane: Lane = 'light';
  state: JobState = 'done';
  done: number = 0;
  total: number = 0;
  message: string = '';
}

@Component
export struct PermissionView {
  params: string = '';
  @StorageLink('center.job.light') @Watch('onLight') light: JobProgress = new PermissionProgress();
  @StorageLink('center.gate.generation') @Watch('onGate') gateGeneration: number = 0;
  @State viewing: string = '';
  @State counts: PermissionCount[] = permissionCounts([]);
  @State blocks: PermissionBlock[] = [];
  @State selectedGroup: string = '';
  @State banner: string = '';
  @State missing: string = '';
  @State notice: string = '';
  @State refreshing: boolean = true;
  @State working: boolean = false;
  @State canRevoke: boolean = false;
  @State grantsAvailable: boolean = false;
  @State usesAvailable: boolean = false;
  @State uses: UseFact[] = [];
  private alive: boolean = false;
  private revision: number = 0;
  private reconciled: string = '';
  private awaitingRequest: boolean = false;
  private initialBundleRead: boolean = false;
  private appeared: boolean = false;

  aboutToAppear(): void {
    this.alive = true;
    if (!this.appeared) {
      this.initialBundleRead = isBundleFocus(this.params);
      this.appeared = true;
    }
    this.selectedGroup = PERMISSION_GROUPS.indexOf(this.params) >= 0 || this.params === '其它' ? this.params : '';
    let record = latestPermissionJob(Writer.loadIndex());
    this.viewing = record === null ? '' : record.jobId;
    this.start();
  }

  aboutToDisappear(): void {
    this.alive = false;
    this.initialBundleRead = false;
    this.revision++;
  }

  onGate(): void {
    if (this.alive) {
      this.initialBundleRead = false;
      this.reconciled = '';
      this.start();
    }
  }

  onLight(): void {
    if (!this.alive || this.light.kind !== 'permission') {
      return;
    }
    if (this.awaitingRequest && settledPermission(this.light.state)) {
      // Let the queue release its active slot after publishing the terminal progress.
      Promise.resolve().then(() => {
        if (this.alive && this.awaitingRequest) {
          this.start();
        }
      });
      return;
    }
    if (this.light.jobId === this.viewing) {
      this.load(!settledPermission(this.light.state));
    }
  }

  build() {
    Column() {
      Scroll() {
        Column() {
          if (this.missing.length > 0) {
            Text(this.missing)
              .fontSize(16)
              .fontColor(Theme.muted)
          } else {
            if (this.banner.length > 0) {
              Text(this.banner)
                .fontSize(14)
                .fontColor(Theme.muted)
                .margin({ bottom: 12 })
            }
            if (!this.canRevoke) {
              Text('无法关闭此权限')
                .fontSize(14)
                .fontColor(Theme.muted)
                .margin({ bottom: 12 })
            }
            this.groupList()
            if (this.refreshing) {
              Text(REFRESHING)
                .fontSize(14)
                .fontColor(Theme.muted)
                .margin({ top: 12 })
            }
            ForEach(this.blocks, (block: PermissionBlock) => {
              this.permissionBlock(block)
            }, (block: PermissionBlock) => block.permission)
            if (this.usesAvailable) {
              this.recentUses()
            }
          }
          if (this.notice.length > 0) {
            Text(this.notice)
              .fontSize(14)
              .fontColor(Theme.muted)
              .margin({ top: 12 })
          }
        }
        .width('100%')
        .alignItems(HorizontalAlign.Start)
        .padding({ left: 16, right: 16, top: 12, bottom: 24 })
      }
      .layoutWeight(1)
      .width('100%')
      .scrollBar(BarState.Off)
      Button('开始')
        .height(40)
        .width('90%')
        .margin({ bottom: 16 })
        .backgroundColor(Theme.accent)
        .fontColor(Theme.onAccent)
        .enabled(!this.working)
        .onClick(() => this.start())
    }
    .width('100%')
    .height('100%')
    .backgroundColor(Theme.page)
  }

  @Builder
  groupList() {
    Column() {
      ForEach(this.counts, (count: PermissionCount) => {
        Row() {
          Text(count.group).fontSize(15).fontColor(Theme.text)
          Blank()
          Text(this.refreshing ? REFRESHING : this.grantsAvailable && count.known ? count.count.toString() + ' 人' : '状态未知')
            .fontSize(14).fontColor(Theme.muted)
        }
        .width('100%')
        .padding(12)
        .borderRadius(12)
        .backgroundColor(this.selectedGroup === count.group ? Theme.line : Theme.card)
        .margin({ bottom: 6 })
        .onClick(() => {
          this.selectedGroup = this.selectedGroup === count.group ? '' : count.group;
          this.load(this.refreshing);
        })
      }, (count: PermissionCount) => count.group)
      Text('其它')
        .fontSize(15).fontColor(Theme.text).width('100%').padding(12)
        .backgroundColor(this.selectedGroup === '其它' ? Theme.line : Theme.card)
        .borderRadius(12)
        .onClick(() => {
          this.selectedGroup = this.selectedGroup === '其它' ? '' : '其它';
          this.load(this.refreshing);
        })
    }
    .width('100%')
  }

  @Builder
  permissionBlock(block: PermissionBlock) {
    Column() {
      Text(block.label)
        .fontSize(17).fontWeight(FontWeight.Medium).fontColor(Theme.text)
        .width('100%').margin({ top: 14, bottom: 8 })
      ForEach(block.rows, (line: PermissionLine) => {
        Column() {
          Text(line.displayName).fontSize(15).fontColor(Theme.text).width('100%')
          Text(line.bundleName).fontSize(12).fontColor(Theme.muted).width('100%').margin({ top: 3 })
          Text(this.refreshing ? REFRESHING : line.countKnown ? '敏感权限 ' + line.sensitiveCount.toString() : '状态未知')
            .fontSize(12).fontColor(Theme.muted).width('100%').margin({ top: 3 })
          Row() {
            Text(permissionStatus(line, this.canRevoke, this.refreshing))
              .fontSize(14).fontColor(Theme.muted)
            Blank()
            if (permissionCanClose(line, this.canRevoke, this.refreshing) && !this.working) {
              Button('关闭权限')
                .fontSize(13).height(32)
                .backgroundColor(Theme.card).fontColor(Theme.danger)
                .onClick(() => this.confirmClose(line))
            }
          }
          .width('100%').margin({ top: 8 })
        }
        .width('100%').padding(12).borderRadius(12).backgroundColor(Theme.card).margin({ bottom: 8 })
      }, (line: PermissionLine) => line.key)
    }
    .width('100%')
  }

  @Builder
  recentUses() {
    Column() {
      Text('最近使用').fontSize(17).fontWeight(FontWeight.Medium).fontColor(Theme.text).margin({ top: 18, bottom: 8 })
      if (this.uses.length === 0) {
        Text('最近 7 天没有使用记录').fontSize(14).fontColor(Theme.muted)
      }
      ForEach(this.uses, (use: UseFact) => {
        Column() {
          Text(use.displayName + ' · ' + permissionName(use.permission, use.label)).fontSize(14).fontColor(Theme.text)
          Text(use.at).fontSize(12).fontColor(Theme.muted).margin({ top: 3 })
        }
        .width('100%').alignItems(HorizontalAlign.Start).padding(12).backgroundColor(Theme.card).margin({ bottom: 6 })
      }, (use: UseFact) => use.bundleName + ':' + use.permission + ':' + use.at)
    }
    .width('100%').alignItems(HorizontalAlign.Start)
  }

  private start(): void {
    this.revision++;
    this.refreshing = true;
    this.blocks = [];
    this.usesAvailable = false;
    let queue = AppStorage.get<JobQueue>(QUEUE_KEY);
    if (queue === undefined) {
      this.notice = '暂不支持';
      this.load(false);
      return;
    }
    let jobId = queue.enqueue(permissionRequest(this.params));
    this.awaitingRequest = jobId.length === 0;
    if (this.awaitingRequest) {
      this.notice = '正在扫描';
      this.load(true);
      return;
    }
    this.notice = '';
    this.viewing = jobId;
    this.load(true);
  }

  private load(pending: boolean): void {
    let revision = this.revision + 1;
    this.loadCurrent(pending).catch((err: Error) => {
      if (this.currentRevision(revision)) {
        this.refreshing = false;
        this.canRevoke = false;
        this.grantsAvailable = false;
        this.notice = '无法读取授权';
        hilog.warn(DOMAIN, TAG, 'permission refresh failed: %{public}s', err.message);
      }
    });
  }

  private async loadCurrent(pending: boolean): Promise<void> {
    let revision = ++this.revision;
    this.refreshing = pending;
    this.canRevoke = false;
    this.grantsAvailable = false;
    this.usesAvailable = false;
    let index = Writer.loadIndex();
    let record = index.find((item: JobRecord): boolean => item.jobId === this.viewing);
    let done = latestPermissionJob(index.filter((item: JobRecord): boolean => settledPermission(item.state)));
    let selected = record !== undefined && settledPermission(record.state) ? record : done;
    let stored = selected === null || selected === undefined ? null : permissionStored(ResultStore.read(selected.jobId));
    // A first bundle route can use historical names with freshly read switches
    // before its first census completes. Foreground invalidation revokes this allowance.
    let initialRead = this.initialBundleRead && isBundleFocus(this.params) && stored === null;
    let waitForResult = pending && !initialRead;
    this.refreshing = waitForResult;
    if (!pending && stored !== null) {
      this.initialBundleRead = false;
    }
    let actions = AppStorage.get<PermissionActions>(PERMISSION_ACTIONS_KEY);
    let selection = permissionSelection(this.params, this.selectedGroup, stored, index,
      (jobId: string): string | null => ResultStore.read(jobId), RulePack.active());
    this.banner = selection.banner;
    this.missing = selection.missing;
    this.counts = stored === null ? permissionCounts([]) : stored.counts;
    this.blocks = permissionBlocks(selection.rows);
    if (selection.missing.length > 0) {
      return;
    }
    if (waitForResult || actions === undefined || !this.alive) {
      if (actions === undefined && this.missing.length === 0 && !pending) {
        this.notice = '暂不支持';
      }
      return;
    }
    let rows = selection.rows;
    if (isBundleFocus(this.params) && rows.length === 0 && !selection.knownBundle) {
      let exists = await actions.exists(this.params);
      if (!this.currentRevision(revision)) {
        return;
      }
      if (exists) {
        let current = await actions.current(this.params, []);
        if (!this.currentRevision(revision)) {
          return;
        }
        rows = permissionLines(current);
      } else {
        this.missing = '没有该应用的记录';
      }
    }
    let names = new Map<string, string[]>();
    for (let row of rows) {
      let permissions = names.get(row.bundleName) ?? [];
      if (permissions.indexOf(row.permission) < 0) {
        permissions.push(row.permission);
      }
      names.set(row.bundleName, permissions);
    }
    this.refreshing = true;
    let current = new Map<string, PermissionFact>();
    for (let bundle of names.keys()) {
      let facts = await actions.current(bundle, names.get(bundle) ?? []);
      if (!this.currentRevision(revision)) {
        return;
      }
      for (let fact of facts) {
        current.set(permissionKey(fact.bundleName, fact.permission), fact);
      }
    }
    let grants = new Map<string, boolean>();
    for (let row of rows) {
      if (!grants.has(row.permission)) {
        grants.set(row.permission, await actions.userGrant(row.permission));
      }
      if (!this.currentRevision(revision)) {
        return;
      }
      row.current = current.get(row.key) ?? null;
      row.userGrant = grants.get(row.permission) === true;
      if (row.current !== null && row.current.tokenId > 0 && row.current.grant === 'granted' &&
        !row.current.fixed && row.userGrant && actions.revokeReady()) {
        try {
          row.revokeVerified = await actions.canRevoke(row.current);
        } catch (err) {
          row.revokeVerified = false;
        }
        if (!this.currentRevision(revision)) {
          return;
        }
        row.verificationFailed = !row.revokeVerified;
      }
      let bundleFacts = Array.from(current.values()).filter((fact: PermissionFact): boolean => fact.bundleName === row.bundleName);
      row.countKnown = bundleFacts.length > 0 && bundleFacts.every((fact: PermissionFact): boolean => fact.grant !== 'unknown');
      row.sensitiveCount = new Set(bundleFacts.filter((fact: PermissionFact): boolean => fact.grant === 'granted' &&
        isSensitive(fact.permission)).map((fact: PermissionFact): string => fact.permission)).size;
      if (row.current !== null) {
        row.label = permissionName(row.permission, row.current.label);
      }
    }
    if (!this.currentRevision(revision)) {
      return;
    }
    this.canRevoke = actions.revokeReady();
    this.grantsAvailable = actions.grantsReady() && stored !== null && stored.bundlesAvailable;
    this.blocks = permissionBlocks(rows);
    this.refreshing = false;
    this.usesAvailable = stored !== null && stored.usesAvailable && actions.usesReady();
    this.uses = this.usesAvailable && stored !== null ? stored.uses : [];
    if (selected !== null && selected !== undefined && selected.state === 'done' && stored !== null &&
      this.reconciled !== selected.jobId && actions.grantsReady()) {
      this.reconciled = selected.jobId;
      await actions.reconcile(this.viewing, this.params, stored.facts);
    }
  }

  private currentRevision(revision: number): boolean {
    return this.alive && revision === this.revision;
  }

  private confirmClose(line: PermissionLine): void {
    if (!permissionCanClose(line, this.canRevoke, this.refreshing)) {
      return;
    }
    AlertDialog.show({
      title: '关闭权限',
      message: permissionConfirmation(line),
      primaryButton: { value: '取消', action: () => {} },
      secondaryButton: { value: '关闭权限', fontColor: Theme.danger, action: () => { this.closePermission(line); } }
    });
  }

  private async closePermission(line: PermissionLine): Promise<void> {
    let disposition = AppStorage.get<Disposition>(DISPOSITION_KEY);
    if (disposition === undefined || this.working || !permissionCanClose(line, this.canRevoke, this.refreshing)) {
      return;
    }
    this.working = true;
    try {
      let result = await disposition.closePermission(this.viewing, line.bundleName, line.permission, this.params);
      this.notice = result.message;
      if (this.alive) {
        let record = Writer.loadIndex().find((item: JobRecord): boolean => item.jobId === this.viewing);
        await this.loadCurrent(record !== undefined && !settledPermission(record.state));
      }
    } catch (err) {
      hilog.warn(DOMAIN, TAG, 'permission close failed');
      this.notice = '无法关闭此权限';
    }
    this.working = false;
  }
}

// Model helpers are independent of platform APIs and are exercised by host tests.
export function permissionRequest(focus: string): JobRequest {
  return { kind: 'permission', scope: 'quick', uris: [], focus: focus };
}

export function settledPermission(state: string): boolean {
  return state === 'done' || state === 'failed' || state === 'cancelled' || state === 'interrupted';
}

export function latestPermissionJob(index: JobRecord[]): JobRecord | null {
  let latest: JobRecord | null = null;
  for (let row of index) {
    if (row.kind === 'permission' && (latest === null || row.seq >= latest.seq)) {
      latest = row;
    }
  }
  return latest;
}

export function permissionStored(text: string | null): PermissionStored | null {
  if (text === null) {
    return null;
  }
  try {
    let raw = JSON.parse(text) as PermissionStored;
    if (raw === null || typeof raw !== 'object' || !(raw.facts instanceof Array) || !(raw.uses instanceof Array)) {
      return null;
    }
    let result = new PermissionStored();
    result.facts = raw.facts.filter((fact: PermissionFact): boolean => validPermissionFact(fact));
    result.uses = raw.uses.filter((use: UseFact): boolean => use !== null && typeof use === 'object' &&
      typeof use.bundleName === 'string' && typeof use.permission === 'string' && typeof use.at === 'string' &&
      typeof use.displayName === 'string' && typeof use.label === 'string');
    result.bundlesAvailable = raw.bundlesAvailable !== false;
    result.usesAvailable = raw.usesAvailable === true;
    result.counts = raw.counts instanceof Array && raw.counts.length === 8 && raw.counts.every(
      (count: PermissionCount, at: number): boolean => count !== null && typeof count === 'object' &&
        count.group === PERMISSION_GROUPS[at] && Number.isSafeInteger(count.count) && count.count >= 0)
      ? raw.counts.map((count: PermissionCount): PermissionCount => ({ group: count.group, count: count.count,
        known: count.known === true }))
      : permissionCounts(result.facts).map((count: PermissionCount): PermissionCount => ({
        group: count.group, count: count.count, known: false }));
    return result;
  } catch (err) {
    return null;
  }
}

function validPermissionFact(fact: PermissionFact): boolean {
  return fact !== null && typeof fact === 'object' && typeof fact.bundleName === 'string' &&
    typeof fact.permission === 'string' && typeof fact.displayName === 'string' && typeof fact.label === 'string' &&
    typeof fact.group === 'string' && (fact.grant === 'granted' || fact.grant === 'denied' || fact.grant === 'unknown');
}

export function permissionCounts(facts: PermissionFact[]): PermissionCount[] {
  return PERMISSION_GROUPS.map((group: string): PermissionCount => {
    let row = new PermissionCount();
    row.group = group;
    row.known = !facts.some((fact: PermissionFact): boolean => fact.group === group && fact.grant === 'unknown');
    row.count = new Set(facts.filter((fact: PermissionFact): boolean => fact.group === group &&
      fact.grant === 'granted').map((fact: PermissionFact): string => fact.bundleName)).size;
    return row;
  });
}

function permissionKey(bundleName: string, permission: string): string {
  return bundleName + ':' + permission;
}

export function permissionLines(facts: PermissionFact[]): PermissionLine[] {
  let rows: PermissionLine[] = [];
  let seen = new Set<string>();
  for (let fact of facts) {
    let key = permissionKey(fact.bundleName, fact.permission);
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    let line = new PermissionLine();
    line.key = key;
    line.bundleName = fact.bundleName;
    line.displayName = fact.displayName.length > 0 ? fact.displayName : fact.bundleName;
    line.permission = fact.permission;
    line.label = permissionName(fact.permission, fact.label);
    line.group = groupOf(fact.permission);
    line.countKnown = !facts.some((item: PermissionFact): boolean => item.bundleName === fact.bundleName && item.grant === 'unknown');
    line.sensitiveCount = new Set(facts.filter((item: PermissionFact): boolean => item.bundleName === fact.bundleName &&
      item.grant === 'granted' && isSensitive(item.permission)).map((item: PermissionFact): string => item.permission)).size;
    rows.push(line);
  }
  return rows;
}

export function permissionBlocks(rows: PermissionLine[]): PermissionBlock[] {
  let blocks = new Map<string, PermissionBlock>();
  for (let row of rows) {
    let block = blocks.get(row.permission);
    if (block === undefined) {
      block = new PermissionBlock();
      block.permission = row.permission;
      block.label = row.label;
      blocks.set(row.permission, block);
    }
    block.rows.push(row);
  }
  return Array.from(blocks.values()).sort((a: PermissionBlock, b: PermissionBlock): number =>
    a.permission < b.permission ? -1 : a.permission > b.permission ? 1 : 0);
}

export function permissionSelection(params: string, group: string, stored: PermissionStored | null,
  index: JobRecord[], read: (jobId: string) => string | null, rules: RuleLoad): PermissionSelection {
  let result = new PermissionSelection();
  if (stored !== null && !stored.bundlesAvailable) {
    result.missing = '无法获取应用列表';
    return result;
  }
  if (params.startsWith('anomaly:')) {
    result.banner = '以下为该次体检的授权记录';
    let id = params.substring('anomaly:'.length);
    let record = index.find((item: JobRecord): boolean => item.jobId === id && item.kind === 'exam');
    let report = record === undefined || !settledPermission(record.state) ? null : examOf(read(id));
    if (report === null) {
      result.missing = '没有该次体检记录';
      return result;
    }
    let facts: PermissionFact[] = [];
    for (let hit of report.apps) {
      if (Anomaly.count([hit], rules) > 0) {
        facts.push(...hitFacts(hit));
      }
    }
    result.rows = permissionLines(facts);
    return result;
  }
  if (isBundleFocus(params)) {
    let facts = stored === null ? [] : stored.facts.filter((fact: PermissionFact): boolean => fact.bundleName === params);
    result.knownBundle = facts.length > 0;
    if (facts.length === 0) {
      let candidates = index.filter((record: JobRecord): boolean => record.state === 'done' &&
        (record.kind === 'exam' || record.kind === 'malware')).sort((a: JobRecord, b: JobRecord): number => b.seq - a.seq);
      for (let record of candidates) {
        let hits = scanHits(read(record.jobId), record.kind);
        let hit = hits.find((item: ScanHit): boolean => item.fingerprint.kind === 'bundle' &&
          item.fingerprint.bundleName === params);
        if (hit !== undefined) {
          facts = hitFacts(hit);
          result.knownBundle = true;
          result.banner = '权限来自上次扫描，开关为当前状态';
          break;
        }
      }
    }
    result.rows = permissionLines(facts);
    return result;
  }
  result.rows = permissionLines(stored === null ? [] : stored.facts).filter((row: PermissionLine): boolean =>
    group.length > 0 && row.group === group);
  return result;
}

function isBundleFocus(params: string): boolean {
  return params.length > 0 && params !== 'sensitive' && params !== '其它' && PERMISSION_GROUPS.indexOf(params) < 0 &&
    !params.startsWith('anomaly:');
}

function examOf(text: string | null): ExamReport | null {
  if (text === null) {
    return null;
  }
  try {
    let report = JSON.parse(text) as ExamReport;
    return report !== null && typeof report === 'object' && report.apps instanceof Array &&
      report.apps.every((hit: ScanHit): boolean => validPermissionHit(hit)) ? report : null;
  } catch (err) {
    return null;
  }
}

function scanHits(text: string | null, kind: string): ScanHit[] {
  if (kind === 'exam') {
    let report = examOf(text);
    return report === null ? [] : report.apps;
  }
  if (text === null) {
    return [];
  }
  try {
    let report = JSON.parse(text) as ScanReport;
    return report !== null && typeof report === 'object' && report.hits instanceof Array ?
      report.hits.filter((hit: ScanHit): boolean => validPermissionHit(hit)) : [];
  } catch (err) {
    return [];
  }
}

function validPermissionHit(hit: ScanHit): boolean {
  return hit !== null && typeof hit === 'object' && hit.fingerprint !== null &&
    typeof hit.fingerprint === 'object' && typeof hit.fingerprint.kind === 'string' &&
    typeof hit.fingerprint.bundleName === 'string' && typeof hit.fingerprint.label === 'string' &&
    hit.verdict !== null && typeof hit.verdict === 'object' && typeof hit.verdict.evidence === 'string' &&
    typeof hit.action === 'string' && hit.granted instanceof Array &&
    hit.granted.every((permission: string): boolean => typeof permission === 'string');
}

function hitFacts(hit: ScanHit): PermissionFact[] {
  return hit.granted.map((permission: string): PermissionFact => ({ bundleName: hit.fingerprint.bundleName,
    displayName: hit.fingerprint.label, permission: permission, label: permissionName(permission, ''),
    group: groupOf(permission), sensitive: isSensitive(permission), declared: true, grant: 'granted', fixed: false,
    tokenId: 0, source: 'unknown' }));
}

export function permissionCanClose(line: PermissionLine, ready: boolean, refreshing: boolean): boolean {
  return !refreshing && ready && line.userGrant && line.revokeVerified && line.current !== null && line.current.tokenId > 0 &&
    line.current.grant === 'granted' && line.current.fixed === false;
}

export function permissionStatus(line: PermissionLine, ready: boolean, refreshing: boolean): string {
  if (refreshing) {
    return REFRESHING;
  }
  let fact = line.current;
  if (fact === null || fact.tokenId === 0) {
    return '无法读取授权';
  }
  if (fact.grant === 'unknown') {
    return '状态未知';
  }
  if (fact.grant === 'denied') {
    return '已关闭';
  }
  if (fact.fixed) {
    return '受系统限制，无法关闭';
  }
  if (!ready) {
    return '无法关闭此权限';
  }
  if (line.verificationFailed) {
    return '无法读取授权';
  }
  return '已授予';
}

export function permissionConfirmation(line: PermissionLine): string {
  return line.displayName + ' · ' + line.label + '\n关闭后，该应用无法再次申请此权限，需到系统设置中重新开启';
}

export function permissionName(permission: string, fallback: string): string {
  const names: string[] = ['LOCATION', 'APPROXIMATELY_LOCATION', 'LOCATION_IN_BACKGROUND', 'MEDIA_LOCATION',
    'CAMERA', 'MICROPHONE', 'READ_CONTACTS', 'WRITE_CONTACTS', 'READ_CALENDAR', 'WRITE_CALENDAR', 'RECEIVE_SMS',
    'SEND_MESSAGES', 'PLACE_CALL', 'ANSWER_CALL', 'READ_CALL_LOG', 'READ_MEDIA', 'READ_IMAGEVIDEO', 'WRITE_IMAGEVIDEO',
    'READ_AUDIO', 'WRITE_AUDIO', 'READ_DOCUMENT'];
  const labels: string[] = ['位置', '大致位置', '后台位置', '媒体位置', '相机', '麦克风', '读取通讯录', '写入通讯录',
    '读取日历', '写入日历', '接收短信', '发送短信', '拨打电话', '接听电话', '读取通话记录', '读取媒体', '读取图片和视频',
    '写入图片和视频', '读取音频', '写入音频', '读取文档'];
  let index = names.indexOf(permission.replace('ohos.permission.', ''));
  return index >= 0 ? labels[index] : fallback.length > 0 ? fallback : permission;
}
