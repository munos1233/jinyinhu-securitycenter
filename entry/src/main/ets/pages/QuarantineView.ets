import { hilog } from '@kit.PerformanceAnalysisKit';
import { common } from '@kit.AbilityKit';
import { picker } from '@kit.CoreFileKit';
import { Theme } from '../common/Theme';
import { CenterError } from '../center/CenterError';
import type { FileGrant, FileSource, QuarantineEntry } from '../center/CenterTypes';
import { formatBytes } from './HomeView';
import { FILES_KEY, fileNameOf } from './CleanView';

const DOMAIN: number = 0x4A59;
const TAG: string = 'Center';

const UNSUPPORTED: string = '暂不支持';
const UNREADABLE: string = '无法读取该结果';
const KEPT: string = '副本已保存，原文件仍在';
const OPEN: string = '未完成';
const STORED: string = '已隔离';
const EMPTY: string = '隔离区没有文件';
const TITLE: string = '隔离区';

/** 组合根把 Quarantine 放在这个键下。页面不直接读清单。 */
export const QUARANTINE_KEY: string = 'center.quarantine';

export interface QuarantineDesk {
  list(): QuarantineEntry[] | null;
  restore(id: string, root: string, choose: string): Promise<CenterError | null>;
  discard(id: string): Promise<CenterError | null>;
}

export class QuarantineRow {
  id: string = '';
  name: string = '';
  size: number = 0;
  status: string = '';
  detail: string = '';
  from: string = '';
  entry: QuarantineEntry | null = null;
}

@Component
export struct QuarantineView {
  @State title: string = TITLE;
  @State rows: QuarantineRow[] = [];
  @State grants: FileGrant[] = [];
  @State notice: string = '';
  @State working: boolean = false;

  aboutToAppear(): void {
    this.reload();
  }

  build() {
    Column() {
      Scroll() {
        Column() {
          Text(this.title)
            .fontSize(20)
            .fontWeight(FontWeight.Medium)
            .fontColor(Theme.text)
            .width('100%')
            .padding(20)
            .borderRadius(20)
            .backgroundColor(Theme.card)
          if (this.notice.length > 0) {
            Text(this.notice)
              .fontSize(14)
              .fontColor(Theme.accent)
              .margin({ top: 8 })
          }
          ForEach(this.rows, (row: QuarantineRow) => {
            this.entryRow(row)
          }, (row: QuarantineRow) => row.id + row.status)
        }
        .width('100%')
        .padding({ left: 16, right: 16, top: 8, bottom: 24 })
        .alignItems(HorizontalAlign.Start)
      }
      .width('100%')
      .height('100%')
      .align(Alignment.TopStart)
      .scrollBar(BarState.Off)
    }
    .width('100%')
    .height('100%')
    .backgroundColor(Theme.page)
  }

  @Builder
  entryRow(row: QuarantineRow) {
    Column() {
      Row() {
        Column() {
          Text(row.name)
            .fontSize(16)
            .fontColor(Theme.text)
          Text(row.status)
            .fontSize(13)
            .fontColor(row.status === OPEN ? Theme.warn : Theme.muted)
            .margin({ top: 4 })
          if (row.detail.length > 0) {
            Text(row.detail)
              .fontSize(12)
              .fontColor(Theme.muted)
              .margin({ top: 2 })
          }
        }
        .layoutWeight(1)
        .alignItems(HorizontalAlign.Start)
        Text(formatBytes(row.size))
          .fontSize(13)
          .fontColor(Theme.muted)
      }
      .width('100%')

      Row() {
        Text('恢复')
          .fontSize(13)
          .fontColor(Theme.accent)
          .padding({ left: 10, right: 10, top: 4, bottom: 4 })
          .onClick(() => {
            this.restore(row, '');
          })
        Text('删除')
          .fontSize(13)
          .fontColor(Theme.danger)
          .padding({ left: 10, right: 10, top: 4, bottom: 4 })
          .onClick(() => {
            this.askDelete(row);
          })
      }
      .width('100%')
      .justifyContent(FlexAlign.End)
      .margin({ top: 8 })
    }
    .width('100%')
    .padding(16)
    .margin({ top: 12 })
    .borderRadius(20)
    .backgroundColor(Theme.card)
  }

  private reload(): void {
    let files = AppStorage.get<FileSource>(FILES_KEY);
    this.grants = files === undefined ? [] : files.persisted();
    let desk = AppStorage.get<QuarantineDesk>(QUARANTINE_KEY);
    if (desk === undefined) {
      hilog.error(DOMAIN, TAG, 'quarantine desk not ready');
      this.title = UNSUPPORTED;
      this.rows = [];
      return;
    }
    let listed = desk.list();
    this.title = quarantineTitle(listed);
    this.rows = quarantineRows(listed);
  }

  private async restore(row: QuarantineRow, choose: string): Promise<void> {
    if (row.entry === null || this.working) {
      return;
    }
    let desk = AppStorage.get<QuarantineDesk>(QUARANTINE_KEY);
    if (desk === undefined) {
      this.notice = UNSUPPORTED;
      return;
    }
    this.working = true;
    let error: CenterError | null;
    try { error = await restoreCall(desk, row.entry, this.grants, choose); }
    catch (err) { this.notice = UNREADABLE; return; }
    finally { this.working = false; }
    if (error === null) {
      this.notice = '';
      this.reload();
      return;
    }
    if (choose.length === 0) {
      this.pickRestore(row);
      return;
    }
    this.notice = error.message;
  }

  private pickRestore(row: QuarantineRow): void {
    let options = new picker.DocumentSelectOptions();
    options.maxSelectNumber = 1;
    let view = new picker.DocumentViewPicker(getContext(this) as common.UIAbilityContext);
    view.select(options).then((uris: string[]) => {
      if (uris.length === 0) {
        return;
      }
      this.restore(row, restoreChoose(uris[0], row.name));
    }).catch((err: Error) => {
      hilog.warn(DOMAIN, TAG, 'quarantine picker failed: %{public}s', err.message);
    });
  }

  private askDelete(row: QuarantineRow): void {
    AlertDialog.show({
      title: '删除',
      message: deleteConfirm(row.name, row.size),
      primaryButton: {
        value: '取消',
        action: () => {
        }
      },
      secondaryButton: {
        value: '确认删除',
        fontColor: Theme.danger,
        action: () => {
          this.removeRow(row.id);
        }
      }
    });
  }

  private async removeRow(id: string): Promise<void> {
    if (this.working) return;
    let desk = AppStorage.get<QuarantineDesk>(QUARANTINE_KEY);
    if (desk === undefined) {
      this.notice = UNSUPPORTED;
      return;
    }
    this.working = true;
    let error: CenterError | null;
    try { error = await discardCall(desk, id); }
    catch (err) { this.notice = UNREADABLE; return; }
    finally { this.working = false; }
    if (error !== null) {
      this.notice = error.message;
      return;
    }
    this.notice = '';
    this.reload();
  }
}

export function quarantineRow(entry: QuarantineEntry): QuarantineRow {
  let row = new QuarantineRow();
  row.entry = entry;
  row.id = entry.id;
  row.from = entry.from;
  row.name = fileNameOf(entry.from);
  row.size = entry.size;
  if (!entry.committed) {
    row.status = OPEN;
    row.detail = KEPT;
  } else {
    row.status = STORED;
    row.detail = '';
  }
  return row;
}

export function quarantineRows(listed: QuarantineEntry[] | null): QuarantineRow[] {
  if (listed === null) {
    return [];
  }
  let out: QuarantineRow[] = [];
  for (let i = 0; i < listed.length; i++) {
    out.push(quarantineRow(listed[i]));
  }
  return out;
}

export function quarantineTitle(listed: QuarantineEntry[] | null): string {
  if (listed === null) {
    return UNREADABLE;
  }
  if (listed.length === 0) {
    return EMPTY;
  }
  return TITLE;
}

export function deleteConfirm(name: string, size: number): string {
  return '再次确认删除「' + name + '」，大小 ' + size.toString() + ' 字节（' + formatBytes(size) + '）。';
}

export function restoreRoot(from: string, grants: FileGrant[]): string {
  let best = '';
  for (let i = 0; i < grants.length; i++) {
    let uri = grants[i].uri;
    if (from.indexOf(uri) === 0 && uri.length > best.length) {
      best = uri;
    }
  }
  return best;
}

export function restoreChoose(directory: string, name: string): string {
  if (directory.length === 0 || name.length === 0) {
    return '';
  }
  let base = directory;
  if (base.charAt(base.length - 1) === '/') {
    base = base.substring(0, base.length - 1);
  }
  return base + '/' + name;
}

export function restoreCall(desk: QuarantineDesk, entry: QuarantineEntry, grants: FileGrant[],
  choose: string): Promise<CenterError | null> {
  let root = choose.length > 0 ? directoryOf(choose) : restoreRoot(entry.from, grants);
  return desk.restore(entry.id, root, choose);
}

export function discardCall(desk: QuarantineDesk, id: string): Promise<CenterError | null> {
  return desk.discard(id);
}

function directoryOf(path: string): string {
  let slash = path.lastIndexOf('/');
  if (slash <= 0) {
    return path;
  }
  return path.substring(0, slash);
}
