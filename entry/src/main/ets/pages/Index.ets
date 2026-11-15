import { Theme } from '../common/Theme';
import { probeName } from '../model/ProbeStatus';
import { ArchiveView } from './ArchiveView';
import { DeviceView } from './DeviceView';
import { ExamView } from './ExamView';
import { HomeView } from './HomeView';
import { JobResultView } from './JobResultView';
import { LedgerView } from './LedgerView';
import { MalwareView } from './MalwareView';
import { ScanView } from './ScanView';
import { SocView } from './SocView';

/** 已有页面的路由。 */
export const PAGE_ROUTES: string[] = [
  'home', 'exam', 'malware', 'job', 'P1', 'P2', 'P3', 'ledger', 'report', 'archive', 'device', 'about'
];
/** 页面由后续 issue 落地，现在只有占位。 */
export const PENDING_ROUTES: string[] = [
  'clean', 'permission', 'apps', 'protect', 'quarantine'
];

@Entry
@Component
struct Index {
  private pages: NavPathStack = new NavPathStack();

  build() {
    Navigation(this.pages) {
      HomeView({
        onOpen: (route: string, params: string) => {
          this.open(route, params);
        }
      })
    }
    .mode(NavigationMode.Stack)
    .hideTitleBar(true)
    .hideToolBar(true)
    .navDestination(this.routeMap)
    .width('100%')
    .height('100%')
    .backgroundColor(Theme.page)
  }

  private open(route: string, params: string): void {
    this.pages.pushPathByName(route, params);
  }

  @Builder
  routeMap(route: string, param: Object) {
    NavDestination() {
      if (route === 'home') {
        HomeView({
          onOpen: (next: string, params: string) => {
            this.open(next, params);
          }
        })
      } else if (route === 'exam') {
        ExamView({
          jobId: routeParams(param),
          onOpen: (next: string, params: string) => {
            this.open(next, params);
          }
        })
      } else if (route === 'malware') {
        MalwareView({
          params: routeParams(param),
          onOpen: (next: string, params: string) => {
            this.open(next, params);
          }
        })
      } else if (route === 'job') {
        JobResultView({ jobId: routeParams(param) })
      } else if (route === 'P1' || route === 'P2' || route === 'P3') {
        ScanView({ only: route })
      } else if (route === 'ledger') {
        LedgerView()
      } else if (route === 'report') {
        SocView()
      } else if (route === 'archive') {
        ArchiveView()
      } else if (route === 'about') {
        ArchiveView({ section: 'about' })
      } else if (route === 'device') {
        DeviceView()
      } else if (PENDING_ROUTES.indexOf(route) >= 0) {
        pendingPage()
      }
    }
    .title(routeTitle(route))
    .backgroundColor(Theme.page)
  }
}

@Builder
function pendingPage() {
  Column() {
    Text('暂不支持')
      .fontSize(16)
      .fontColor(Theme.muted)
  }
  .width('100%')
  .height('100%')
  .justifyContent(FlexAlign.Center)
}

/** params 只能是字符串；没有定位时为空串。 */
export function routeParams(param: Object | undefined | null): string {
  return typeof param === 'string' ? param as string : '';
}

export function routeTitle(route: string): string {
  if (route === 'P1' || route === 'P2' || route === 'P3') {
    return probeName(route);
  }
  if (route === 'exam') {
    return '体检';
  }
  if (route === 'malware') {
    return '应用信誉';
  }
  if (route === 'clean') {
    return '清理';
  }
  if (route === 'permission') {
    return '权限';
  }
  if (route === 'apps') {
    return '软件';
  }
  if (route === 'protect') {
    return '防护';
  }
  if (route === 'quarantine') {
    return '隔离区';
  }
  if (route === 'job') {
    return '作业结果';
  }
  if (route === 'ledger') {
    return '风险记录';
  }
  if (route === 'report') {
    return '安全报告';
  }
  if (route === 'archive') {
    return '记录导入导出';
  }
  if (route === 'about') {
    return '安全说明';
  }
  if (route === 'device') {
    return '设备信息';
  }
  return '安全中心';
}
