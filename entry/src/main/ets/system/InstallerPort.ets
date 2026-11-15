import type { BusinessError } from '@ohos.base';
import installer from '@ohos.bundle.installer';
import { hilog } from '@kit.PerformanceAnalysisKit';
import { CenterError } from '../center/CenterError';
import type { InstallerPort } from '../center/CenterTypes';

const DOMAIN: number = 0x4A59
const TAG: string = 'Center'

/** 201：权限被拒；202：非系统应用；801：本设备没有该接口。 */
const REFUSED: string[] = ['201', '202', '801']

export interface UninstallTool {
  uninstall(bundleName: string): Promise<void>
}

/** 只执行卸载。能不能卸载由 SystemGate.uninstall() 探测，这里不再探测。 */
export class GatedInstallerPort implements InstallerPort {
  private tool: () => Promise<UninstallTool>

  constructor(tool: () => Promise<UninstallTool>) {
    this.tool = tool
  }

  async uninstall(bundleName: string): Promise<void> {
    if (typeof bundleName !== 'string' || bundleName.length === 0) {
      throw new CenterError('io', 'uninstall:empty-bundle')
    }
    try {
      let tool = await this.tool()
      await tool.uninstall(bundleName)
    } catch (err) {
      let code = codeOf(err as Object)
      let raw = 'uninstall:' + code
      hilog.error(DOMAIN, TAG, 'installer uninstall %{public}s failed: %{public}s', bundleName, code)
      throw new CenterError(REFUSED.indexOf(code) >= 0 ? 'unsupported' : 'io', raw)
    }
    hilog.info(DOMAIN, TAG, 'installer uninstalled %{public}s', bundleName)
  }
}

export function sdkUninstallTool(): Promise<UninstallTool> {
  return installer.getBundleInstaller()
}

function codeOf(err: Object): string {
  try {
    let code = (err as BusinessError).code
    if (code !== undefined && code !== null) {
      return String(code)
    }
  } catch (e) {
  }
  return 'error'
}
