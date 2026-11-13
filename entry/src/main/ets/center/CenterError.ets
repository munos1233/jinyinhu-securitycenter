/**
 * 界面短句。cloud 与 unsigned-cloud 的 message 不得写入 Verdict.reason。
 */

export type CenterErrorCode =
  | 'unsupported'
  | 'cancelled'
  | 'interrupted'
  | 'rejected-system-path'
  | 'io'
  | 'cloud'
  | 'unsigned-cloud'
  | 'parse'
  | 'quota'

export class CenterError {
  code: CenterErrorCode
  message: string
  raw: string

  constructor(code: CenterErrorCode, raw: string) {
    this.code = code
    this.raw = raw
    this.message = centerErrorMessage(code)
  }
}

export function centerErrorMessage(code: CenterErrorCode): string {
  if (code === 'unsupported') {
    return '当前系统不支持此功能'
  }
  if (code === 'cancelled') {
    return '已停止'
  }
  if (code === 'interrupted') {
    return '扫描已中断'
  }
  if (code === 'rejected-system-path') {
    return '系统目录已跳过'
  }
  if (code === 'cloud') {
    return '云查询失败，已使用本地结果'
  }
  if (code === 'unsigned-cloud') {
    return '云端结果无效'
  }
  if (code === 'io') {
    return '文件处理失败'
  }
  if (code === 'parse') {
    return '规则文件损坏，仍使用上一份'
  }
  return '隔离区已满'
}

export function isUiMessageNotVerdictReason(code: CenterErrorCode): boolean {
  return code === 'cloud' || code === 'unsigned-cloud'
}
