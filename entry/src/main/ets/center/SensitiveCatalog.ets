const PREFIX: string = 'ohos.permission.'

const LOCATION: string[] = ['LOCATION', 'APPROXIMATELY_LOCATION', 'LOCATION_IN_BACKGROUND', 'MEDIA_LOCATION']
const CAMERA: string[] = ['CAMERA']
const MICROPHONE: string[] = ['MICROPHONE']
const CONTACTS: string[] = ['READ_CONTACTS', 'WRITE_CONTACTS']
const CALENDAR: string[] = ['READ_CALENDAR', 'WRITE_CALENDAR']
const SMS: string[] = ['RECEIVE_SMS', 'SEND_MESSAGES']
const PHONE: string[] = ['PLACE_CALL', 'ANSWER_CALL', 'READ_CALL_LOG']
const MEDIA: string[] = [
  'READ_MEDIA',
  'READ_IMAGEVIDEO',
  'WRITE_IMAGEVIDEO',
  'READ_AUDIO',
  'WRITE_AUDIO',
  'READ_DOCUMENT'
]

function listed(permission: string, names: string[]): boolean {
  for (let i = 0; i < names.length; i++) {
    if (permission === PREFIX + names[i]) {
      return true
    }
  }
  return false
}

export function groupOf(permission: string): string {
  if (listed(permission, LOCATION)) {
    return '位置'
  }
  if (listed(permission, CAMERA)) {
    return '相机'
  }
  if (listed(permission, MICROPHONE)) {
    return '麦克风'
  }
  if (listed(permission, CONTACTS)) {
    return '通讯录'
  }
  if (listed(permission, CALENDAR)) {
    return '日历'
  }
  if (listed(permission, SMS)) {
    return '短信'
  }
  if (listed(permission, PHONE)) {
    return '电话'
  }
  if (listed(permission, MEDIA)) {
    return '媒体'
  }
  return '其它'
}

export function isSensitive(permission: string): boolean {
  return groupOf(permission) !== '其它'
}
