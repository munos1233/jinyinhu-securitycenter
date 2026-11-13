import type { Fingerprint, QueryKey } from '../center/CenterTypes'

class QueryKeyValue implements QueryKey {
  bundleName: string = ''
  versionCode: number = 0
  certSha256: string = ''
  sha256: string = ''
}

export function toQueryKey(fp: Fingerprint): QueryKey {
  let key = new QueryKeyValue()
  key.bundleName = fp.bundleName
  key.versionCode = fp.versionCode
  key.certSha256 = fp.certSha256
  key.sha256 = fp.sha256
  return key
}
