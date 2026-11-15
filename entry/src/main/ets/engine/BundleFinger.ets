import cryptoFramework from '@ohos.security.cryptoFramework'
import type { CertAlgo } from '../center/CenterTypes'
import { canonicalCert } from './Decide'

export class CertificateFingerprint {
  certSha256: string = ''
  certAlgo: CertAlgo = 'none'
}

export function sha256Bytes(bytes: Uint8Array): string {
  let digest = cryptoFramework.createMd('SHA256')
  digest.updateSync({ data: bytes })
  return digestHex(digest.digestSync().data)
}

export function digestHex(bytes: Uint8Array): string {
  let text = ''
  for (let i = 0; i < bytes.length; i++) {
    text += bytes[i].toString(16).padStart(2, '0')
  }
  return text
}

export class BundleFinger {
  static read(platformFingerprint: string, certificate: Uint8Array): CertificateFingerprint {
    let result = new CertificateFingerprint()
    let normalized = canonicalCert(platformFingerprint)
    if (normalized.length > 0) {
      result.certSha256 = normalized
      result.certAlgo = 'platform-fingerprint'
    } else if (certificate.length > 0) {
      result.certSha256 = canonicalCert(sha256Bytes(certificate))
      result.certAlgo = 'sha256-of-cert-bytes'
    }
    return result
  }
}
