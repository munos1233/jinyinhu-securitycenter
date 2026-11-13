import type { JobKind, Lane } from './CenterTypes'

const MB: number = 1024 * 1024

export const largeTiers: number[] = [100 * MB, 500 * MB, 1024 * MB]
export const hashChunk: number = 1024 * 1024
export const reasonMax: number = 200
export const listMax: number = 2000
export const jobMax: number = 100
export const quarantineQuota: number = 512 * MB
export const hapReadMax: number = 200 * MB
export const hapEntriesMax: number = 200
export const hapEntryMax: number = 2 * MB
export const useLookbackMs: number = 7 * 24 * 60 * 60 * 1000
export const useListMax: number = 100
export const cloudTimeoutMs: number = 5000
export const cloudBatch: number = 50
export const gateCacheMs: number = 30000
export const cloudAlg: string = 'SHA256withECDSA'
export const cloudKid: string = 'primary'
export const heavyMaxFiles: number = 5000
export const heavyMaxBytes: number = 2 * 1024 * 1024 * 1024
export const heavyBudgetMs: number = 10 * 60 * 1000
export const lookalikeDistance: number = 2
export const lookalikeMinLength: number = 10
export const hardPrefixes: string[] = ['/system', '/vendor', '/chip_prod', '/proc', '/sys', '/dev']
export const privatePrefixes: string[] = ['/data/app', '/data/service']

export function laneOf(kind: JobKind): Lane {
  if (kind === 'protect' || kind === 'permission' || kind === 'apps') {
    return 'light'
  }
  return 'heavy'
}
