const K: number[] = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

/** Incremental SHA-256, retaining at most one partial block. */
export class StreamingSha256 {
  private h: number[] = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]
  private tail: Uint8Array = new Uint8Array(64)
  private used: number = 0
  private total: number = 0
  private finished: boolean = false

  update(data: Uint8Array): void {
    if (this.finished) throw new Error('digest finished')
    this.total += data.length
    let offset = 0
    if (this.used > 0) {
      let amount = Math.min(64 - this.used, data.length)
      this.tail.set(data.subarray(0, amount), this.used)
      this.used += amount
      offset += amount
      if (this.used === 64) { this.block(this.tail, 0); this.used = 0 }
    }
    while (offset + 64 <= data.length) { this.block(data, offset); offset += 64 }
    if (offset < data.length) {
      this.tail.set(data.subarray(offset), 0)
      this.used = data.length - offset
    }
  }

  finish(): string {
    if (this.finished) throw new Error('digest finished')
    let hi = Math.floor(this.total / 0x20000000)
    let lo = (this.total * 8) >>> 0
    let size = this.used < 56 ? 64 : 128
    let final = new Uint8Array(size)
    final.set(this.tail.subarray(0, this.used))
    final[this.used] = 0x80
    final[size - 8] = (hi >>> 24) & 255
    final[size - 7] = (hi >>> 16) & 255
    final[size - 6] = (hi >>> 8) & 255
    final[size - 5] = hi & 255
    final[size - 4] = (lo >>> 24) & 255
    final[size - 3] = (lo >>> 16) & 255
    final[size - 2] = (lo >>> 8) & 255
    final[size - 1] = lo & 255
    this.block(final, 0)
    if (size === 128) this.block(final, 64)
    this.finished = true
    return this.h.map((value: number): string => value.toString(16).padStart(8, '0')).join('')
  }

  private block(data: Uint8Array, offset: number): void {
    let w: number[] = new Array<number>(64).fill(0)
    for (let i = 0; i < 16; i++) {
      let at = offset + i * 4
      w[i] = ((data[at] << 24) | (data[at + 1] << 16) | (data[at + 2] << 8) | data[at + 3]) >>> 0
    }
    for (let i = 16; i < 64; i++) {
      let s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3)
      let s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10)
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0
    }
    let a = this.h[0], b = this.h[1], c = this.h[2], d = this.h[3]
    let e = this.h[4], f = this.h[5], g = this.h[6], h = this.h[7]
    for (let i = 0; i < 64; i++) {
      let s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
      let ch = (e & f) ^ ((~e) & g)
      let t1 = (h + s1 + ch + K[i] + w[i]) >>> 0
      let s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
      let maj = (a & b) ^ (a & c) ^ (b & c)
      let t2 = (s0 + maj) >>> 0
      h = g; g = f; f = e; e = (d + t1) >>> 0
      d = c; c = b; b = a; a = (t1 + t2) >>> 0
    }
    this.h[0] = (this.h[0] + a) >>> 0; this.h[1] = (this.h[1] + b) >>> 0
    this.h[2] = (this.h[2] + c) >>> 0; this.h[3] = (this.h[3] + d) >>> 0
    this.h[4] = (this.h[4] + e) >>> 0; this.h[5] = (this.h[5] + f) >>> 0
    this.h[6] = (this.h[6] + g) >>> 0; this.h[7] = (this.h[7] + h) >>> 0
  }
}

function rotr(value: number, bits: number): number {
  return (value >>> bits) | (value << (32 - bits))
}
