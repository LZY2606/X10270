// 字节读取器：显式字节序，不猜。越界读取返回带位置诊断，不抛异常。
export type Endian = 'big' | 'little';

export interface ReadResult<T> { ok: true; value: T } | { ok: false; pos: number; code: string; message: string }

export class ByteReader {
  constructor(public readonly buf: Uint8Array, public readonly endian: Endian, public readonly base = 0) {}

  u32(off: number): ReadResult<number> {
    if (off < 0 || off + 4 > this.buf.length) {
      return { ok: false, pos: this.base + off, code: 'READ_OUT_OF_BOUNDS',
        message: `读取 u32 越界: offset=${off}, len=${this.buf.length}` };
    }
    const v = this.endian === 'big'
      ? (this.buf[off] << 24 | this.buf[off+1] << 16 | this.buf[off+2] << 8 | this.buf[off+3]) >>> 0
      : (this.buf[off] | this.buf[off+1] << 8 | this.buf[off+2] << 16 | this.buf[off+3] << 24) >>> 0;
    return { ok: true, value: v };
  }

  slice(off: number, len: number): ReadResult<Uint8Array> {
    if (off < 0 || len < 0 || off + len > this.buf.length) {
      return { ok: false, pos: this.base + off, code: 'READ_OUT_OF_BOUNDS',
        message: `切片越界: offset=${off}, len=${len}, buflen=${this.buf.length}` };
    }
    return { ok: true, value: this.buf.subarray(off, off + len) };
  }
}

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}
export function fromHex(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

// FNV-1a 32 位摘要：确定性、无外部依赖，用于输入摘要与身份派生。
export function digest(bytes: Uint8Array | string): string {
  const data = typeof bytes === 'string' ? new TextEncoder().encode(bytes) : bytes;
  let h = 0x811c9dc5;
  for (const b of data) { h ^= b; h = Math.imul(h, 0x01000193) >>> 0; }
  return h.toString(16).padStart(8, '0');
}
