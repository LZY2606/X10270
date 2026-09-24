import type { Diagnostic, RawScalar } from './units.js';
import { byteRange } from './units.js';

export class CorruptError extends Error {
  constructor(
    message: string,
    public readonly offset: number,
    public readonly basis: 'file-offset' | 'slice-offset' | 'blob-offset',
  ) {
    super(message);
    this.name = 'CorruptError';
  }
}

export const toHex = (bytes: Uint8Array, start: number, len: number): string =>
  Array.from(bytes.subarray(start, Math.min(start + len, bytes.length)))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');

/** 有界二进制读取器：越界即抛 CorruptError（带位置），绝不返回默认值伪装成功。 */
export class Reader {
  constructor(
    public readonly bytes: Uint8Array,
    public readonly basis: 'file-offset' | 'slice-offset' | 'blob-offset' = 'file-offset',
  ) {}

  get length(): number {
    return this.bytes.length;
  }

  private check(offset: number, size: number): void {
    if (!Number.isInteger(offset) || offset < 0 || offset + size > this.bytes.length) {
      throw new CorruptError(
        `read of ${size} byte(s) at offset ${offset} exceeds buffer length ${this.bytes.length}`,
        offset,
        this.basis,
      );
    }
  }

  u8(offset: number): number {
    this.check(offset, 1);
    return this.bytes[offset];
  }

  u16(offset: number, endian: 'big' | 'little'): number {
    this.check(offset, 2);
    return endian === 'big'
      ? (this.bytes[offset] << 8) | this.bytes[offset + 1]
      : this.bytes[offset] | (this.bytes[offset + 1] << 8);
  }

  u32(offset: number, endian: 'big' | 'little'): number {
    this.check(offset, 4);
    const b = this.bytes;
    const v =
      endian === 'big'
        ? ((b[offset] << 24) | (b[offset + 1] << 16) | (b[offset + 2] << 8) | b[offset + 3]) >>> 0
        : (b[offset] | (b[offset + 1] << 8) | (b[offset + 2] << 16) | (b[offset + 3] << 24)) >>> 0;
    return v;
  }

  raw32(offset: number, endian: 'big' | 'little'): RawScalar {
    return { rawHex: toHex(this.bytes, offset, 4), rawEndian: endian, value: this.u32(offset, endian) };
  }

  slice(offset: number, len: number): Uint8Array {
    this.check(offset, len);
    return this.bytes.subarray(offset, offset + len);
  }

  diagnostic(err: unknown): Diagnostic {
    if (err instanceof CorruptError) {
      return {
        code: 'format.corrupt',
        message: err.message,
        range: byteRange(err.offset, Math.min(err.offset + 1, this.bytes.length), err.basis),
      };
    }
    return { code: 'internal.error', message: String(err) };
  }
}
