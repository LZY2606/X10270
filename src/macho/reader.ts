import type { Endianness } from '../../shared/types.js';
import { hexFromBytes } from '../../shared/bytes.js';

export class ByteReader {
  constructor(public readonly bytes: Uint8Array) {}

  get length(): number {
    return this.bytes.length;
  }

  slice(offset: number, length: number): Uint8Array {
    if (offset < 0 || length < 0) throw new RangeError(`negative slice at ${offset}`);
    const end = offset + length;
    if (end > this.bytes.length) {
      throw new RangeError(
        `read ${length} bytes at ${offset}, only ${this.bytes.length - offset} available`,
      );
    }
    return this.bytes.subarray(offset, end);
  }

  available(offset: number): number {
    return Math.max(0, this.bytes.length - offset);
  }

  u32(offset: number, endian: Endianness): number {
    const d = this.slice(offset, 4);
    return endian === 'big'
      ? (d[0]! << 24 | d[1]! << 16 | d[2]! << 8 | d[3]!) >>> 0
      : (d[3]! << 24 | d[2]! << 16 | d[1]! << 8 | d[0]!) >>> 0;
  }

  u32LE(offset: number): number {
    return this.u32(offset, 'little');
  }
  u32BE(offset: number): number {
    return this.u32(offset, 'big');
  }

  hex(offset: number, length: number): string {
    return hexFromBytes(this.bytes, offset, Math.min(length, this.available(offset)));
  }
}
