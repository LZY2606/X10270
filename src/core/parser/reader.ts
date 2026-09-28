import type { ByteOrder } from '../../shared/types.js';

/** Bounds-checked binary reader. Every numeric read is exact width. */
export class DataReader {
  readonly view: DataView;
  readonly u8: Uint8Array;

  constructor(
    readonly bytes: Uint8Array,
    readonly littleEndian: boolean,
    readonly base = 0,
  ) {
    this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    this.u8 = bytes;
  }

  get length(): number {
    return this.bytes.length - this.base;
  }

  order(le: boolean): DataReader {
    return new DataReader(this.bytes, le, this.base);
  }

  at(offset: number): number {
    return this.base + offset;
  }

  inRange(offset: number, width = 1): boolean {
    const abs = this.base + offset;
    return abs >= this.base && abs >= 0 && abs + width <= this.bytes.length;
  }

  u8at(offset: number): number {
    const abs = this.base + offset;
    if (abs < 0 || abs + 1 > this.bytes.length) throw new RangeError(`read past end @${abs}`);
    return this.view.getUint8(abs);
  }

  u16(offset: number): number {
    const abs = this.base + offset;
    if (abs < 0 || abs + 2 > this.bytes.length) throw new RangeError(`read past end @${abs}`);
    return this.view.getUint16(abs, this.littleEndian);
  }

  u32(offset: number): number {
    const abs = this.base + offset;
    if (abs < 0 || abs + 4 > this.bytes.length) throw new RangeError(`read past end @${abs}`);
    return this.view.getUint32(abs, this.littleEndian);
  }

  u64(offset: number): bigint {
    const abs = this.base + offset;
    if (abs < 0 || abs + 8 > this.bytes.length) throw new RangeError(`read past end @${abs}`);
    return this.view.getBigUint64(abs, this.littleEndian);
  }

  slice(from: number, len: number): Uint8Array {
    const abs = this.base + from;
    if (abs < 0 || len < 0 || abs + len > this.bytes.length) {
      throw new RangeError(`slice past end @${abs}+${len} (len=${this.bytes.length})`);
    }
    return this.bytes.subarray(abs, abs + len);
  }

  /** Returns true if [from, from+len) is fully inside the readable area. */
  covers(from: number, len: number): boolean {
    const abs = this.base + from;
    return abs >= 0 && len >= 0 && abs + len <= this.bytes.length;
  }

  hexPreview(from: number, len: number, maxBytes = 16): string {
    const take = Math.min(len, maxBytes);
    const abs = this.base + from;
    const end = Math.min(abs + take, this.bytes.length);
    const out: string[] = [];
    for (let i = abs; i < end; i++) out.push(this.bytes[i]!.toString(16).padStart(2, '0'));
    return out.join(' ');
  }
}

export function detectOrder(magic: number): { order: ByteOrder; swapped: boolean } | null {
  if (magic >>> 16 === 0xcafe || magic >>> 16 === 0xcefa) {
    return { order: 'be', swapped: false };
  }
  if ((magic & 0xffff) === 0xcafe || (magic & 0xffff) === 0xcefa) {
    return { order: 'le', swapped: false };
  }
  return null;
}
