import { createHash } from 'node:crypto';
import type { Endian } from '../shared/types.js';

export function hex(value: number, width = 8): string {
  return `0x${value.toString(16).padStart(width, '0')}`;
}

export function hexBytes(bytes: Uint8Array, max = bytes.length): string {
  return Array.from(bytes.slice(0, max), (b) => b.toString(16).padStart(2, '0')).join(' ');
}

export function stableId(...parts: (string | number | null | undefined)[]): string {
  const text = parts.map((p) => String(p ?? '_')).join(':');
  const digest = createHash('sha256').update(text).digest('hex').slice(0, 12);
  return `${text.length > 64 ? text.slice(0, 64) : text}#${digest}`;
}

export function shortDigest(bytes: Uint8Array | string): string {
  return createHash('sha256').update(bytes).digest('hex');
}

export class Reader {
  view: DataView;
  bytes: Uint8Array;
  endian: Endian;

  constructor(bytes: Uint8Array, endian: Endian = 'be') {
    this.bytes = bytes;
    this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    this.endian = endian;
  }

  inBounds(off: number, size: number): boolean {
    return Number.isInteger(off) && off >= 0 && size >= 0 && off + size <= this.bytes.length;
  }

  u8(off: number): number {
    if (!this.inBounds(off, 1)) throw new RangeError(`u8 out of bounds at ${off}`);
    return this.view.getUint8(off);
  }

  u16(off: number, endian: Endian = this.endian): number {
    if (!this.inBounds(off, 2)) throw new RangeError(`u16 out of bounds at ${off}`);
    return this.view.getUint16(off, endian === 'le');
  }

  u32(off: number, endian: Endian = this.endian): number {
    if (!this.inBounds(off, 4)) throw new RangeError(`u32 out of bounds at ${off}`);
    return this.view.getUint32(off, endian === 'le');
  }

  u64(off: number, endian: Endian = this.endian): bigint {
    if (!this.inBounds(off, 8)) throw new RangeError(`u64 out of bounds at ${off}`);
    return this.view.getBigUint64(off, endian === 'le');
  }

  slice(off: number, size: number): Uint8Array {
    if (!this.inBounds(off, size)) throw new RangeError(`slice out of bounds at ${off}+${size}`);
    return this.bytes.subarray(off, off + size);
  }

  cstr(off: number, max: number): string {
    const end = Math.min(off + max, this.bytes.length);
    let i = off;
    while (i < end && this.bytes[i] !== 0) i += 1;
    return Buffer.from(this.bytes.subarray(off, i)).toString('utf8');
  }
}

export function base64ToBytes(b64: string): Uint8Array {
  return new Uint8Array(Buffer.from(b64, 'base64'));
}

export function bytesToBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64');
}

export function alignUp(value: number, exponent: number): number {
  const mask = (1 << exponent) - 1;
  return (value + mask) & ~mask;
}

export function isAligned(value: number, exponent: number): boolean {
  return exponent <= 0 ? true : value % 2 ** exponent === 0;
}
