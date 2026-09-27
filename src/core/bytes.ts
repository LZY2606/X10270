// 字节序读取 / hex / 摘要工具。纯函数，可被服务端、存储测试直接调用。
import { createHash } from 'node:crypto';

export class ByteReader {
  constructor(
    public buf: Buffer,
    public le: boolean,
    public base = 0,
  ) {}

  u8(off: number): number {
    return this.buf.readUInt8(this.base + off);
  }
  u16(off: number): number {
    return this.le
      ? this.buf.readUInt16LE(this.base + off)
      : this.buf.readUInt16BE(this.base + off);
  }
  u32(off: number): number {
    return this.le
      ? this.buf.readUInt32LE(this.base + off)
      : this.buf.readUInt32BE(this.base + off);
  }
  u64(off: number): number {
    // fat64 offset/size 为 64 位；测试案例远小于 2^32，安全读取
    const hi = this.le
      ? this.buf.readUInt32LE(this.base + off)
      : this.buf.readUInt32BE(this.base + off);
    const lo = this.le
      ? this.buf.readUInt32LE(this.base + off + 4)
      : this.buf.readUInt32BE(this.base + off + 4);
    const value = (this.le ? lo : hi) * 0x100000000 + (this.le ? hi : lo);
    if (!Number.isSafeInteger(value)) {
      throw new RangeError('u64 exceeds safe integer range');
    }
    return value;
  }
  slice(start: number, end: number): Buffer {
    return this.buf.subarray(this.base + start, this.base + end);
  }
}

export function hex(buf: Buffer, maxBytes = 64): string {
  const shown = buf.subarray(0, maxBytes);
  return shown.toString('hex').match(/.{1,2}/g)?.join(' ') ?? '';
}

export function digestBuffer(buf: Buffer, algo = 'sha256'): string {
  return `${algo}:${createHash(algo).update(buf).digest('hex')}`;
}

export function stableStringify(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value.map(stableStringify).join(',')}]`;
  }
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return `{${entries
    .map(([k, v]) => `${JSON.stringify(k)}:${stableStringify(v)}`)
    .join(',')}}`;
}

export function digestJson(value: unknown, algo = 'sha256'): string {
  return digestBuffer(Buffer.from(stableStringify(value), 'utf8'), algo);
}

let counter = 0;
export function localId(prefix: string): string {
  counter += 1;
  return `${prefix}:${process.pid.toString(36)}${counter.toString(36)}${Date.now().toString(36)}`;
}

export function toHex32(v: number): string {
  return `0x${v.toString(16).toUpperCase().padStart(8, '0')}`;
}
