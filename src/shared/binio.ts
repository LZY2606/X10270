// Deterministic, dependency-free binary read/write helpers.
// All readers are bounds-checked: reading outside the available window returns
// undefined instead of fabricating a default value.

import type { ByteOrder, RawField } from './types';

export class ByteWindow {
  constructor(
    readonly buf: Uint8Array,
    readonly base: number = 0,
    readonly length: number = buf.length - base,
  ) {}

  inBounds(rel: number, width: number): boolean {
    return rel >= 0 && rel + width <= this.length;
  }

  u8(rel: number): number | undefined {
    if (!this.inBounds(rel, 1)) return undefined;
    return this.buf[this.base + rel];
  }

  read(rel: number, width: 8 | 16 | 32 | 64, order: ByteOrder): number | bigint | undefined {
    if (!this.inBounds(rel, width / 8)) return undefined;
    const abs = this.base + rel;
    if (width === 8) return this.buf[abs];
    let value = 0n;
    const bytes = width / 8;
    for (let i = 0; i < bytes; i++) {
      const src = order === 'be' ? abs + i : abs + (bytes - 1 - i);
      value = (value << 8n) | BigInt(this.buf[src]);
    }
    if (width <= 32) return Number(value & 0xffffffffn);
    return value;
  }

  u16(rel: number, order: ByteOrder): number | undefined {
    const v = this.read(rel, 16, order);
    return v === undefined ? undefined : (v as number);
  }

  u32(rel: number, order: ByteOrder): number | undefined {
    const v = this.read(rel, 32, order);
    return v === undefined ? undefined : (v as number);
  }

  u64(rel: number, order: ByteOrder): number | undefined {
    const v = this.read(rel, 64, order);
    return v === undefined ? undefined : Number(v as bigint);
  }

  slice(rel: number, len: number): Uint8Array | undefined {
    if (!this.inBounds(rel, len)) return undefined;
    return this.buf.subarray(this.base + rel, this.base + rel + len);
  }

  hex(rel: number, len: number): string {
    const s = this.slice(rel, len);
    if (!s) return '';
    return toHex(s);
  }
}

export function toHex(bytes: Uint8Array): string {
  let out = '';
  for (const b of bytes) out += b.toString(16).padStart(2, '0');
  return out;
}

export function fromHex(hex: string): Uint8Array {
  const clean = hex.trim();
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.substr(i * 2, 2), 16);
  }
  return out;
}

export class ByteBuilder {
  private parts: number[] = [];

  get length(): number {
    return this.parts.length;
  }

  bytes(): Uint8Array {
    return Uint8Array.from(this.parts);
  }

  write8(value: number): this {
    this.parts.push(value & 0xff);
    return this;
  }

  write(value: number | bigint, width: 8 | 16 | 32 | 64, order: ByteOrder): this {
    if (width === 8) return this.write8(Number(value));
    let v = BigInt(value);
    const bytes = width / 8;
    const octets: number[] = [];
    for (let i = 0; i < bytes; i++) {
      octets.push(Number(v & 0xffn));
      v >>= 8n;
    }
    const ordered = order === 'be' ? octets.reverse() : octets;
    for (const o of ordered) this.parts.push(o);
    return this;
  }

  write16(v: number, order: ByteOrder): this {
    return this.write(v, 16, order);
  }

  write32(v: number, order: ByteOrder): this {
    return this.write(v, 32, order);
  }

  write64(v: number | bigint, order: ByteOrder): this {
    return this.write(v, 64, order);
  }

  append(buf: Uint8Array | number[]): this {
    for (const b of buf) this.parts.push(b);
    return this;
  }

  /** Fill with zero up to absolute offset; never rounds existing content. */
  padTo(absoluteOffset: number, fill = 0): this {
    while (this.parts.length < absoluteOffset) this.parts.push(fill);
    return this;
  }

  patch32(absoluteOffset: number, value: number, order: ByteOrder): void {
    for (let i = 0; i < 4; i++) {
      const shift = order === 'be' ? (3 - i) * 8 : i * 8;
      this.parts[absoluteOffset + i] = (value >>> shift) & 0xff;
    }
  }

  patch16(absoluteOffset: number, value: number, order: ByteOrder): void {
    for (let i = 0; i < 2; i++) {
      const shift = order === 'be' ? (1 - i) * 8 : i * 8;
      this.parts[absoluteOffset + i] = (value >>> shift) & 0xff;
    }
  }

  rawField(
    field: string,
    rel: number,
    value: number | string,
    width: 8 | 16 | 32 | 64,
    order: ByteOrder,
    unit: RawField['unit'],
  ): RawField {
    const rawHex = this.parts
      .slice(rel, rel + width / 8)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
    return { field, value, unit, rawHex, byteOrder: order, at: rel, width };
  }
}

export function swapBytes16(v: number): number {
  return ((v & 0xff) << 8) | ((v >>> 8) & 0xff);
}

export function swapBytes32(v: number): number {
  return (
    (((v >>> 0) & 0xff) << 24) |
    (((v >>> 8) & 0xff) << 16) |
    (((v >>> 16) & 0xff) << 8) |
    (((v >>> 24) & 0xff) << 0)
  ) >>> 0;
}

export const FAT_MAGIC_BE = 0xcafebabe;
export const FAT_CIGAM_BE = 0xbebafeca;
export const MH_MAGIC_64 = 0xfeedfacf;
export const MH_CIGAM_64 = 0xcffaedfe;
export const CSMAGIC_EMBEDDED_SIGNATURE = 0xfade0cc0;
export const CSSLOT_CODEDIRECTORY = 0;
export const CS_HASHTYPE_SHA256 = 2;
