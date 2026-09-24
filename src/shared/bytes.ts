/** 字节级读取：全部带显式字节序，绝不依赖宿主默认字节序。 */
import type { Endian } from './types.js';

export class ByteView {
  constructor(readonly buf: Uint8Array) {}

  get length(): number {
    return this.buf.length;
  }

  has(off: number, n: number): boolean {
    return off >= 0 && n >= 0 && off + n <= this.buf.length;
  }

  u8(off: number): number | null {
    if (!this.has(off, 1)) return null;
    return this.buf[off];
  }

  read(off: number, n: number, endian: Endian): number | null {
    if (!this.has(off, n)) return null;
    let v = 0;
    if (endian === 'be') {
      for (let i = 0; i < n; i++) v = v * 256 + this.buf[off + i];
    } else {
      for (let i = n - 1; i >= 0; i--) v = v * 256 + this.buf[off + i];
    }
    return v;
  }

  slice(off: number, n: number): Uint8Array | null {
    if (!this.has(off, n)) return null;
    return this.buf.subarray(off, off + n);
  }

  hex(off: number, n: number): string | null {
    const s = this.slice(off, n);
    if (!s) return null;
    return [...s].map((b) => b.toString(16).padStart(2, '0')).join('');
  }
}

export function detectSwapped(magic: number, beMagic: number, leMagic: number): Endian | null {
  if (magic === beMagic) return 'be';
  if (magic === leMagic) return 'le';
  return null;
}

export function hex32(n: number): string {
  return '0x' + (n >>> 0).toString(16).padStart(8, '0');
}

export function toBase64(bytes: Uint8Array): string {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

export function fromBase64(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
