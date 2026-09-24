import { createHash } from "node:crypto";
import type { ByteOrder } from "./types.ts";

export function sha256Hex(data: Uint8Array): string {
  return createHash("sha256").update(data).digest("hex");
}

export function sha256Short(data: Uint8Array): string {
  return sha256Hex(data).slice(0, 12);
}

export function stableId(prefix: string, ...parts: (string | number | boolean | undefined)[]): string {
  const canonical = parts
    .map((p) => (p === undefined ? "\\u0000undef" : String(p)))
    .join("\u0001");
  return `${prefix}_${sha256Short(new TextEncoder().encode(canonical))}`;
}

export function bytesToBase64(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return Buffer.from(bin, "binary").toString("base64");
}

export function base64ToBytes(b64: string): Uint8Array {
  const bin = Buffer.from(b64, "base64").toString("binary");
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i) & 0xff;
  return out;
}

export function hex32(value: number): string {
  return "0x" + (value >>> 0).toString(16).padStart(8, "0");
}

export function hex16(value: number): string {
  return "0x" + (value & 0xffff).toString(16).padStart(4, "0");
}

export class SliceError extends Error {
  constructor(
    message: string,
    readonly path?: string,
    readonly byteOffset?: number,
    readonly byteLength = 4,
    readonly actualHex?: string,
  ) {
    super(message);
    this.name = "SliceError";
  }
}

/** Bounds-checked, endian-aware reader over a fixed byte window. */
export class ByteReader {
  constructor(
    readonly buf: Uint8Array,
    readonly base: number,
    readonly endian: ByteOrder,
    readonly windowEnd: number = buf.length,
  ) {}

  private need(off: number, n: number): void {
    if (off < this.base || off + n > this.windowEnd || off + n > this.buf.length) {
      throw new SliceError(
        "read out of bounds",
        undefined,
        off,
        n,
        off < this.buf.length ? sliceHex(this.buf, off, Math.min(n, 16)) : undefined,
      );
    }
  }

  u8(off: number): number {
    this.need(off, 1);
    return this.buf[off]!;
  }

  u16(off: number): number {
    this.need(off, 2);
    const a = this.buf[off]!;
    const b = this.buf[off + 1]!;
    return this.endian === "big" ? (a << 8) | b : a | (b << 8);
  }

  u32(off: number): number {
    this.need(off, 4);
    const b = this.buf;
    return this.endian === "big"
      ? ((b[off]! << 24) >>> 0) + ((b[off + 1]! << 16) | (b[off + 2]! << 8) | b[off + 3]!)
      : ((b[off + 3]! << 24) >>> 0) + ((b[off + 2]! << 16) | (b[off + 1]! << 8) | b[off]!);
  }

  u64(off: number): bigint {
    this.need(off, 8);
    const b = this.buf;
    let v = 0n;
    for (let i = 0; i < 8; i++) {
      const idx = this.endian === "big" ? off + i : off + 7 - i;
      v = (v << 8n) | BigInt(b[idx]!);
    }
    return v;
  }

  /** C-string inside window, bounded by maxLen. */
  cstr(off: number, maxLen: number): string {
    this.need(off, Math.min(1, maxLen));
    let end = off;
    const limit = Math.min(off + maxLen, this.windowEnd, this.buf.length);
    while (end < limit && this.buf[end] !== 0) end++;
    return Buffer.from(this.buf.subarray(off, end)).toString("utf8");
  }

  sub(off: number, len: number): Uint8Array {
    this.need(off, len);
    return this.buf.subarray(off, off + len);
  }

  window(base: number, end: number, endian: ByteOrder = this.endian): ByteReader {
    return new ByteReader(this.buf, base, endian, end);
  }
}

export function sliceHex(buf: Uint8Array, start: number, len: number): string {
  const end = Math.min(start + len, buf.length);
  const parts: string[] = [];
  for (let i = start; i < end; i++) parts.push(buf[i]!.toString(16).padStart(2, "0"));
  return parts.join(" ");
}

export function hexOfBytes(bytes: Uint8Array): string {
  return sliceHex(bytes, 0, bytes.length);
}

export function alignUp(value: number, exponent: number): number {
  const a = 1 << exponent;
  return Math.ceil(value / a) * a;
}

export function isAligned(value: number, exponent: number): boolean {
  return (value & ((1 << exponent) - 1)) === 0;
}
