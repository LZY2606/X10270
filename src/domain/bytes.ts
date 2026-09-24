/** 字节序感知的只读视图：越界读取不抛异常，返回 {ok:false} 让上层产生带位置诊断。 */

export class ByteView {
  readonly buf: Buffer;
  constructor(buf: Buffer) {
    this.buf = buf;
  }
  get length(): number {
    return this.buf.length;
  }
  u32(offset: number, endian: "big" | "little"): number | null {
    if (offset < 0 || offset + 4 > this.buf.length) return null;
    return endian === "big"
      ? this.buf.readUInt32BE(offset)
      : this.buf.readUInt32LE(offset);
  }
  u64(offset: number, endian: "big" | "little"): bigint | null {
    if (offset < 0 || offset + 8 > this.buf.length) return null;
    return endian === "big"
      ? this.buf.readBigUInt64BE(offset)
      : this.buf.readBigUInt64LE(offset);
  }
  slice(start: number, end: number): Buffer | null {
    if (start < 0 || end > this.buf.length || start > end) return null;
    return this.buf.subarray(start, end);
  }
  hex(start: number, len: number): string {
    const s = this.slice(start, start + len);
    return s ? Buffer.from(s).toString("hex") : "";
  }
  raw(start: number, len: number): number[] {
    const s = this.slice(start, start + len);
    return s ? Array.from(s) : [];
  }
}

export function sha1Hex(buf: Buffer): string {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { createHash } = require("node:crypto") as typeof import("node:crypto");
  return createHash("sha1").update(buf).digest("hex");
}

export function rangesOverlap(a: { start: number; end: number }, b: { start: number; end: number }): boolean {
  return a.start < b.end && b.start < a.end;
}

export function digestBuf(buf: Buffer): string {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { createHash } = require("node:crypto") as typeof import("node:crypto");
  return createHash("sha256").update(buf).digest("hex");
}
