/** Bounds-checked binary cursor. Reads never throw generic RangeError:
 * an exhausted read yields a position-carrying diagnostic instead. */

export interface ReadResult<T> {
  value: T | null;
  ok: boolean;
  at: number;
  diagnosticAt?: number;
}

export class ByteCursor {
  readonly view: DataView;
  offset = 0;

  constructor(readonly bytes: Uint8Array, start = 0) {
    this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    this.offset = start;
  }

  get length(): number {
    return this.bytes.length;
  }

  remaining(): number {
    return this.bytes.length - this.offset;
  }

  seek(off: number): void {
    this.offset = off;
  }

  canRead(n: number, at: number = this.offset): boolean {
    return at >= 0 && at + n <= this.bytes.length;
  }

  u32(at: number, le: boolean): ReadResult<number> {
    if (!this.canRead(4, at)) return { value: null, ok: false, at, diagnosticAt: at };
    return { value: this.view.getUint32(at, le), ok: true, at };
  }

  readU32(le: boolean): ReadResult<number> {
    const r = this.u32(this.offset, le);
    if (r.ok) this.offset += 4;
    return r;
  }

  u64(at: number, le: boolean): ReadResult<bigint> {
    if (!this.canRead(8, at)) return { value: null, ok: false, at, diagnosticAt: at };
    return { value: this.view.getBigUint64(at, le), ok: true, at };
  }

  readU64(le: boolean): ReadResult<bigint> {
    const r = this.u64(this.offset, le);
    if (r.ok) this.offset += 8;
    return r;
  }

  slice(start: number, end: number): Uint8Array | null {
    if (start < 0 || end > this.bytes.length || end < start) return null;
    return this.bytes.subarray(start, end);
  }
}

export class ByteWriter {
  private buf: Uint8Array;
  private view: DataView;
  pos = 0;

  constructor(capacity: number) {
    this.buf = new Uint8Array(capacity);
    this.view = new DataView(this.buf.buffer);
  }

  get capacity(): number {
    return this.buf.length;
  }

  u32(v: number, le: boolean, at?: number): void {
    const p = at ?? this.pos;
    this.view.setUint32(p, v >>> 0, le);
    if (at === undefined) this.pos += 4;
  }

  u64(v: bigint | number, le: boolean, at?: number): void {
    const p = at ?? this.pos;
    this.view.setBigUint64(p, BigInt(v), le);
    if (at === undefined) this.pos += 8;
  }

  bytes(data: Uint8Array, at?: number): void {
    const p = at ?? this.pos;
    this.buf.set(data, p);
    if (at === undefined) this.pos += data.length;
  }

  fill(v: number, n: number, at?: number): void {
    const p = at ?? this.pos;
    this.buf.fill(v, p, p + n);
    if (at === undefined) this.pos += n;
  }

  result(): Uint8Array {
    return this.buf.slice(0, this.pos);
  }

  raw(): Uint8Array {
    return this.buf;
  }

  position(): number {
    return this.pos;
  }
}

export function concatBytes(parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}
