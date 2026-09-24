export class Reader {
  constructor(
    public readonly buf: Buffer,
    public readonly endian: 'le' | 'be',
  ) {}
  u8(off: number): number {
    return this.buf.readUInt8(off);
  }
  u16(off: number): number {
    return this.endian === 'le' ? this.buf.readUInt16LE(off) : this.buf.readUInt16BE(off);
  }
  u32(off: number): number {
    return this.endian === 'le' ? this.buf.readUInt32LE(off) : this.buf.readUInt32BE(off);
  }
  u64(off: number): number {
    const v = this.endian === 'le' ? this.buf.readBigUInt64LE(off) : this.buf.readBigUInt64BE(off);
    if (v > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new RangeError(`u64 at ${off} exceeds safe integer range`);
    }
    return Number(v);
  }
  hex(off: number, len: number): string {
    return this.buf.subarray(off, off + len).toString('hex');
  }
}
