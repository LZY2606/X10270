// Deterministic Mach-O / universal-binary builder used by the offline case
// pack and the counterexample archive. All offsets are explicit; nothing is
// silently rounded.

import { createHash } from 'node:crypto';
import { FAT_MAGIC, MH_MAGIC_64, LC_SEGMENT_64, LC_CODE_SIGNATURE, CSMAGIC_EMBEDDED_SIGNATURE, CSMAGIC_CODEDIRECTORY } from './const.js';

export type Arch = 'x86_64' | 'arm64' | 'arm64e';

export const CPU: Record<Arch, { type: number; sub: number }> = {
  x86_64: { type: 0x01000007, sub: 3 },
  arm64: { type: 0x0100000c, sub: 0 },
  arm64e: { type: 0x0100000c, sub: 2 },
};

export function alignUp(n: number, a: number): number {
  return Math.ceil(n / a) * a;
}

export interface ThinSpec {
  arch: Arch;
  pages: number; // number of code pages
  pageSize?: number; // bytes, default 4096
  fillSeed?: number; // deterministic code fill
  hashType?: 'sha1' | 'sha256' | 'unknown';
  extraBlobs?: Array<{ type: number; magic: number; body?: Buffer }>;
  tailBytes?: number; // trailing bytes after the signature blob (coverage gap)
  corruptSlot?: number; // code slot to corrupt after hashing (hash mismatch)
  cmdSizeOverride?: { index: number; cmdsize: number }; // command out-of-bounds
  sigDataSizeOverride?: number; // shrink declared signature coverage
}

const HEADER64 = 32;
const SEG64_SIZE = 72;
const CODESIG_SIZE = 16;

export function buildThinMachO(spec: ThinSpec): Buffer {
  const pageSize = spec.pageSize ?? 4096;
  const ncmds = 3;
  const sizeofcmds = SEG64_SIZE * 2 + CODESIG_SIZE;
  const codeLimit = alignUp(HEADER64 + sizeofcmds, pageSize) + spec.pages * pageSize;
  const linkeditOff = codeLimit;
  const linkeditSize = 64;
  const sigOff = alignUp(linkeditOff + linkeditSize, 16);

  const hashType = spec.hashType ?? 'sha256';
  const hashSize = hashType === 'sha1' ? 20 : 32;
  const hashTypeCode = hashType === 'sha1' ? 1 : hashType === 'sha256' ? 2 : 0xfe;
  const nCodeSlots = Math.ceil(codeLimit / pageSize);
  const ident = Buffer.from(`com.example.${spec.arch}\0`, 'ascii');
  const cdHeaderSize = 52; // version 0x20200
  const identOffset = cdHeaderSize;
  const hashOffset = identOffset + ident.length;
  const cdLength = hashOffset + nCodeSlots * hashSize;

  const extra = spec.extraBlobs ?? [];
  const indexCount = 1 + extra.length;
  const sbHeader = 12 + indexCount * 8;
  let cursor = sbHeader;
  const cdOffset = cursor;
  cursor += cdLength;
  const extraOffsets = extra.map((e) => {
    const o = cursor;
    cursor += e.body?.length ?? 8;
    return o;
  });
  const sbLength = cursor;

  const datasize = spec.sigDataSizeOverride ?? sbLength;
  const tail = spec.tailBytes ?? 0;
  const total = sigOff + sbLength + tail;
  const buf = Buffer.alloc(total);

  const seed = spec.fillSeed ?? 7;
  for (let i = HEADER64 + sizeofcmds; i < codeLimit; i++) {
    buf[i] = (i * 31 + seed) & 0xff;
  }

  // mach_header_64 (little-endian)
  buf.writeUInt32LE(MH_MAGIC_64, 0);
  const cpu = CPU[spec.arch];
  buf.writeInt32LE(cpu.type, 4);
  buf.writeInt32LE(cpu.sub, 8);
  buf.writeUInt32LE(2, 12); // MH_EXECUTE
  buf.writeUInt32LE(ncmds, 16);
  buf.writeUInt32LE(sizeofcmds, 20);
  buf.writeUInt32LE(0x200000, 24);
  buf.writeUInt32LE(0, 28);

  // LC_SEGMENT_64 __TEXT
  let p = HEADER64;
  buf.writeUInt32LE(LC_SEGMENT_64, p);
  buf.writeUInt32LE(SEG64_SIZE, p + 4);
  buf.write('__TEXT', p + 8, 16, 'ascii');
  buf.writeBigUInt64LE(0n, p + 24);
  buf.writeBigUInt64LE(BigInt(codeLimit), p + 32);
  buf.writeBigUInt64LE(0n, p + 40);
  buf.writeBigUInt64LE(BigInt(codeLimit), p + 48);
  buf.writeUInt32LE(5, p + 56);
  buf.writeUInt32LE(5, p + 60);

  // LC_SEGMENT_64 __LINKEDIT
  p += SEG64_SIZE;
  buf.writeUInt32LE(LC_SEGMENT_64, p);
  buf.writeUInt32LE(SEG64_SIZE, p + 4);
  buf.write('__LINKEDIT', p + 8, 16, 'ascii');
  buf.writeBigUInt64LE(BigInt(linkeditOff), p + 24);
  buf.writeBigUInt64LE(BigInt(total - linkeditOff), p + 32);
  buf.writeBigUInt64LE(BigInt(linkeditOff), p + 40);
  buf.writeBigUInt64LE(BigInt(total - linkeditOff), p + 48);
  buf.writeUInt32LE(1, p + 56);
  buf.writeUInt32LE(1, p + 60);

  // LC_CODE_SIGNATURE
  p += SEG64_SIZE;
  buf.writeUInt32LE(LC_CODE_SIGNATURE, p);
  buf.writeUInt32LE(CODESIG_SIZE, p + 4);
  buf.writeUInt32LE(sigOff, p + 8);
  buf.writeUInt32LE(datasize, p + 12);

  for (let i = 0; i < linkeditSize; i++) buf[linkeditOff + i] = 0xab;

  // CodeDirectory
  const cd = buf.subarray(sigOff + cdOffset, sigOff + cdOffset + cdLength);
  cd.writeUInt32BE(CSMAGIC_CODEDIRECTORY, 0);
  cd.writeUInt32BE(cdLength, 4);
  cd.writeUInt32BE(0x20200, 8);
  cd.writeUInt32BE(0, 12);
  cd.writeUInt32BE(hashOffset, 16);
  cd.writeUInt32BE(identOffset, 20);
  cd.writeUInt32BE(0, 24); // nSpecialSlots
  cd.writeUInt32BE(nCodeSlots, 28);
  cd.writeUInt32BE(codeLimit, 32);
  cd.writeUInt8(hashSize, 36);
  cd.writeUInt8(hashTypeCode, 37);
  cd.writeUInt8(0, 38);
  cd.writeUInt8(Math.log2(pageSize), 39);
  cd.writeUInt32BE(0, 40);
  cd.writeUInt32BE(0, 44);
  cd.writeUInt32BE(0, 48);
  ident.copy(cd, identOffset);
  for (let i = 0; i < nCodeSlots; i++) {
    const start = i * pageSize;
    const end = Math.min(start + pageSize, codeLimit);
    const algo = hashType === 'sha1' ? 'sha1' : 'sha256';
    createHash(algo).update(buf.subarray(start, end)).digest().copy(cd, hashOffset + i * hashSize);
  }

  // extra blobs (e.g. unknown-magic blob for the unsupported-format case)
  extra.forEach((e, i) => {
    const o = sigOff + extraOffsets[i];
    buf.writeUInt32BE(e.magic, o);
    buf.writeUInt32BE(e.body?.length ?? 8, o + 4);
    if (e.body) e.body.copy(buf, o);
  });

  // superblob header
  const sb = buf.subarray(sigOff, sigOff + sbLength);
  sb.writeUInt32BE(CSMAGIC_EMBEDDED_SIGNATURE, 0);
  sb.writeUInt32BE(sbLength, 4);
  sb.writeUInt32BE(indexCount, 8);
  sb.writeUInt32BE(0, 12); // CSSLOT_CODEDIRECTORY
  sb.writeUInt32BE(cdOffset, 16);
  extra.forEach((e, i) => {
    sb.writeUInt32BE(e.type, 20 + i * 8);
    sb.writeUInt32BE(extraOffsets[i], 24 + i * 8);
  });

  if (spec.corruptSlot !== undefined) {
    const pos = Math.min(codeLimit - 1, spec.corruptSlot * pageSize + 200);
    buf[pos] = buf[pos] ^ 0xff;
  }
  if (spec.cmdSizeOverride) {
    const off = HEADER64 + [0, SEG64_SIZE, SEG64_SIZE * 2][spec.cmdSizeOverride.index] + 4;
    buf.writeUInt32LE(spec.cmdSizeOverride.cmdsize >>> 0, off);
  }
  return buf;
}

export interface SliceSpec {
  arch: Arch;
  thin: Buffer;
  alignExp?: number; // default 12 (4096)
  offsetOverride?: number; // forces overlap / misalignment
  sizeOverride?: number;
  cputypeOverride?: number; // forces duplicate arch names
}

export interface FatOptions {
  magicOverride?: number; // e.g. FAT_CIGAM for the endianness case
  archEndian?: 'big' | 'little'; // endianness of fat_arch records
}

export function buildFat(slices: SliceSpec[], opts: FatOptions = {}): Buffer {
  const headerSize = 8 + slices.length * 20;
  let cursor = headerSize;
  const entries = slices.map((s, i) => {
    const alignExp = s.alignExp ?? 12;
    const alignBytes = alignExp < 31 ? 2 ** alignExp : 0;
    const offset = s.offsetOverride ?? (alignBytes ? alignUp(cursor, alignBytes) : cursor);
    const size = s.sizeOverride ?? s.thin.length;
    cursor = Math.max(cursor, offset + size);
    return { s, alignExp, offset, size };
  });
  const total = Math.max(...entries.map((e) => e.offset + e.size));
  const buf = Buffer.alloc(total);
  buf.writeUInt32BE(opts.magicOverride ?? FAT_MAGIC, 0);
  buf.writeUInt32BE(slices.length, 4);
  entries.forEach((e, i) => {
    const p = 8 + i * 20;
    const cpu = CPU[e.s.arch];
    const ct = e.s.cputypeOverride ?? cpu.type;
    if (opts.archEndian === 'little') {
      buf.writeInt32LE(ct, p);
      buf.writeInt32LE(cpu.sub, p + 4);
      buf.writeUInt32LE(e.offset, p + 8);
      buf.writeUInt32LE(e.size, p + 12);
      buf.writeUInt32LE(e.alignExp, p + 16);
    } else {
      buf.writeInt32BE(ct, p);
      buf.writeInt32BE(cpu.sub, p + 4);
      buf.writeUInt32BE(e.offset, p + 8);
      buf.writeUInt32BE(e.size, p + 12);
      buf.writeUInt32BE(e.alignExp, p + 16);
    }
  });
  entries.forEach((e) => e.s.thin.copy(buf, e.offset));
  return buf;
}
