// Deterministic synthetic universal Mach-O builder used by the offline case
// pack. fat header + fat_arch entries; two 64-bit slices, each with
// LC_SEGMENT_64(__LINKEDIT) + LC_CODE_SIGNATURE, hashed code pages and an
// embedded SuperBlob containing one CodeDirectory.

import {
  CPU_SUBTYPE,
  CPU_TYPE,
  CS_HASH_TYPE,
  CS_MAGIC,
  CS_SLOT,
  LC,
  MAGIC,
} from './constants.js';
import { sha256Hex } from '../../shared/bytes.js';
import { CD, SUPERBLOB } from './codedirectory.js';

export const PAGE = 4096;
const MH_HEADER_64 = 32;
const SEG64_SIZE = 72;
const CODESIG_LC_SIZE = 16;
export const LOAD_COMMANDS_SIZE = SEG64_SIZE + CODESIG_LC_SIZE; // 88 = 0x58
export const CD_SLOT = 0x28; // CodeDirectory offset inside SuperBlob

export const BASELINE = {
  codePages: 3,
  codeLimit: 0x3000, // equals signatureDataoff: no uncovered tail
  signatureDataoff: 0x3000,
  sigLength: 0x100,
  slice1Offset: 0x2000,
  slice1AlignmentShift: 12,
  slice2AlignmentShift: 14,
} as const;

export interface SliceSpec {
  cputype: number;
  cpusubtype: number;
  alignmentShift: number;
  endianness: 'big' | 'little';
  codePages: number;
  codeLimit: number;
  signatureDataoff: number;
  sigLength: number;
}

export interface BuiltSlice {
  spec: SliceSpec;
  bytes: Uint8Array;
}

function pageFill(pageIndex: number, cputype: number): Uint8Array {
  const page = new Uint8Array(PAGE);
  page[0] = pageIndex + 1;
  page[1] = 0xa5;
  page[2] = cputype & 0xff;
  page[3] = (cputype >>> 8) & 0xff;
  for (let i = 4; i < PAGE - 4; i++) page[i] = (i * 7 + pageIndex * 31) & 0xff;
  page[PAGE - 4] = 0xde;
  page[PAGE - 3] = 0xad;
  page[PAGE - 2] = 0xbe;
  page[PAGE - 1] = 0xef;
  return page;
}

export const IDENTITY = 'com.platform.review.sample';

export interface SliceBuildOptions {
  extraUnknownBlob?: boolean;
  brokenSigMagic?: boolean;
  codeByteFlip?: { page: number; offsetInPage: number };
  rehash?: boolean;
  sizeofcmdsOverride?: number;
  endiannessOverride?: 'big' | 'little';
  codeLimitOverride?: number;
  signatureDataoffOverride?: number;
}

export function buildSlice(
  arch: { cputype: number; cpusubtype: number; alignmentShift: number },
  options: SliceBuildOptions = {},
): BuiltSlice {
  const rehash = options.rehash ?? true;
  const endianness = options.endiannessOverride ?? 'big';
  const codeLimit = options.codeLimitOverride ?? BASELINE.codeLimit;
  const signatureDataoff = options.signatureDataoffOverride ?? BASELINE.signatureDataoff;
  const sigLength = options.extraUnknownBlob ? 0x180 : BASELINE.sigLength;
  const spec: SliceSpec = {
    ...arch,
    endianness,
    codePages: BASELINE.codePages,
    codeLimit,
    signatureDataoff,
    sigLength,
  };

  const le = endianness === 'little';
  const set32 = (view: DataView, offset: number, value: number) =>
    view.setUint32(offset, value >>> 0, le);

  const size = signatureDataoff + sigLength;
  const bytes = new Uint8Array(size);
  const view = new DataView(bytes.buffer);

  set32(view, 0, le ? MAGIC.MH_CIGAM_64 : MAGIC.MH_MAGIC_64);
  set32(view, 4, arch.cputype);
  set32(view, 8, arch.cpusubtype);
  set32(view, 12, 0x00000002); // MH_EXECUTE
  set32(view, 16, 2); // ncmds
  set32(view, 20, options.sizeofcmdsOverride ?? LOAD_COMMANDS_SIZE);
  set32(view, 24, 0x00200085);
  set32(view, 28, 0);

  let off = MH_HEADER_64;
  set32(view, off, LC.LC_SEGMENT_64);
  set32(view, off + 4, SEG64_SIZE);
  bytes.set(new TextEncoder().encode('__LINKEDIT'), off + 8);
  view.setBigUint64(off + 24, 0n, le);
  view.setBigUint64(off + 32, BigInt(size), le);
  view.setBigUint64(off + 40, BigInt(signatureDataoff), le);
  view.setBigUint64(off + 48, BigInt(sigLength), le);
  set32(view, off + 56, 5);
  set32(view, off + 60, 3);
  set32(view, off + 64, 0);
  set32(view, off + 68, 0);
  off += SEG64_SIZE;

  set32(view, off, LC.LC_CODE_SIGNATURE);
  set32(view, off + 4, CODESIG_LC_SIZE);
  set32(view, off + 8, signatureDataoff);
  set32(view, off + 12, sigLength);

  for (let p = 0; p < spec.codePages; p++) {
    const page = pageFill(p, arch.cputype);
    page.set(bytes.subarray(0, LOAD_COMMANDS_SIZE), 0);
    bytes.set(page, p * PAGE);
  }

  if (options.codeByteFlip) {
    const pos = options.codeByteFlip.page * PAGE + options.codeByteFlip.offsetInPage;
    bytes[pos] = bytes[pos]! ^ 0xff;
  }

  // SuperBlob (big-endian).
  const sig = signatureDataoff;
  const be32 = (offset: number, value: number) => view.setUint32(offset, value >>> 0, false);
  be32(sig + SUPERBLOB.magic, options.brokenSigMagic ? 0x00000000 : CS_MAGIC.CSMAGIC_EMBEDDED_SIGNATURE);
  be32(sig + SUPERBLOB.length, sigLength);
  const blobCount = options.extraUnknownBlob ? 2 : 1;
  be32(sig + SUPERBLOB.count, blobCount);
  be32(sig + SUPERBLOB.entriesStart, CS_SLOT.CSSLOT_CODEDIRECTORY);
  be32(sig + SUPERBLOB.entriesStart + 4, CD_SLOT);
  if (options.extraUnknownBlob) {
    be32(sig + SUPERBLOB.entriesStart + 8, 99);
    be32(sig + SUPERBLOB.entriesStart + 12, BASELINE.sigLength);
  }

  // CodeDirectory (big-endian, real header layout).
  const cd = sig + CD_SLOT;
  const identBytes = new TextEncoder().encode(IDENTITY + '\0');
  const identOffset = 0x40;
  const hashOffset = identOffset + identBytes.length;
  const nCodeSlots = Math.ceil(codeLimit / PAGE);
  const hashSize = 32;
  const cdLength = hashOffset + nCodeSlots * hashSize;
  be32(cd + CD.magic, CS_MAGIC.CSMAGIC_CODEDIRECTORY);
  be32(cd + CD.length, cdLength);
  be32(cd + CD.version, 0x20400);
  be32(cd + CD.flags, 0);
  be32(cd + CD.hashOffset, hashOffset);
  be32(cd + CD.identOffset, identOffset);
  be32(cd + CD.nSpecialSlots, 0);
  be32(cd + CD.nCodeSlots, nCodeSlots);
  be32(cd + CD.codeLimit, codeLimit);
  view.setUint8(cd + CD.hashSize, hashSize);
  view.setUint8(cd + CD.hashType, CS_HASH_TYPE.SHA256);
  view.setUint8(cd + CD.platform, 0);
  view.setUint8(cd + CD.pageSize, 12);
  be32(cd + CD.spare2, 0);
  be32(cd + CD.scatterOffset, 0);
  bytes.set(identBytes, cd + identOffset);

  if (rehash) {
    for (let i = 0; i < nCodeSlots; i++) {
      const start = i * PAGE;
      const len = Math.min(PAGE, codeLimit - start);
      bytes.set(
        Buffer.from(sha256Hex(bytes.subarray(start, start + len)), 'hex'),
        cd + hashOffset + i * hashSize,
      );
    }
  }

  if (options.extraUnknownBlob) {
    const u = sig + BASELINE.sigLength;
    be32(u, 0xdeadbeef);
    be32(u + 4, 0x80);
  }

  return { spec, bytes };
}

export function alignUp(value: number, shift: number): number {
  const align = 1 << shift;
  return Math.ceil(value / align) * align;
}

export interface FatOptions {
  archEndianness?: 'big' | 'little';
  overrideOffsets?: (number | undefined)[];
  overrideAlignments?: (number | undefined)[];
  overrideCputypes?: (number | undefined)[];
  forceSize?: number;
}

export function buildFat(slices: BuiltSlice[], options: FatOptions = {}): {
  bytes: Uint8Array;
  sliceOffsets: number[];
} {
  const fatEndian = options.archEndianness ?? 'big';
  const le = fatEndian === 'little';
  const set32 = (view: DataView, offset: number, value: number) =>
    view.setUint32(offset, value >>> 0, le);

  const headerSize = 8 + slices.length * 20;
  const offsets: number[] = [];
  let cursor = headerSize;
  slices.forEach((slice, i) => {
    const override = options.overrideOffsets?.[i];
    if (override !== undefined) {
      offsets[i] = override;
    } else {
      const shift = options.overrideAlignments?.[i] ?? slice.spec.alignmentShift;
      offsets[i] = shift >= 32 ? cursor : alignUp(cursor, shift);
    }
    cursor = offsets[i]! + slice.bytes.length;
  });
  const end =
    options.forceSize ??
    Math.max(...slices.map((s, i) => offsets[i]! + s.bytes.length), headerSize);
  const out = new Uint8Array(end);
  const view = new DataView(out.buffer);

  // Real fat magic is big-endian. The byte-order counterexample emits FAT_CIGAM.
  view.setUint32(
    0,
    fatEndian === 'little' ? MAGIC.FAT_CIGAM : MAGIC.FAT_MAGIC,
    false,
  );
  set32(view, 4, slices.length);
  slices.forEach((slice, i) => {
    const entry = 8 + i * 20;
    set32(view, entry, options.overrideCputypes?.[i] ?? slice.spec.cputype);
    set32(view, entry + 4, slice.spec.cpusubtype);
    set32(view, entry + 8, offsets[i]!);
    set32(view, entry + 12, slice.bytes.length);
    set32(view, entry + 16, options.overrideAlignments?.[i] ?? slice.spec.alignmentShift);
    if (offsets[i]! + slice.bytes.length <= out.length) {
      out.set(slice.bytes, offsets[i]!);
    }
  });
  return { bytes: out, sliceOffsets: offsets };
}

export function baselineSlices(): BuiltSlice[] {
  return [
    buildSlice({
      cputype: CPU_TYPE.X86_64,
      cpusubtype: CPU_SUBTYPE.X86_64_ALL,
      alignmentShift: BASELINE.slice1AlignmentShift,
    }),
    buildSlice({
      cputype: CPU_TYPE.ARM64,
      cpusubtype: CPU_SUBTYPE.ARM64_ALL,
      alignmentShift: BASELINE.slice2AlignmentShift,
    }),
  ];
}
