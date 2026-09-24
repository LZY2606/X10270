// Deterministic synthetic universal-Mach-O builder.
//
// Produces small, fully controlled fat binaries that carry a real
// LC_CODE_SIGNATURE linkedit payload: an embedded-signature superblob with a
// CodeDirectory whose code slots are genuine page digests of the slice bytes.
// The same builder is used both for the clean baseline fixture and for the
// counterexample archive (each counterexample changes exactly one direct
// source and is re-derived independently).

import { createHash } from 'node:crypto';
import {
  CPU_SUBTYPE_ARM64_ALL,
  CPU_SUBTYPE_X86_64_ALL,
  CPU_TYPE_ARM64,
  CPU_TYPE_X86_64,
  CSMAGIC_BLOBWRAPPER,
  CSMAGIC_CODEDIRECTORY,
  CSMAGIC_EMBEDDED_SIGNATURE,
  CSMAGIC_REQUIREMENTS,
  CS_HASHTYPE_SHA256,
  CSSLOT_CODEDIRECTORY,
  CSSLOT_REQUIREMENTS,
  CSSLOT_SIGNATURE,
  FAT_MAGIC,
  FAT_MAGIC_64,
  HASH_ALGO_LENGTH,
  LC_CODE_SIGNATURE,
  LC_MAIN,
  LC_SEGMENT_64,
  LC_UUID,
  MH_MAGIC_64,
} from './constants.js';

export interface SliceSpec {
  arch: 'arm64' | 'x86_64';
  cpuType: number;
  cpuSubtype: number;
  alignExponent: number; // raw power-of-two exponent placed in fat_arch.align
  // Body length that is *signed* (CodeDirectory.codeLimit). The slice may be
  // declared larger, which is exactly how a non-covering tail is produced.
  bodySize: number;
  // Extra bytes appended after the signed region but still inside the slice.
  uncoveredTail: number;
  marker: number; // deterministic filler seed so pages differ across arches
  pageSizeExponent: number;
}

export interface BuildOptions {
  fat64?: boolean;
  slices: SliceSpec[];
}

const MACH_HEADER_64_SIZE = 32;
const SEGMENT_COMMAND_64_SIZE = 72;
const UUID_COMMAND_SIZE = 24;
const ENTRY_MAIN_SIZE = 24;
const CODE_SIGNATURE_COMMAND_SIZE = 16;

function writeU32At(buf: Uint8Array, off: number, value: number, endian: 'le' | 'be' = 'le'): void {
  const v = value >>> 0;
  if (endian === 'le') {
    buf[off] = v & 0xff;
    buf[off + 1] = (v >>> 8) & 0xff;
    buf[off + 2] = (v >>> 16) & 0xff;
    buf[off + 3] = (v >>> 24) & 0xff;
  } else {
    buf[off + 3] = v & 0xff;
    buf[off + 2] = (v >>> 8) & 0xff;
    buf[off + 1] = (v >>> 16) & 0xff;
    buf[off] = (v >>> 24) & 0xff;
  }
}

function writeU16At(buf: Uint8Array, off: number, value: number, endian: 'le' | 'be' = 'le'): void {
  if (endian === 'le') {
    buf[off] = value & 0xff;
    buf[off + 1] = (value >>> 8) & 0xff;
  } else {
    buf[off + 1] = value & 0xff;
    buf[off] = (value >>> 8) & 0xff;
  }
}

function writeUuidCommand(buf: Uint8Array, off: number, seed: number): void {
  writeU32At(buf, off, LC_UUID);
  writeU32At(buf, off + 4, UUID_COMMAND_SIZE);
  for (let i = 0; i < 16; i += 1) buf[off + 8 + i] = (seed + i * 17) & 0xff;
}

function buildCodeDirectory(spec: SliceSpec, sliceBody: Uint8Array, codeLimit: number): Uint8Array {
  const pageSize = 2 ** spec.pageSizeExponent;
  const hashLen = HASH_ALGO_LENGTH[CS_HASHTYPE_SHA256];
  const codePages = Math.ceil(codeLimit / pageSize);
  const headerLen = 44; // CodeDirectory scalar fields used here (v20100)
  const scatterOffset = headerLen;
  const codeSlotsOffset = scatterOffset; // no scatter slots
  const specialSlotsOffset = codeSlotsOffset + codePages * hashLen;
  const cdLength = specialSlotsOffset + 1 * hashLen; // one special slot (signature=-1)

  const cd = new Uint8Array(cdLength);
  writeU32At(cd, 0, CSMAGIC_CODEDIRECTORY, 'be');
  writeU32At(cd, 4, cdLength, 'be');
  writeU32At(cd, 8, 0x20200, 'be'); // version
  writeU32At(cd, 12, 0, 'be'); // flags
  // offsets (scalar layout)
  cd[16] = hashLen; // hashOffset -> special slot base
  cd[17] = 0; // identOffset (none)
  cd[18] = 0; // nSpecialSlots filled below
  cd[19] = codePages; // nCodeSlots
  writeU32At(cd, 20, codeLimit, 'be');
  cd[24] = spec.pageSizeExponent; // hashSize=1 byte field; pageSize follows
  writeU32At(cd, 28, CS_HASHTYPE_SHA256, 'be'); // hashType
  // digest positions: leave the code slot digests to be filled below.
  // Special slot count written explicitly (one byte at offset 18)
  cd[18] = 1;

  for (let page = 0; page < codePages; page += 1) {
    const start = page * pageSize;
    const end = Math.min(start + pageSize, codeLimit);
    const h = createHash('sha256').update(sliceBody.subarray(start, end)).digest();
    cd.set(h, codeSlotsOffset + page * hashLen);
  }
  // Special slot -1 (CMS blob) — zero for the offline fixture.
  for (let i = 0; i < hashLen; i += 1) cd[specialSlotsOffset + i] = 0;
  return cd;
}

function buildRequirements(seed: number): Uint8Array {
  // Minimal designated-requirement style blob; only magic/length matter to review.
  const length = 12 + 8;
  const b = new Uint8Array(length);
  writeU32At(b, 0, CSMAGIC_REQUIREMENTS, 'be');
  writeU32At(b, 4, length, 'be');
  writeU32At(b, 8, 1, 'be'); // count
  writeU32At(b, 12, 2, 'be'); // type
  writeU32At(b, 16, seed & 0xff, 'be'); // payload
  return b;
}

function buildCmsWrapper(): Uint8Array {
  const b = new Uint8Array(12);
  writeU32At(b, 0, CSMAGIC_BLOBWRAPPER, 'be');
  writeU32At(b, 4, 12, 'be');
  return b;
}

interface IndexedBlob {
  slot: number;
  bytes: Uint8Array;
}

function buildSuperblob(spec: SliceSpec, sliceBody: Uint8Array, codeLimit: number): { blob: Uint8Array; codeDirectoryOffset: number } {
  const blobs: IndexedBlob[] = [
    { slot: CSSLOT_CODEDIRECTORY, bytes: buildCodeDirectory(spec, sliceBody, codeLimit) },
    { slot: CSSLOT_REQUIREMENTS, bytes: buildRequirements(spec.marker) },
    { slot: CSSLOT_SIGNATURE, bytes: buildCmsWrapper() },
  ].sort((a, b) => a.slot - b.slot);

  const indexEntrySize = 8; // uint32 type + uint32 offset
  const headerSize = 8 + indexEntrySize * blobs.length;
  const offsets: number[] = [];
  let cursor = headerSize;
  for (const entry of blobs) {
    offsets.push(cursor);
    cursor += entry.bytes.length;
  }
  const out = new Uint8Array(cursor);
  writeU32At(out, 0, CSMAGIC_EMBEDDED_SIGNATURE, 'be');
  writeU32At(out, 4, cursor, 'be');
  writeU32At(out, 8, blobs.length, 'be');
  blobs.forEach((entry, i) => {
    writeU32At(out, 12 + i * 8, entry.slot, 'be');
    writeU32At(out, 16 + i * 8, offsets[i], 'be');
    out.set(entry.bytes, offsets[i]);
  });
  const codeDirectoryOffset = offsets[blobs.findIndex((e) => e.slot === CSSLOT_CODEDIRECTORY)];
  return { blob: out, codeDirectoryOffset };
}

// Builds one Mach-O slice. Returns the bytes plus the declared linkedit range.
export function buildSlice(spec: SliceSpec): {
  bytes: Uint8Array;
  linkeditDataoff: number;
  linkeditDatasize: number;
  codeLimit: number;
} {
  const ncmds = 4;
  const sizeofcmds =
    SEGMENT_COMMAND_64_SIZE + UUID_COMMAND_SIZE + ENTRY_MAIN_SIZE + CODE_SIGNATURE_COMMAND_SIZE;

  const { blob: sigBlob } = buildSuperBlobPlaceholder: never;
}
