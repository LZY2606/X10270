// Deterministic builder for the offline case pack's synthetic universal
// Mach-O images. Every layout value is explicit; code-slot digests are
// computed over the final bytes, so results are byte-for-byte reproducible.

import { ByteBuilder, toHex } from './binio';
import { CPU_ARM64, CPU_X86_64, LC_CODE_SIGNATURE, LC_SEGMENT_64, PAGE_SIZE, SHA256_SIZE } from './macho';
import { sha256Hex } from './sha256';

export interface SliceSpec {
  cpuType: number;
  cpuSubtype: number;
  arch: string;
  alignShift: number;
  tailGap?: number;
  unknownBlob?: { type: number };
}

const CD_HEADER_V20400 = 64;
const SEG_CMD_SIZE = 72;
const CODESIG_CMD_SIZE = 16;
const HEADER_SIZE = 32;

export interface BuiltSlice {
  bytes: Uint8Array;
  codesigOffset: number;
  codesigSize: number;
  codeLimit: number;
  codeSlots: number;
}

function pad4(value: number): number {
  return (value + 3) & ~3;
}

export function buildThinSlice(spec: SliceSpec): BuiltSlice {
  const order = 'le' as const;
  const identifier = new TextEncoder().encode(`${spec.arch}-offline-case`);
  const codeSlots = 1;
  const identOffset = CD_HEADER_V20400;
  const hashOffset = pad4(identOffset + identifier.length + 1);
  const cdSize = hashOffset + codeSlots * SHA256_SIZE;
  const extraIndexCount = spec.unknownBlob ? 1 : 0;
  const superBlobSize = 12 + 8 * (1 + extraIndexCount) + 8 * extraIndexCount + cdSize;
  const codesigOffset = PAGE_SIZE + (spec.tailGap ?? 0);
  const codesigSize = superBlobSize;
  const totalFileSize = codesigOffset + codesigSize;
  const codeLimit = PAGE_SIZE;

  const b = new ByteBuilder();
  const ncmds = 3;
  const sizeofcmds = SEG_CMD_SIZE * 2 + CODESIG_CMD_SIZE;
  // mach_header_64
  b.write32(0xfeedfacf, order)
    .write32(spec.cpuType, order)
    .write32(spec.cpuSubtype, order)
    .write32(0x2, order)
    .write32(ncmds, order)
    .write32(sizeofcmds, order)
    .write32(0, order)
    .write32(0, order);

  // LC_SEGMENT_64 __TEXT
  const cmdStart = b.length;
  b.write32(LC_SEGMENT_64, order).write32(SEG_CMD_SIZE, order);
  b.append(encodeFixedName('__TEXT', 16));
  b.write64(0x100000000, order)
    .write64(PAGE_SIZE, order)
    .write64(0, order)
    .write64(PAGE_SIZE, order);
  b.write32(0x7, order).write32(0x5, order).write32(0, order).write32(0, order);
  if (b.length - cmdStart !== SEG_CMD_SIZE) throw new Error('__TEXT cmd size mismatch');

  // LC_SEGMENT_64 __LINKEDIT
  const linkeditFileSize = (spec.tailGap ?? 0) + superBlobSize;
  const cmd2 = b.length;
  b.write32(LC_SEGMENT_64, order).write32(SEG_CMD_SIZE, order);
  b.append(encodeFixedName('__LINKEDIT', 16));
  b.write64(0x100010000, order)
    .write64(0x10000, order)
    .write64(PAGE_SIZE, order)
    .write64(linkeditFileSize, order);
  b.write32(0x7, order).write32(0x3, order).write32(0, order).write32(0, order);
  if (b.length - cmd2 !== SEG_CMD_SIZE) throw new Error('__LINKEDIT cmd size mismatch');

  // LC_CODE_SIGNATURE
  b.write32(LC_CODE_SIGNATURE, order)
    .write32(CODESIG_CMD_SIZE, order)
    .write32(codesigOffset, order)
    .write32(codesigSize, order);

  // Deterministic first-page content.
  b.padTo(PAGE_SIZE, 0);
  const bytes: number[] = Array.from(b.bytes());
  for (let i = HEADER_SIZE + sizeofcmds; i < PAGE_SIZE; i++) {
    bytes[i] = (i * 31 + 7) & 0xff;
  }

  // __LINKEDIT area: optional uncovered tail gap (zero bytes) then the blob.
  while (bytes.length < codesigOffset) bytes.push(0);

  // --- SuperBlob (always big-endian) --------------------------------------
  const superStart = bytes.length;
  if (superStart !== codesigOffset) throw new Error('codesig offset mismatch');
  const be = 'be' as const;
  const count = 1 + extraIndexCount;
  push32be(bytes, 0xfade0cc0);
  push32be(bytes, superBlobSize);
  push32be(bytes, count);
  // index 0 -> CodeDirectory at offset 12 + 8*count
  const cdOffsetInBlob = 12 + 8 * count;
  push32be(bytes, 0);
  push32be(bytes, cdOffsetInBlob);
  let unknownBlobOffsetInBlob = 0;
  if (spec.unknownBlob) {
    // unknown blob lives right after the CodeDirectory
    unknownBlobOffsetInBlob = cdOffsetInBlob + cdSize;
    push32be(bytes, spec.unknownBlob.type >>> 0);
    push32be(bytes, unknownBlobOffsetInBlob);
  }

  // --- CodeDirectory -------------------------------------------------------
  const cdStart = bytes.length;
  if (cdStart - superStart !== cdOffsetInBlob) throw new Error('cd offset mismatch');
  push32be(bytes, 0xfade0c02); // CSMAGIC_CODEDIRECTORY
  push32be(bytes, cdSize);
  push32be(bytes, 0x00020400); // version supporting codeLimit64
  push32be(bytes, 0); // flags
  push32be(bytes, hashOffset);
  push32be(bytes, identOffset);
  push32be(bytes, 0); // nSpecialSlots
  push32be(bytes, codeSlots); // nCodeSlots
  push32be(bytes, codeLimit);
  bytes.push(SHA256_SIZE); // hashSize @36
  bytes.push(2); // hashType = CS_HASHTYPE_SHA256 @37
  bytes.push(0); // platform @38
  bytes.push(12); // pageSize = 2^12 @39
  push32be(bytes, 0); // spare2 @40
  push32be(bytes, 0); // scatterOffset @44
  push32be(bytes, 0); // teamOffset @48
  push32be(bytes, 0); // spare3 @52
  push32be64(bytes, 0n); // codeLimit64 @56
  if (bytes.length - cdStart !== CD_HEADER_V20400) throw new Error('cd header size mismatch');
  bytes.push(...identifier, 0);
  while (bytes.length < cdStart + hashOffset) bytes.push(0);
  const hashAt = bytes.length;
  for (let i = 0; i < codeSlots * SHA256_SIZE; i++) bytes.push(0);

  if (spec.unknownBlob) {
    // 12-byte unsupported blob (arbitrary magic on purpose).
    if (bytes.length - superStart !== unknownBlobOffsetInBlob) throw new Error('unknown blob offset mismatch');
    push32be(bytes, 0x11223344);
    push32be(bytes, 12);
    push32be(bytes, spec.unknownBlob.type >>> 0);
  }
  if (bytes.length !== totalFileSize) throw new Error(`slice size mismatch ${bytes.length} != ${totalFileSize}`);

  // Compute the code-slot digest over the exact first page of final bytes.
  const finalBytes = Uint8Array.from(bytes);
  const page0 = finalBytes.subarray(0, PAGE_SIZE);
  const digest = new Uint8Array(PAGE_SIZE);
  digest.set(page0);
  const digestHex = sha256Hex(digest);
  for (let i = 0; i < SHA256_SIZE; i++) bytes[hashAt + i] = parseInt(digestHex.substr(i * 2, 2), 16);

  return { bytes: Uint8Array.from(bytes), codesigOffset, codesigSize, codeLimit, codeSlots };
}

export interface FatLayoutEntry {
  cpuType: number;
  cpuSubtype: number;
  offset: number;
  size: number;
  alignShift: number;
  bytes: Uint8Array;
  /** Raw entry-word overrides for controlled corruptions. */
  overrides?: { cpuType?: number; offset?: number; alignShift?: number; littleEndianEntry?: boolean };
}

export function buildFat(entries: FatLayoutEntry[]): Uint8Array {
  const headerSize = 8 + entries.length * 20;
  let cursor = Math.ceil(headerSize / PAGE_SIZE) * PAGE_SIZE;
  const placed: { entry: FatLayoutEntry; at: number }[] = [];
  for (const entry of entries) {
    // Builder placements respect declared alignment explicitly; corruption
    // variants inject their own raw offset value afterwards.
    if (entry.overrides?.offset !== undefined) {
      cursor = entry.overrides.offset;
    } else {
      const alignment = 2 ** entry.alignShift;
      if (cursor % alignment !== 0) cursor = Math.ceil(cursor / alignment) * alignment;
    }
    placed.push({ entry, at: cursor });
    cursor += entry.bytes.length;
  }

  const total = cursor;
  const image = new Uint8Array(total);
  const be = 'be' as const;
  write32At(image, 0, 0xcafebabe, be);
  write32At(image, 4, entries.length, be);
  for (let i = 0; i < placed.length; i++) {
    const { entry, at } = placed[i];
    const ea = 8 + i * 20;
    const leSwap = !!entry.overrides?.littleEndianEntry;
    const order = leSwap ? ('le' as const) : be;
    write32At(image, ea + 0, entry.overrides?.cpuType ?? entry.cpuType, order);
    write32At(image, ea + 4, entry.cpuSubtype, order);
    write32At(image, ea + 8, entry.overrides?.offset ?? at, order);
    write32At(image, ea + 12, entry.size ?? entry.bytes.length, order);
    write32At(image, ea + 16, entry.overrides?.alignShift ?? entry.alignShift, order);
    image.set(entry.bytes, entry.overrides?.offset ?? at);
  }
  return image;
}

export function arm64Spec(tailGap = 0, unknownBlob = false): SliceSpec {
  return {
    cpuType: CPU_ARM64,
    cpuSubtype: 0,
    arch: 'arm64',
    alignShift: 14,
    tailGap,
    unknownBlob: unknownBlob ? { type: 0x12345678 } : undefined,
  };
}

export function x86Spec(): SliceSpec {
  return { cpuType: CPU_X86_64, cpuSubtype: 3, arch: 'x86_64', alignShift: 14 };
}

function encodeFixedName(name: string, width: number): Uint8Array {
  const out = new Uint8Array(width);
  out.set(new TextEncoder().encode(name).subarray(0, width));
  return out;
}

function push32be(bytes: number[], v: number): void {
  bytes.push((v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff);
}

function push32be64(bytes: number[], v: bigint): void {
  for (let i = 7; i >= 0; i--) bytes.push(Number((v >> BigInt(i * 8)) & 0xffn));
}

function write32At(image: Uint8Array, at: number, v: number, order: 'be' | 'le'): void {
  const octets = [(v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff];
  const ordered = order === 'be' ? octets : octets.reverse();
  for (let i = 0; i < 4; i++) image[at + i] = ordered[i];
}

export { toHex };
