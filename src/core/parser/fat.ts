import { DataReader, detectOrder } from './reader.js';
import {
  FAT_MAGIC, FAT_MAGIC_64,
  MH_MAGIC, MH_MAGIC_64, MH_CIGAM, MH_CIGAM_64,
  archName,
} from './constants.js';
import type { ByteOrder, DomainValue, FatContainer, FatArchEntry } from '../../shared/types.js';
import { bytes, cid, count, dv, flagNum } from '../domain.js';

export class ParseFatal extends Error {
  constructor(readonly code: 'format-corrupt' | 'budget-exhausted' | 'endian-mismatch',
              message: string, readonly at: number, readonly basis: 'fat-container' | 'slice-local' = 'fat-container') {
    super(message);
  }
}

export interface FatDetect {
  kind: 'fat32' | 'fat64' | 'thin';
  order: ByteOrder;
  thinLe?: boolean;
}

export function detectContainer(input: Uint8Array): FatDetect {
  if (input.length < 4) throw new ParseFatal('format-corrupt', 'file shorter than 4-byte magic', 0);
  const magic = new DataView(input.buffer, input.byteOffset, input.byteLength).getUint32(0, false);
  if (magic === FAT_MAGIC) return { kind: 'fat32', order: 'be' };
  if (magic === FAT_MAGIC_64) return { kind: 'fat64', order: 'be' };
  if (magic >>> 0 === MH_MAGIC || magic >>> 0 === MH_MAGIC_64) return { kind: 'thin', order: 'be', thinLe: false };
  if (magic >>> 0 === MH_CIGAM || magic >>> 0 === MH_CIGAM_64) return { kind: 'thin', order: 'le', thinLe: true };

  // Swapped fat magic is recognizable but the rest of the header must also be
  // byte-swapped. The parser rejects this with an explicit endianness diagnostic
  // (it must not silently reinterpret BE fields as LE).
  const le = new DataView(input.buffer, input.byteOffset, input.byteLength).getUint32(0, true);
  if (le === FAT_MAGIC || le === FAT_MAGIC_64) {
    // nfat_arch following the swapped magic is still big-endian -> provable mismatch
    if (input.length >= 8) {
      const nfatBe = new DataView(input.buffer, input.byteOffset, input.byteLength).getUint32(4, false);
      const nfatLe = new DataView(input.buffer, input.byteOffset, input.byteLength).getUint32(4, true);
      const saneBe = nfatBe >= 1 && nfatBe <= 64;
      const saneLe = nfatLe >= 1 && nfatLe <= 64;
      if (saneBe && !saneLe) {
        throw new ParseFatal('endian-mismatch',
          'fat header magic is byte-swapped but nfat_arch remains big-endian', 0);
      }
    }
    throw new ParseFatal('endian-mismatch', 'fat header magic is byte-swapped; mixed-endian header', 0);
  }
  throw new ParseFatal('format-corrupt', `unknown magic 0x${(magic >>> 0).toString(16)}`, 0);
}

export function parseFat(input: Uint8Array, maxSlices: number): FatContainer {
  const detected = detectContainer(input);
  const le = detected.order === 'le';
  const r = new DataReader(input, le);

  if (detected.kind === 'thin') {
    const magic = r.u32(0);
    const is64 = magic === MH_MAGIC_64 || magic === MH_CIGAM_64;
    const cpuType = r.u32(is64 ? 4 : 4);
    const cpuSub = r.u32(8);
    return {
      kind: 'thin',
      magic: dv(`0x${(magic >>> 0).toString(16)}`, magic >>> 0, 'magic-word', 'fat-container'),
      byteOrder: detected.order,
      declaredByteOrder: detected.order,
      nfatArch: count(1, 'slice'),
      headerSize: bytes(0, 'fat-container'),
      archTable: [{
        id: 'slice-0',
        index: 0,
        cpuType: dv(`0x${(cpuType >>> 0).toString(16)}`, cpuType >>> 0, 'cpu-type', 'slice-local'),
        cpuSubtype: dv(`0x${(cpuSub >>> 0).toString(16)}`, cpuSub >>> 0, 'cpu-subtype', 'slice-local'),
        archName: archName(cpuType, cpuSub),
        offset: bytes(0, 'fat-container'),
        size: bytes(input.length, 'fat-container'),
        align: dv('0', 0, '2^align boundary', 'fat-container'),
        alignBoundary: bytes(0, 'fat-container'),
        effectiveOffset: bytes(0, 'fat-container'),
      }],
      totalSize: bytes(input.length, 'fat-container'),
    };
  }

  const magic = r.u32(0);
  const nfat = r.u32(4);
  if (nfat === 0) throw new ParseFatal('format-corrupt', 'nfat_arch is zero', 4);
  if (nfat > 64) throw new ParseFatal('format-corrupt', `implausible nfat_arch=${nfat}`, 4);
  if (nfat > maxSlices) {
    throw new ParseFatal('budget-exhausted',
      `nfat_arch=${nfat} exceeds configured slice budget ${maxSlices}`, 4);
  }

  const entrySize = detected.kind === 'fat64' ? 32 : 20;
  const tableStart = 8;
  if (input.length < tableStart + nfat * entrySize) {
    throw new ParseFatal('format-corrupt',
      `arch table of ${nfat} entries (${entrySize}B each) exceeds file end`, tableStart);
  }

  const entries: FatArchEntry[] = [];
  for (let i = 0; i < nfat; i++) {
    const off = tableStart + i * entrySize;
    const cpuType = r.u32(off);
    const cpuSub = r.u32(off + 4);
    let sliceOff: number; let size: number; let align: number;
    if (detected.kind === 'fat64') {
      sliceOff = Number(r.u64(off + 8));
      const align64 = r.u32(off + 16);
      size = Number(r.u64(off + 24));
      align = align64;
    } else {
      sliceOff = r.u32(off + 8);
      size = r.u32(off + 12);
      align = r.u32(off + 16);
    }
    // Fat align is a power of two exponent. Boundary is never "rounded": an
    // offset must already lie on 2^align.
    let boundary: number; let eff: number | null = null; let diag: string | undefined;
    if (align > 63) {
      boundary = Number(BigInt(2) ** BigInt(Math.min(align, 63)));
      diag = `align exponent ${align} overflows addressable 2^n boundary for this file`;
    } else {
      boundary = 2 ** align;
      const rounded = (sliceOff + boundary - 1) & ~(boundary - 1);
      if (rounded !== sliceOff) {
        diag = `slice offset 0x${sliceOff.toString(16)} is not on 2^${align}=${boundary} boundary`;
      }
      eff = sliceOff;
    }
    entries.push({
      id: `slice-${i}`,
      index: i,
      cpuType: flagNum(cpuType),
      cpuSubtype: flagNum(cpuSub),
      archName: archName(cpuType, cpuSub),
      offset: bytes(sliceOff, 'fat-container'),
      size: bytes(size, 'fat-container'),
      align: dv(`${align} (2^${align})`, align, '2^align exponent', 'fat-container', diag),
      alignBoundary: bytes(boundary, 'fat-container'),
      effectiveOffset: eff === null
        ? dv('0x' + sliceOff.toString(16), null, 'byte', 'fat-container', diag)
        : bytes(sliceOff, 'fat-container'),
    });
  }

  return {
    kind: detected.kind,
    magic: dv(`0x${(magic >>> 0).toString(16)}`, magic >>> 0, 'magic-word', 'fat-container'),
    byteOrder: 'be',
    declaredByteOrder: 'be',
    nfatArch: count(nfat, 'slice'),
    headerSize: bytes(tableStart, 'fat-container'),
    archTable: entries,
    totalSize: bytes(input.length, 'fat-container'),
  };
}

/** stable identity for a parsed fat arch entry */
export function fatEntryId(e: FatArchEntry, sourceSha: string): string {
  return cid('slice', [sourceSha, e.index, e.offset.value, e.size.value, e.cpuType.value]);
}
