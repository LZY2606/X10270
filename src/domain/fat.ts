import { Reader } from './reader';
import { BudgetError } from './errors';
import { q, type Budget, type Diag } from '../shared/types';

export interface FatArchEntry {
  index: number;
  objectId: string;
  cputype: number;
  cpusubtype: number;
  archName: string;
  offset: number;
  size: number;
  alignExp: number;
  raw: { cputype: string; offset: string; align: string };
}

export interface FatParseResult {
  isFat: boolean;
  endian: 'le' | 'be';
  is64: boolean;
  magicHex: string;
  arches: FatArchEntry[];
  diags: Diag[];
  /** codes that abort the pipeline as `malformed` */
  fatal: boolean;
}

export function archName(cputype: number, cpusubtype: number): string {
  switch (cputype) {
    case 0x01000007:
      return 'x86_64';
    case 0x0100000c:
      return (cpusubtype & 0xff) === 2 ? 'arm64e' : 'arm64';
    case 0x00000007:
      return 'i386';
    case 0x0000000c:
      return 'arm';
    default:
      return 'cpu_0x' + cputype.toString(16);
  }
}

const FAT_HEADER = 'fat-header';

export function parseFat(buf: Buffer, matId: string, budget: Budget): FatParseResult {
  const diags: Diag[] = [];
  const fail = (diag: Diag): FatParseResult => {
    diags.push(diag);
    return { isFat: false, endian: 'be', is64: false, magicHex: '', arches: [], diags, fatal: true };
  };
  if (buf.length < 8) {
    return fail({
      code: 'header_truncated',
      message: `fat header needs 8 bytes, file has ${buf.length}`,
      objectId: FAT_HEADER,
      position: q(0, 'byte', 'file'),
    });
  }
  const beMagic = buf.readUInt32BE(0);
  let endian: 'le' | 'be';
  let is64 = false;
  if (beMagic === 0xcafebabe) endian = 'be';
  else if (beMagic === 0xbebafeca) endian = 'le';
  else if (beMagic === 0xcafebabf) {
    endian = 'be';
    is64 = true;
  } else if (beMagic === 0xbfbafeca) {
    endian = 'le';
    is64 = true;
  } else {
    return fail({
      code: 'bad_magic',
      message: `not a universal binary: magic 0x${beMagic.toString(16)}`,
      objectId: FAT_HEADER,
      position: q(0, 'byte', 'file'),
      raw: { rawHex: buf.subarray(0, 4).toString('hex'), endian: 'be' },
    });
  }
  const r = new Reader(buf, endian);
  const nfat = r.u32(4);
  if (nfat > budget.maxSlices) {
    throw new BudgetError({
      code: 'budget_exceeded',
      message: `nfat_arch ${nfat} exceeds budget maxSlices=${budget.maxSlices}`,
      objectId: FAT_HEADER,
      position: q(4, 'byte', 'file'),
    });
  }
  const entrySize = is64 ? 32 : 20;
  const arches: FatArchEntry[] = [];
  for (let i = 0; i < nfat; i++) {
    const base = 8 + i * entrySize;
    if (base + entrySize > buf.length) {
      diags.push({
        code: 'header_truncated',
        message: `arch entry ${i} truncated at file offset ${base}`,
        objectId: FAT_HEADER,
        position: q(base, 'byte', 'file'),
      });
      break;
    }
    const cputype = r.u32(base);
    const cpusubtype = r.u32(base + 4);
    const offset = is64 ? r.u64(base + 8) : r.u32(base + 8);
    const size = is64 ? r.u64(base + 16) : r.u32(base + 12);
    const alignExp = r.u32(base + (is64 ? 24 : 16));
    const objectId = `slice_${matId}_${i}`;
    arches.push({
      index: i,
      objectId,
      cputype,
      cpusubtype,
      archName: archName(cputype, cpusubtype),
      offset,
      size,
      alignExp,
      raw: {
        cputype: r.hex(base, 4),
        offset: r.hex(base + 8, is64 ? 8 : 4),
        align: r.hex(base + (is64 ? 24 : 16), 4),
      },
    });
  }
  for (const a of arches) {
    // Alignment: exponent too large to normalize stays raw with a diagnostic.
    if (a.alignExp > 32) {
      diags.push({
        code: 'align_overflow',
        message: `slice ${a.index} align exponent 2^${a.alignExp} cannot be normalized; raw value kept in place`,
        objectId: a.objectId,
        position: q(a.offset, 'byte', 'file'),
        raw: { rawHex: a.raw.align, endian, note: 'unconvertible alignment exponent, preserved as imported' },
      });
    } else {
      const alignBytes = 2 ** a.alignExp;
      if (a.offset % alignBytes !== 0) {
        diags.push({
          code: 'align_invalid',
          message: `slice ${a.index} offset 0x${a.offset.toString(16)} is not a multiple of 2^${a.alignExp}; offset is NOT rounded to fit`,
          objectId: a.objectId,
          position: q(a.offset, 'byte', 'file'),
          raw: { rawHex: a.raw.offset, endian },
        });
      }
    }
    if (a.offset + a.size > buf.length) {
      diags.push({
        code: 'slice_out_of_bounds',
        message: `slice ${a.index} range [0x${a.offset.toString(16)}, 0x${(a.offset + a.size).toString(16)}) exceeds file size 0x${buf.length.toString(16)}`,
        objectId: a.objectId,
        position: q(a.offset, 'byte', 'file'),
      });
    }
  }
  const sorted = [...arches].sort((x, y) => x.offset - y.offset || x.index - y.index);
  for (let i = 0; i + 1 < sorted.length; i++) {
    const cur = sorted[i];
    const nxt = sorted[i + 1];
    if (nxt.offset < cur.offset + cur.size) {
      diags.push({
        code: 'slice_overlap',
        message: `slice ${nxt.index} [0x${nxt.offset.toString(16)}, 0x${(nxt.offset + nxt.size).toString(16)}) overlaps slice ${cur.index} ending 0x${(cur.offset + cur.size).toString(16)}`,
        objectId: nxt.objectId,
        position: q(nxt.offset, 'byte', 'file'),
      });
    }
  }
  return {
    isFat: true,
    endian,
    is64,
    magicHex: r.hex(0, 4),
    arches,
    diags,
    fatal: false,
  };
}
