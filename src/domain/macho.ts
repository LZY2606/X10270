import { Reader, CorruptError, toHex } from './binary.js';
import type { Diagnostic, RawScalar, ResultKind } from './units.js';

export const FAT_MAGIC = 0xcafebabe; // 大端 fat 头
export const FAT_CIGAM = 0xbebafeca; // 小端 fat 头

export const CPU_TYPE: Record<number, string> = {
  7: 'x86',
  12: 'arm',
  18: 'ppc',
  0x01000007: 'x86_64',
  0x0100000c: 'arm64',
  0x01000012: 'ppc64',
};

export const LC_SEGMENT_64 = 0x19;
export const LC_CODE_SIGNATURE = 0x1d;

export const LOAD_COMMAND_NAMES: Record<number, string> = {
  0x1: 'LC_SEGMENT',
  0x19: 'LC_SEGMENT_64',
  0x2: 'LC_SYMTAB',
  0xb: 'LC_DYSYMTAB',
  0x1d: 'LC_CODE_SIGNATURE',
  0x21: 'LC_ENCRYPTION_INFO',
  0x2c: 'LC_ENCRYPTION_INFO_64',
  0x26: 'LC_FUNCTION_STARTS',
  0x29: 'LC_DATA_IN_CODE',
};

export interface ParseBudget {
  maxSlices: number;
  maxCommands: number;
}

export const DEFAULT_BUDGET: ParseBudget = { maxSlices: 64, maxCommands: 4096 };

export interface FatHeaderInfo {
  magic: RawScalar;
  magicMeaning: 'FAT_MAGIC' | 'FAT_CIGAM' | 'unknown';
  nfatArch: RawScalar | null;
  endian: 'big' | 'little' | 'unknown';
}

export interface SliceInfo {
  index: number;
  cputype: RawScalar;
  cpusubtype: RawScalar;
  archName: string;
  offset: RawScalar; // basis: file-offset
  size: RawScalar;
  alignExp: RawScalar;
  endian: 'big' | 'little' | 'unknown';
  is64: boolean;
  ncmds: number | null;
  sizeofcmds: number | null;
}

export interface LoadCommandInfo {
  sliceIndex: number;
  index: number;
  offset: number; // slice-offset
  cmd: RawScalar;
  cmdName: string;
  cmdsize: RawScalar;
  /** LC_CODE_SIGNATURE: 签名 blob 的 slice 相对范围 */
  sigDataOff?: number;
  sigDataSize?: number;
}

export interface FatParse {
  kind: ResultKind;
  header: FatHeaderInfo | null;
  slices: SliceInfo[];
  commands: LoadCommandInfo[];
  diagnostics: Diagnostic[];
}

function parseMachOMagic(r: Reader, at: number): { endian: 'big' | 'little' | 'unknown'; is64: boolean } {
  if (at + 4 > r.length) return { endian: 'unknown', is64: false };
  const hex = toHex(r.bytes, at, 4);
  switch (hex) {
    case 'feedfacf':
      return { endian: 'big', is64: true };
    case 'feedface':
      return { endian: 'big', is64: false };
    case 'cffaedfe':
      return { endian: 'little', is64: true };
    case 'cefaedfe':
      return { endian: 'little', is64: false };
    default:
      return { endian: 'unknown', is64: false };
  }
}

/** 解析 universal (fat) 容器：fat header、slice 表、每个 slice 的 Mach-O 头与 load commands。 */
export function parseFatContainer(bytes: Uint8Array, budget: ParseBudget = DEFAULT_BUDGET): FatParse {
  const r = new Reader(bytes, 'file-offset');
  const diagnostics: Diagnostic[] = [];
  const slices: SliceInfo[] = [];
  const commands: LoadCommandInfo[] = [];
  let header: FatHeaderInfo | null = null;
  let commandCount = 0;

  try {
    const magicHex = toHex(bytes, 0, 4);
    let magicMeaning: FatHeaderInfo['magicMeaning'] = 'unknown';
    let endian: 'big' | 'little' | 'unknown' = 'unknown';
    if (magicHex === 'cafebabe') {
      magicMeaning = 'FAT_MAGIC';
      endian = 'big';
    } else if (magicHex === 'bebafeca') {
      magicMeaning = 'FAT_CIGAM';
      endian = 'little';
    }
    if (endian === 'unknown') {
      diagnostics.push({
        code: 'fat.endianness.unknown',
        message: `unrecognized fat magic 0x${magicHex}; cannot determine container byte order`,
        range: { start: { value: 0, unit: 'byte', basis: 'file-offset' }, end: { value: 4, unit: 'byte', basis: 'file-offset' } },
        rawHex: magicHex,
      });
      header = {
        magic: { rawHex: magicHex, rawEndian: 'unknown', value: null, diagnostic: 'unrecognized fat magic; value left unconverted' },
        magicMeaning,
        nfatArch: null,
        endian,
      };
      return { kind: 'format_corrupt', header, slices, commands, diagnostics };
    }

    const magic: RawScalar = { rawHex: magicHex, rawEndian: endian, value: r.u32(0, endian) };
    const nfatArch = r.raw32(4, endian);
    header = { magic, magicMeaning, nfatArch, endian };

    if (nfatArch.value === null || nfatArch.value > budget.maxSlices) {
      diagnostics.push({
        code: 'budget.slices',
        message: `nfat_arch=${nfatArch.value} exceeds budget maxSlices=${budget.maxSlices}`,
        range: { start: { value: 4, unit: 'byte', basis: 'file-offset' }, end: { value: 8, unit: 'byte', basis: 'file-offset' } },
        rawHex: nfatArch.rawHex,
      });
      return { kind: 'budget_exhausted', header, slices, commands, diagnostics };
    }

    for (let i = 0; i < nfatArch.value; i++) {
      const base = 8 + i * 20;
      const cputype = r.raw32(base, endian);
      const cpusubtype = r.raw32(base + 4, endian);
      const offset = r.raw32(base + 8, endian);
      const size = r.raw32(base + 12, endian);
      const alignExp = r.raw32(base + 16, endian);
      const cpu = cputype.value ?? -1;
      const archName = CPU_TYPE[cpu] ?? `unknown(cputype=0x${(cpu >>> 0).toString(16)})`;

      const slice: SliceInfo = {
        index: i,
        cputype,
        cpusubtype,
        archName,
        offset,
        size,
        alignExp,
        endian: 'unknown',
        is64: false,
        ncmds: null,
        sizeofcmds: null,
      };

      if (offset.value !== null && size.value !== null && offset.value + 4 <= bytes.length) {
        const m = parseMachOMagic(r, offset.value);
        slice.endian = m.endian;
        slice.is64 = m.is64;
        if (m.endian !== 'unknown') {
          const headerSize = m.is64 ? 32 : 28;
          if (offset.value + headerSize <= bytes.length) {
            slice.ncmds = r.u32(offset.value + 16, m.endian);
            slice.sizeofcmds = r.u32(offset.value + 20, m.endian);
          }
        } else {
          diagnostics.push({
            code: 'macho.endianness.unknown',
            message: `slice ${i} (${archName}): unrecognized Mach-O magic 0x${toHex(bytes, offset.value, 4)} at file offset ${offset.value}`,
            range: {
              start: { value: offset.value, unit: 'byte', basis: 'file-offset' },
              end: { value: offset.value + 4, unit: 'byte', basis: 'file-offset' },
            },
            rawHex: toHex(bytes, offset.value, 4),
          });
        }
      }
      slices.push(slice);
    }

    // load commands per slice
    for (const slice of slices) {
      if (slice.endian === 'unknown' || slice.ncmds === null || slice.offset.value === null) continue;
      const sliceOff = slice.offset.value;
      const sliceSize = slice.size.value ?? 0;
      const headerSize = slice.is64 ? 32 : 28;
      if (slice.ncmds > budget.maxCommands - commandCount) {
        diagnostics.push({
          code: 'budget.commands',
          message: `slice ${slice.index}: ncmds=${slice.ncmds} exceeds remaining command budget`,
          range: {
            start: { value: sliceOff + 16, unit: 'byte', basis: 'file-offset' },
            end: { value: sliceOff + 20, unit: 'byte', basis: 'file-offset' },
          },
        });
        return { kind: 'budget_exhausted', header, slices, commands, diagnostics };
      }
      let cursor = headerSize;
      for (let ci = 0; ci < slice.ncmds; ci++) {
        const abs = sliceOff + cursor;
        if (cursor + 8 > sliceSize || abs + 8 > bytes.length) {
          diagnostics.push({
            code: 'loadcmd.out-of-bounds',
            message: `slice ${slice.index} command ${ci}: header at slice offset ${cursor} exceeds slice size ${sliceSize}`,
            range: {
              start: { value: cursor, unit: 'byte', basis: 'slice-offset' },
              end: { value: Math.min(cursor + 8, sliceSize), unit: 'byte', basis: 'slice-offset' },
            },
          });
          break;
        }
        const sr = new Reader(r.slice(sliceOff, Math.min(sliceSize, bytes.length - sliceOff)), 'slice-offset');
        const cmd = sr.raw32(cursor, slice.endian);
        const cmdsize = sr.raw32(cursor + 4, slice.endian);
        const cmdVal = cmd.value ?? 0;
        const sizeVal = cmdsize.value ?? 0;
        const info: LoadCommandInfo = {
          sliceIndex: slice.index,
          index: ci,
          offset: cursor,
          cmd,
          cmdName: LOAD_COMMAND_NAMES[cmdVal] ?? `LC_UNKNOWN(0x${cmdVal.toString(16)})`,
          cmdsize,
        };
        if (cmdVal === LC_CODE_SIGNATURE && sizeVal >= 16 && cursor + 16 <= sliceSize) {
          info.sigDataOff = sr.u32(cursor + 8, slice.endian);
          info.sigDataSize = sr.u32(cursor + 12, slice.endian);
        }
        commands.push(info);
        commandCount++;
        if (sizeVal < 8) break; // 交由规则层判定越界/损坏
        cursor += sizeVal;
      }
    }

    return { kind: 'ok', header, slices, commands, diagnostics };
  } catch (err) {
    if (err instanceof CorruptError) {
      diagnostics.push(r.diagnostic(err));
      return { kind: 'format_corrupt', header, slices, commands, diagnostics };
    }
    throw err;
  }
}
