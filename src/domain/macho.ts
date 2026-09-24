import { Reader } from './reader';
import { BudgetError } from './errors';
import { q, type Budget, type Diag } from '../shared/types';

export interface MachCommand {
  index: number;
  objectId: string;
  cmd: number;
  cmdName: string;
  cmdsize: number;
  offset: number; // slice-basis
  inBounds: boolean;
  rawHex: string;
}

export interface MachParse {
  endian: 'le' | 'be';
  is64: boolean;
  cputype: number;
  ncmds: number;
  sizeofcmds: number;
  commands: MachCommand[];
  diags: Diag[];
  fatal: boolean;
  codeSig?: { dataoff: number; datasize: number };
}

export function cmdName(cmd: number): string {
  const names: Record<number, string> = {
    0x1: 'LC_SEGMENT',
    0x2: 'LC_SYMTAB',
    0xb: 'LC_DYSYMTAB',
    0xc: 'LC_LOAD_DYLIB',
    0x19: 'LC_SEGMENT_64',
    0x1b: 'LC_UUID',
    0x1d: 'LC_CODE_SIGNATURE',
    0x21: 'LC_ENCRYPTION_INFO',
    0x22: 'LC_VERSION_MIN_MACOSX',
    0x24: 'LC_UNIXTHREAD',
    0x26: 'LC_FUNCTION_STARTS',
    0x29: 'LC_DATA_IN_CODE',
    0x2a: 'LC_SOURCE_VERSION',
    0x2c: 'LC_ENCRYPTION_INFO_64',
    0x32: 'LC_BUILD_VERSION',
  };
  return names[cmd] ?? `LC_0x${cmd.toString(16)}`;
}

export function parseMacho(
  slice: Buffer,
  sliceId: string,
  fileOffset: number,
  budget: Budget,
): MachParse {
  const diags: Diag[] = [];
  const base: MachParse = {
    endian: 'le',
    is64: false,
    cputype: 0,
    ncmds: 0,
    sizeofcmds: 0,
    commands: [],
    diags,
    fatal: false,
  };
  if (slice.length < 28) {
    diags.push({
      code: 'header_truncated',
      message: `mach header needs 28 bytes, slice has ${slice.length}`,
      objectId: sliceId,
      position: q(fileOffset, 'byte', 'file'),
    });
    return { ...base, fatal: true };
  }
  const beMagic = slice.readUInt32BE(0);
  let endian: 'le' | 'be';
  let is64: boolean;
  if (beMagic === 0xfeedface) {
    endian = 'be';
    is64 = false;
  } else if (beMagic === 0xfeedfacf) {
    endian = 'be';
    is64 = true;
  } else if (beMagic === 0xcefaedfe) {
    endian = 'le';
    is64 = false;
  } else if (beMagic === 0xcffaedfe) {
    endian = 'le';
    is64 = true;
  } else {
    diags.push({
      code: 'bad_magic',
      message: `bad mach magic 0x${beMagic.toString(16)} in slice`,
      objectId: sliceId,
      position: q(fileOffset, 'byte', 'file'),
      raw: { rawHex: slice.subarray(0, 4).toString('hex'), endian: 'be' },
    });
    return { ...base, fatal: true };
  }
  const r = new Reader(slice, endian);
  const headerSize = is64 ? 32 : 28;
  const cputype = r.u32(4);
  const ncmds = r.u32(16);
  const sizeofcmds = r.u32(20);
  if (headerSize + sizeofcmds > slice.length) {
    diags.push({
      code: 'command_out_of_bounds',
      message: `sizeofcmds ${sizeofcmds} exceeds slice bounds (slice size 0x${slice.length.toString(16)})`,
      objectId: sliceId,
      position: q(fileOffset + headerSize, 'byte', 'file'),
    });
    return { ...base, fatal: true, endian, is64, cputype, ncmds, sizeofcmds };
  }
  const commands: MachCommand[] = [];
  let codeSig: { dataoff: number; datasize: number } | undefined;
  let off = headerSize;
  for (let i = 0; i < ncmds; i++) {
    if (i >= budget.maxCommands) {
      throw new BudgetError({
        code: 'budget_exceeded',
        message: `command count exceeds budget maxCommands=${budget.maxCommands}`,
        objectId: sliceId,
        position: q(fileOffset + off, 'byte', 'file'),
      });
    }
    if (off > budget.maxBytes) {
      throw new BudgetError({
        code: 'budget_exceeded',
        message: `command walk exceeds budget maxBytes=${budget.maxBytes}`,
        objectId: sliceId,
        position: q(fileOffset + off, 'byte', 'file'),
      });
    }
    if (off + 8 > slice.length) {
      diags.push({
        code: 'command_out_of_bounds',
        message: `command ${i} header at slice offset 0x${off.toString(16)} is truncated`,
        objectId: `${sliceId}_cmd_${i}`,
        position: q(fileOffset + off, 'byte', 'file'),
      });
      break;
    }
    const cmd = r.u32(off);
    const cmdsize = r.u32(off + 4);
    const inBounds = cmdsize >= 8 && off + cmdsize <= slice.length && off + cmdsize <= headerSize + sizeofcmds;
    commands.push({
      index: i,
      objectId: `${sliceId}_cmd_${i}`,
      cmd,
      cmdName: cmdName(cmd),
      cmdsize,
      offset: off,
      inBounds,
      rawHex: r.hex(off, 8),
    });
    if (!inBounds) {
      diags.push({
        code: 'command_out_of_bounds',
        message: `command ${i} (${cmdName(cmd)}) cmdsize=${cmdsize} at slice offset 0x${off.toString(16)} escapes slice/declared command region`,
        objectId: `${sliceId}_cmd_${i}`,
        position: q(fileOffset + off, 'byte', 'file'),
        raw: { rawHex: r.hex(off, 8), endian },
      });
      break;
    }
    if (cmd === 0x1d && cmdsize >= 16) {
      codeSig = { dataoff: r.u32(off + 8), datasize: r.u32(off + 12) };
    }
    off += cmdsize;
  }
  return { endian, is64, cputype, ncmds, sizeofcmds, commands, diags, fatal: false, codeSig };
}
