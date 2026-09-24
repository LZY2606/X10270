import {
  Budget,
  BudgetExhausted,
  Diagnostic,
  Endianness,
  FatArch,
  FatParseResult,
  LoadCommand,
  Quantity,
  SectionInfo,
  ThinParseResult,
} from './types.js';
import { archName } from './arch.js';

const FAT_MAGIC = 0xcafebabe;
const FAT_CIGAM = 0xbebafeca;
const FAT_MAGIC_64 = 0xcafebabf;
const FAT_CIGAM_64 = 0xbfbafeca;
const MH_MAGIC = 0xfeedface;
const MH_CIGAM = 0xcefaedfe;
const MH_MAGIC_64 = 0xfeedfacf;
const MH_CIGAM_64 = 0xcffaedfe;

const LC_REQ_DYLD = 0x80000000;

export const KNOWN_COMMANDS: Record<number, string> = {
  0x1: 'LC_SEGMENT',
  0x2: 'LC_SYMTAB',
  0xb: 'LC_DYSYMTAB',
  0x19: 'LC_SEGMENT_64',
  0x1b: 'LC_UUID',
  0x1d: 'LC_CODE_SIGNATURE',
  0x21: 'LC_ENCRYPTION_INFO',
  0x2c: 'LC_ENCRYPTION_INFO_64',
  0x32: 'LC_BUILD_VERSION',
  [0x28 | LC_REQ_DYLD]: 'LC_MAIN',
};

class Reader {
  pos = 0;
  constructor(
    public buf: Uint8Array,
    public endian: Endianness,
  ) {}

  remaining(): number {
    return this.buf.length - this.pos;
  }

  u8(): number {
    return this.buf[this.pos++];
  }

  u32(): number {
    const p = this.pos;
    this.pos += 4;
    return readU32(this.buf, p, this.endian);
  }

  u64(): number {
    const p = this.pos;
    this.pos += 8;
    if (this.endian === 'le') {
      const lo = readU32(this.buf, p, 'le');
      const hi = readU32(this.buf, p + 4, 'le');
      return hi * 0x100000000 + lo;
    }
    const hi = readU32(this.buf, p, 'be');
    const lo = readU32(this.buf, p + 4, 'be');
    return hi * 0x100000000 + lo;
  }

  cstr(fixed: number): string {
    const start = this.pos;
    let out = '';
    for (let i = 0; i < fixed; i++) {
      const c = this.buf[this.pos++];
      if (c === 0) {
        this.pos = start + fixed;
        return out;
      }
      out += String.fromCharCode(c);
    }
    return out;
  }

  bytes(n: number): Uint8Array {
    const out = this.buf.subarray(this.pos, this.pos + n);
    this.pos += n;
    return out;
  }
}

export function readU32(b: Uint8Array, p: number, endian: Endianness): number {
  const x0 = b[p];
  const x1 = b[p + 1];
  const x2 = b[p + 2];
  const x3 = b[p + 3];
  return endian === 'le'
    ? (x0 | (x1 << 8) | (x2 << 16) | (x3 << 24)) >>> 0
    : (x3 | (x2 << 8) | (x1 << 16) | (x0 << 24)) >>> 0;
}

export function hex8(n: number): string {
  return `0x${n.toString(16).padStart(8, '0')}`;
}

export function hexBytes(b: Uint8Array, max = 16): string {
  const n = Math.min(b.length, max);
  return Array.from(b.subarray(0, n))
    .map((x) => x.toString(16).padStart(2, '0'))
    .join(' ');
}

/** 规范化领域量；无法转换时保留原表示并附诊断，绝不丢弃或替换默认值。 */
export function normalizeQuantity(
  raw: string,
  unit: Quantity['unit'],
  basis: Quantity['basis'],
  at: number,
): Quantity {
  const trimmed = raw.trim();
  let value: number | null = null;
  let diagnostic: Diagnostic | undefined;
  if (/^0x[0-9a-fA-F]+$/.test(trimmed)) {
    value = Number.parseInt(trimmed.slice(2), 16);
  } else if (/^-?[0-9]+$/.test(trimmed)) {
    value = Number.parseInt(trimmed, 10);
  }
  if (value === null || Number.isNaN(value)) {
    diagnostic = {
      code: 'unconvertible_quantity',
      message: `无法把原始表示 ${JSON.stringify(trimmed)} 转换为 ${unit}；值保留在原位置，不参与规范化计算`,
      severity: 'error',
      offset: at,
      basis,
      raw: trimmed,
    };
  }
  return { raw: trimmed, value, unit, basis, diagnostic };
}

export function detectEndianMagic(data: Uint8Array): {
  magic: number;
  kind: 'fat' | 'fat64' | 'thin64' | 'thin32';
  endian: Endianness;
} | null {
  if (data.length < 4) return null;
  const be = readU32(data, 0, 'be');
  const table: Record<number, { kind: 'fat' | 'fat64' | 'thin64' | 'thin32'; endian: Endianness }> = {
    [FAT_MAGIC]: { kind: 'fat', endian: 'be' },
    [FAT_CIGAM]: { kind: 'fat', endian: 'le' },
    [FAT_MAGIC_64]: { kind: 'fat64', endian: 'be' },
    [FAT_CIGAM_64]: { kind: 'fat64', endian: 'le' },
    [MH_MAGIC_64]: { kind: 'thin64', endian: 'le' },
    [MH_CIGAM_64]: { kind: 'thin64', endian: 'be' },
    [MH_MAGIC]: { kind: 'thin32', endian: 'le' },
    [MH_CIGAM]: { kind: 'thin32', endian: 'be' },
  };
  if (table[be]) return { magic: be, ...table[be] };
  return null;
}

function addU32(a: number, b: number): { ok: boolean; value: number } {
  if (a > 0xffffffff - b) return { ok: false, value: 0 };
  return { ok: true, value: a + b };
}

/** 解析 fat 容器。对齐只判定不修正：offset 未对齐是错误，绝不四舍五入。 */
export function parseFat(data: Uint8Array, budget: Budget): FatParseResult {
  const diagnostics: Diagnostic[] = [];
  const detected = detectEndianMagic(data);
  if (!detected) {
    return {
      kind: 'thin',
      endian: 'le',
      fat64: false,
      magic: data.length >= 4 ? readU32(data, 0, 'be') : 0,
      nfatArch: 0,
      arches: [],
      diagnostics: [
        {
          code: 'unknown_magic',
          message: `文件头魔数 ${hexBytes(data.subarray(0, 4), 4)} 不是任何已知的 Mach-O/fat 魔数`,
          severity: 'error',
          offset: 0,
          basis: 'file',
          raw: data.length >= 4 ? hex8(readU32(data, 0, 'be')) : '<truncated>',
        },
      ],
    };
  }

  if (detected.kind === 'thin64' || detected.kind === 'thin32') {
    return {
      kind: 'thin',
      endian: detected.endian,
      fat64: false,
      magic: detected.magic,
      nfatArch: 1,
      arches: [
        {
          index: 0,
          cputype: 0,
          cpusubtype: 0,
          archName: 'thin',
          offset: 0,
          size: data.length,
          align: 0,
        },
      ],
      diagnostics,
    };
  }

  const fat64 = detected.kind === 'fat64';
  const r = new Reader(data, detected.endian);
  r.u32(); // magic
  const nfatArch = r.u32();
  const entrySize = fat64 ? 32 : 20;

  if (data.length < 8 + nfatArch * entrySize) {
    diagnostics.push({
      code: 'fat_header_truncated',
      message: `fat 头声明 ${nfatArch} 个 slice，但容器仅有 ${data.length} 字节，无法容纳 ${8 + nfatArch * entrySize} 字节的 arch 表`,
      severity: 'error',
      offset: 8,
      basis: 'file',
    });
  }
  if (nfatArch > budget.maxSlices) {
    throw new BudgetExhausted(`fat arch 数量 ${nfatArch} 超过预算 ${budget.maxSlices}`);
  }

  const arches: FatArch[] = [];
  for (let i = 0; i < nfatArch; i++) {
    const entryOffset = 8 + i * entrySize;
    if (entryOffset + entrySize > data.length) break;
    r.pos = entryOffset;
    const cputype = r.u32();
    const cpusubtype = r.u32();
    const offset = r.u32();
    const size = r.u32();
    const align = r.u32();
    const reserved = fat64 ? r.u32() : undefined;
    arches.push({
      index: i,
      cputype,
      cpusubtype,
      archName: archName(cputype),
      offset,
      size,
      align,
      reserved,
    });
  }

  validateSlices(arches, data.length, diagnostics);
  return { kind: 'fat', endian: detected.endian, fat64, magic: detected.magic, nfatArch, arches, diagnostics };
}

export function validateSlices(arches: FatArch[], fileLength: number, diagnostics: Diagnostic[]): void {
  for (const arch of arches) {
    // 对齐指数溢出：2^align 无法可靠表示或超过文件尺度
    if (arch.align > 30) {
      diagnostics.push({
        code: 'alignment_overflow',
        message: `slice#${arch.index} 的对齐指数 ${arch.align} 使 2^${arch.align} 超出 32 位地址预算（对齐溢出），不做舍入修正`,
        severity: 'error',
        offset: 8 + arch.index * (arch.reserved !== undefined ? 32 : 20) + 16,
        basis: 'file',
        raw: String(arch.align),
      });
    } else {
      const granularity = 1 << arch.align;
      if (arch.offset % granularity !== 0) {
        diagnostics.push({
          code: 'slice_misaligned',
          message: `slice#${arch.index} 偏移 0x${arch.offset.toString(16)} 不是 2^${arch.align}=${granularity} 的倍数；记录违规，不对偏移做四舍五入修正`,
          severity: 'error',
          offset: 8 + arch.index * (arch.reserved !== undefined ? 32 : 20) + 8,
          basis: 'file',
          raw: `0x${arch.offset.toString(16)}`,
        });
      }
    }
    const end = addU32(arch.offset, arch.size);
    if (!end.ok || end.value > fileLength) {
      diagnostics.push({
        code: 'slice_out_of_file',
        message: `slice#${arch.index} 区间 [0x${arch.offset.toString(16)}, +0x${arch.size.toString(16)}) 超出容器边界 0x${fileLength.toString(16)}`,
        severity: 'error',
        offset: arch.offset,
        basis: 'file',
      });
    }
  }

  // slice 范围不得重叠
  const sorted = [...arches].sort((a, b) => a.offset - b.offset || a.size - b.size);
  for (let i = 1; i < sorted.length; i++) {
    const prev = sorted[i - 1];
    const cur = sorted[i];
    if (prev.offset + prev.size > cur.offset) {
      diagnostics.push({
        code: 'slice_overlap',
        message: `slice#${prev.index} 与 slice#${cur.index} 的字节区间重叠：[0x${prev.offset.toString(16)},0x${(prev.offset + prev.size).toString(16)}) 与 [0x${cur.offset.toString(16)},0x${(cur.offset + cur.size).toString(16)})`,
        severity: 'error',
        offset: cur.offset,
        basis: 'file',
      });
    }
  }

  // 多架构同名：cputype 相同导致名称冲突，身份必须依赖 slice 编号而非名称
  const byName = new Map<string, FatArch[]>();
  for (const arch of arches) {
    const list = byName.get(arch.archName) ?? [];
    list.push(arch);
    byName.set(arch.archName, list);
  }
  for (const [name, list] of byName) {
    if (list.length > 1) {
      diagnostics.push({
        code: 'multi_arch_same_name',
        message: `${list.length} 个 slice 解析到同一架构名 ${name}（#${list.map((a) => a.index).join(', #')}）；架构名不唯一，身份只能使用 slice 编号与内容摘要`,
        severity: 'warning',
        offset: 0,
        basis: 'file',
        raw: name,
      });
    }
  }
}

const HEADER_SIZE_64 = 32;
const HEADER_SIZE_32 = 28;

/** 解析单个 slice 的 mach header 与 load commands。命令越界只记录不跨读。 */
export function parseThin(data: Uint8Array, budget: Budget): ThinParseResult {
  const diagnostics: Diagnostic[] = [];
  const detected = detectEndianMagic(data);
  const is64 = detected?.kind === 'thin64';
  const endian = detected?.endian ?? 'le';
  if (!detected || (detected.kind !== 'thin64' && detected.kind !== 'thin32')) {
    diagnostics.push({
      code: 'slice_bad_magic',
      message: `slice 魔数 ${hexBytes(data.subarray(0, 4), 4)} 不是 Mach-O 魔数`,
      severity: 'error',
      offset: 0,
      basis: 'slice',
    });
  }
  const headerSize = is64 ? HEADER_SIZE_64 : HEADER_SIZE_32;
  const r = new Reader(data, endian);
  const magic = r.u32();
  const cputype = r.u32();
  const cpusubtype = r.u32();
  const filetype = r.u32();
  const ncmds = r.u32();
  const sizeofcmds = r.u32();
  const flags = r.u32();
  if (is64) r.u32(); // reserved

  if (ncmds > budget.maxCommands) {
    throw new BudgetExhausted(`load command 数量 ${ncmds} 超过预算 ${budget.maxCommands}`);
  }

  const commands: LoadCommand[] = [];
  const sections: SectionInfo[] = [];
  let codeSignature: ThinParseResult['codeSignature'];
  let linkedit: ThinParseResult['linkedit'];

  if (headerSize + sizeofcmds > data.length) {
    diagnostics.push({
      code: 'load_commands_past_slice',
      message: `header+sizeofcmds=${headerSize + sizeofcmds} 超过 slice 长度 ${data.length}，load command 区整体越界`,
      severity: 'error',
      offset: headerSize,
      basis: 'slice',
    });
  }

  let cursor = headerSize;
  const cmdRegionEnd = Math.min(headerSize + sizeofcmds, data.length);
  for (let i = 0; i < ncmds; i++) {
    const cmdOffset = cursor;
    if (cmdOffset + 8 > cmdRegionEnd) {
      diagnostics.push({
        code: 'command_out_of_bounds',
        message: `command#${i} @0x${cmdOffset.toString(16)}：剩余 ${cmdRegionEnd - cmdOffset} 字节不足以读取 cmd/cmdsize（load command 越界）`,
        severity: 'error',
        offset: cmdOffset,
        basis: 'slice',
      });
      break;
    }
    r.pos = cmdOffset;
    const cmd = r.u32();
    const cmdsize = r.u32();
    const cmdEnd = cmdOffset + cmdsize;
    let outOfBounds = false;
    if (cmdsize < 8 || cmdEnd > headerSize + sizeofcmds) {
      outOfBounds = true;
      diagnostics.push({
        code: 'command_out_of_bounds',
        message: `command#${i}（${KNOWN_COMMANDS[cmd] ?? hex8(cmd)}）cmdsize=${cmdsize} 使区间 [0x${cmdOffset.toString(16)},0x${cmdEnd.toString(16)}) 越过 sizeofcmds 边界 0x${(headerSize + sizeofcmds).toString(16)}`,
        severity: 'error',
        offset: cmdOffset,
        basis: 'slice',
        raw: String(cmdsize),
      });
    }
    if (cmdEnd > data.length) {
      outOfBounds = true;
      diagnostics.push({
        code: 'command_out_of_bounds',
        message: `command#${i}（${KNOWN_COMMANDS[cmd] ?? hex8(cmd)}）区间越过 slice 物理末尾 ${data.length}`,
        severity: 'error',
        offset: cmdOffset,
        basis: 'slice',
      });
    }

    const fields: Record<string, number | string> = {};
    const safeEnd = Math.min(cmdEnd, cmdRegionEnd, data.length);
    if (!outOfBounds && safeEnd - cmdOffset >= 8) {
      decodeCommandFields(r, cmd, cmdsize, safeEnd, fields, sections, data, endian);
      if (cmd === 0x19) {
        const seg = fields;
        if (seg.segname === '__LINKEDIT') {
          linkedit = { fileoff: Number(seg.fileoff), filesize: Number(seg.filesize) };
        }
      }
      if (cmd === 0x1d) {
        codeSignature = { dataoff: Number(fields.dataoff), datasize: Number(fields.datasize) };
      }
    }

    commands.push({ index: i, cmd, cmdName: KNOWN_COMMANDS[cmd] ?? `UNKNOWN_${hex8(cmd)}`, cmdsize, offset: cmdOffset, fields, outOfBounds });
    if (cmdsize < 8) break;
    cursor = cmdEnd;
  }

  return {
    endian,
    is64,
    magic,
    cputype,
    cpusubtype,
    filetype,
    ncmds,
    sizeofcmds,
    flags,
    commands,
    sections,
    codeSignature,
    linkedit,
    diagnostics,
  };
}

function decodeCommandFields(
  r: Reader,
  cmd: number,
  cmdsize: number,
  safeEnd: number,
  fields: Record<string, number | string>,
  sections: SectionInfo[],
  data: Uint8Array,
  endian: Endianness,
): void {
  const segName = () => {
    const segname = r.cstr(16);
    fields.segname = segname;
    return segname;
  };
  if (cmd === 0x19) {
    segName();
    fields.vmaddr = r.u64();
    fields.vmsize = r.u64();
    fields.fileoff = r.u64();
    fields.filesize = r.u64();
    fields.maxprot = r.u32();
    fields.initprot = r.u32();
    const nsects = r.u32();
    fields.nsects = nsects;
    fields.flags = r.u32();
    for (let s = 0; s < nsects; s++) {
      if (r.pos + 80 > safeEnd) break;
      const sectname = r.cstr(16);
      const sn = r.cstr(16);
      r.u64(); // addr
      r.u64(); // size
      r.u32(); // offset
      const secOff = readU32(data, r.pos - 4, endian);
      const secSize = (() => {
        r.u32();
        return readU32(data, r.pos - 4, endian);
      })();
      r.pos += 32;
      sections.push({ sectname, segname: sn, offset: secOff, size: secSize });
    }
  } else if (cmd === 0x1) {
    segName();
    fields.vmaddr = r.u32();
    fields.vmsize = r.u32();
    fields.fileoff = r.u32();
    fields.filesize = r.u32();
    fields.maxprot = r.u32();
    fields.initprot = r.u32();
    const nsects = r.u32();
    fields.nsects = nsects;
    fields.flags = r.u32();
    for (let s = 0; s < nsects; s++) {
      if (r.pos + 68 > safeEnd) break;
      const sectname = r.cstr(16);
      const sn = r.cstr(16);
      r.u32();
      r.u32();
      const secOff = r.u32();
      const secSize = r.u32();
      r.pos += 28;
      sections.push({ sectname, segname: sn, offset: secOff, size: secSize });
    }
  } else if (cmd === 0x1d) {
    fields.dataoff = r.u32();
    fields.datasize = r.u32();
  } else if (cmd === 0x2) {
    fields.symoff = r.u32();
    fields.nsyms = r.u32();
    fields.stroff = r.u32();
    fields.strsize = r.u32();
  } else if (cmd === 0x21 || cmd === 0x2c) {
    fields.cryptoff = r.u32();
    fields.cryptsize = r.u32();
    fields.cryptid = r.u32();
  } else {
    fields.rawLen = safeEnd - (r.pos - 8);
  }
}

import { createHash } from 'node:crypto';
import {
  CodeSlotCheck,
  CoverageBand,
  SignatureParseResult,
} from './types.js';

const CSMAGIC_EMBEDDED_SIGNATURE = 0xfade0cc0;
const CSMAGIC_CODEDIRECTORY = 0xfade0c02;

const HASH_NAMES: Record<number, string> = {
  1: 'SHA-1',
  2: 'SHA-256',
  3: 'SHA-256/20',
  4: 'SHA-384',
};

export function hashName(type: number): string {
  return HASH_NAMES[type] ?? `unsupported(#${type})`;
}

/** 解析 LC_CODE_SIGNATURE 指向的 SuperBlob：blob 目录、code slot 哈希、覆盖带。 */
export function parseSignature(
  slice: Uint8Array,
  sig: { dataoff: number; datasize: number },
  budget: { maxPages: number },
): SignatureParseResult {
  const diagnostics: Diagnostic[] = [];
  const result: SignatureParseResult = {
    present: true,
    blobOffset: sig.dataoff,
    blobSize: sig.datasize,
    entries: [],
    slots: [],
    bands: [],
    diagnostics,
  };

  const endSum = sig.dataoff + sig.datasize;
  if (sig.dataoff < 0 || sig.datasize < 12 || endSum > slice.length) {
    diagnostics.push({
      code: 'signature_out_of_bounds',
      message: `LC_CODE_SIGNATURE 声明的 blob 区间 [0x${sig.dataoff.toString(16)},0x${endSum.toString(16)}) 越过 slice 末尾 ${slice.length}`,
      severity: 'error',
      offset: sig.dataoff,
      basis: 'slice',
    });
    return result;
  }

  const blob = slice.subarray(sig.dataoff, endSum);
  const magic = readU32(blob, 0, 'be');
  result.superblobMagic = magic;
  if (magic !== CSMAGIC_EMBEDDED_SIGNATURE) {
    diagnostics.push({
      code: 'unsupported_signature_format',
      message: `签名 blob 起始魔数 ${hex8(magic)} 不是嵌入式代码签名 SuperBlob(${hex8(CSMAGIC_EMBEDDED_SIGNATURE)})，无法核验，格式标记为不支持`,
      severity: 'error',
      offset: sig.dataoff,
      basis: 'blob',
      raw: hex8(magic),
    });
    return result;
  }

  const declaredLength = readU32(blob, 4, 'be');
  if (declaredLength !== sig.datasize) {
    diagnostics.push({
      code: 'signature_length_mismatch',
      message: `SuperBlob 声明长度 ${declaredLength} 与 LC_CODE_SIGNATURE datasize ${sig.datasize} 不一致`,
      severity: 'warning',
      offset: sig.dataoff + 4,
      basis: 'blob',
    });
  }

  const count = readU32(blob, 8, 'be');
  for (let i = 0; i < count; i++) {
    const ip = 12 + i * 8;
    if (ip + 8 > blob.length) {
      diagnostics.push({
        code: 'blob_index_out_of_bounds',
        message: `SuperBlob index#${i} 越过 blob 末尾`,
        severity: 'error',
        offset: sig.dataoff + ip,
        basis: 'blob',
      });
      break;
    }
    const type = readU32(blob, ip, 'be');
    const offset = readU32(blob, ip + 4, 'be');
    let entryMagic: number | null = null;
    let known = false;
    if (offset + 4 > blob.length) {
      diagnostics.push({
        code: 'blob_entry_out_of_bounds',
        message: `SuperBlob 槽位 ${type} 偏移 0x${offset.toString(16)} 越过 blob 末尾`,
        severity: 'error',
        offset: sig.dataoff + offset,
        basis: 'blob',
      });
    } else {
      entryMagic = readU32(blob, offset, 'be');
      known = entryMagic === CSMAGIC_CODEDIRECTORY || entryMagic === 0xfade0b01 || entryMagic === 0xfade7172;
      if (!known) {
        diagnostics.push({
          code: 'unknown_blob',
          message: `SuperBlob 槽位 ${type} 处的 blob 魔数 ${hex8(entryMagic)} 未知，原始字节保留，不做猜测式解析`,
          severity: 'error',
          offset: sig.dataoff + offset,
          basis: 'blob',
          raw: hex8(entryMagic),
        });
      }
    }
    result.entries.push({ type, offset, magic: entryMagic, known });
  }

  const cdEntry = result.entries.find(
    (e) => e.type === 0 && e.magic === CSMAGIC_CODEDIRECTORY,
  );
  if (!cdEntry) {
    return result;
  }

  const cd = blob.subarray(cdEntry.offset);
  const cdLength = readU32(cd, 4, 'be');
  const version = readU32(cd, 8, 'be');
  const flags = readU32(cd, 12, 'be');
  const hashOffset = readU32(cd, 16, 'be');
  const identOffset = readU32(cd, 20, 'be');
  const nSpecialSlots = readU32(cd, 24, 'be');
  const nCodeSlots = readU32(cd, 28, 'be');
  const codeLimit = readU32(cd, 32, 'be');
  const hashSize = cd[36];
  const hashType = cd[37];
  const platform = cd[38];
  const pageShift = cd[39];
  const identEnd = cd.subarray(identOffset).indexOf(0);
  const ident = new TextDecoder().decode(cd.subarray(identOffset, identOffset + (identEnd < 0 ? 0 : identEnd)));

  result.codeDirectory = {
    hashType,
    hashName: hashName(hashType),
    pageSize: pageShift,
    nCodeSlots,
    nSpecialSlots,
    codeLimit,
    ident,
  };

  if (!HASH_NAMES[hashType]) {
    diagnostics.push({
      code: 'unsupported_hash_type',
      message: `CodeDirectory hashType=${hashType} 不受支持，无法重算 code slot 摘要`,
      severity: 'error',
      offset: sig.dataoff + cdEntry.offset + 37,
      basis: 'blob',
      raw: String(hashType),
    });
  }
  if (pageShift > 20) {
    diagnostics.push({
      code: 'alignment_overflow',
      message: `CodeDirectory pageSize 指数 ${pageShift} 异常，2^${pageShift} 超过预算`,
      severity: 'error',
      offset: sig.dataoff + cdEntry.offset + 39,
      basis: 'blob',
    });
  }

  const algo = hashType === 1 ? 'sha1' : hashType === 2 ? 'sha256' : hashType === 3 || hashType === 4 ? 'sha256' : null;
  const pageBytes = 1 << pageShift;
  if (nCodeSlots > budget.maxPages) {
    throw new BudgetExhausted(`code slot 数量 ${nCodeSlots} 超过预算 ${budget.maxPages}`);
  }

  // 覆盖带：[0,codeLimit) 已覆盖 → [codeLimit, sigOff) 缺口 → 签名 → blob 之后尾部缺口
  const bands: CoverageBand[] = [];
  if (codeLimit > 0) bands.push({ start: 0, end: codeLimit, kind: 'covered' });
  if (codeLimit < sig.dataoff) bands.push({ start: codeLimit, end: sig.dataoff, kind: 'gap' });
  bands.push({ start: sig.dataoff, end: endSum, kind: 'signature' });
  if (endSum < slice.length) bands.push({ start: endSum, end: slice.length, kind: 'gap' });
  result.bands = bands;

  if (codeLimit < sig.dataoff) {
    diagnostics.push({
      code: 'signature_coverage_gap',
      message: `codeLimit=0x${codeLimit.toString(16)} 到签名 blob 起点 0x${sig.dataoff.toString(16)} 之间有 ${sig.dataoff - codeLimit} 字节未被 code slot 覆盖（签名未覆盖尾部）`,
      severity: 'error',
      offset: codeLimit,
      basis: 'slice',
    });
  }
  if (endSum < slice.length) {
    diagnostics.push({
      code: 'signature_coverage_gap',
      message: `签名 blob 结束于 0x${endSum.toString(16)}，slice 末尾在 0x${slice.length.toString(16)}，仍有 ${slice.length - endSum} 字节尾部未覆盖`,
      severity: 'error',
      offset: endSum,
      basis: 'slice',
    });
  }

  if (algo) {
    for (let i = 0; i < nCodeSlots; i++) {
      const hp = hashOffset + i * hashSize;
      if (hp + hashSize > Math.min(cdLength, cd.length)) {
        diagnostics.push({
          code: 'code_slot_out_of_bounds',
          message: `code slot#${i} 的哈希位置越过 CodeDirectory 长度`,
          severity: 'error',
          offset: sig.dataoff + cdEntry.offset + hp,
          basis: 'blob',
        });
        break;
      }
      const expected = Array.from(cd.subarray(hp, hp + hashSize))
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');
      const pageStart = i * pageBytes;
      const pageEnd = Math.min(pageStart + pageBytes, codeLimit);
      let actual = '';
      if (pageStart >= codeLimit) {
        actual = createHash(algo).update(new Uint8Array(0)).digest('hex');
      } else {
        actual = createHash(algo).update(slice.subarray(pageStart, pageEnd)).digest('hex');
      }
      result.slots.push({
        slot: i,
        pageOffset: pageStart,
        pageLength: Math.max(0, pageEnd - pageStart),
        expectedHash: expected,
        actualHash: actual,
        match: expected === actual,
      });
    }
    const mismatch = result.slots.filter((s) => !s.match);
    if (mismatch.length > 0) {
      for (const m of mismatch) {
        diagnostics.push({
          code: 'code_slot_hash_mismatch',
          message: `code slot#${m.slot}（页 0x${m.pageOffset.toString(16)}）摘要不匹配：期望 ${m.expectedHash.slice(0, 16)}… 实际 ${m.actualHash.slice(0, 16)}…`,
          severity: 'error',
          offset: m.pageOffset,
          basis: 'slice',
        });
      }
    }
  }

  void version;
  void flags;
  void platform;
  void nSpecialSlots;
  return result;
}
