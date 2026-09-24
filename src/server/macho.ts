// Mach-O / universal(fat) 二进制解析与确定性夹具构建。
// 解析只做“忠实读取”：所有原始字节以 base64 保留，字节序在原始字段中显式记录，
// 规范化（单位换算、对齐判定）发生在派生规则层。
import { createHash } from 'node:crypto';

export const FAT_MAGIC = 0xcafebabe; // 头部大端
export const FAT_CIGAM = 0xbebafeca; // 头部小端
export const MH_MAGIC = 0xfeedface;
export const MH_CIGAM = 0xcefaedfe;
export const LC_SEGMENT = 0x1;
export const LC_CODE_SIGNATURE = 0x1d;
export const CSMAGIC_EMBEDDED_SIGNATURE = 0xfade0cc0;
export const CSMAGIC_CODEDIRECTORY = 0xfade0c02;
export const CSSLOT_CODEDIRECTORY = 0x0;
export const CSSLOT_REQUIREMENTS = 0x2;

export const CPU_ARCH: Record<number, string> = {
  0x01000007: 'x86_64',
  0x0100000c: 'arm64',
  0x00000007: 'i386',
  0x00000012: 'ppc',
};

export interface ParseBudget {
  maxBytes: number;
  maxSlices: number;
  maxCommands: number;
  maxCodeSlots: number;
}

export const DEFAULT_BUDGET: ParseBudget = {
  maxBytes: 64 * 1024,
  maxSlices: 32,
  maxCommands: 256,
  maxCodeSlots: 4096,
};

export interface RawMaterial {
  kind: 'fat_header' | 'slice' | 'load_command' | 'signature_blob' | 'code_slot' | 'file_digest';
  name: string;
  sliceRef?: string; // e.g. "slice:0:x86_64"
  raw: Uint8Array;
  meta: Record<string, unknown>;
}

export interface ParsedFile {
  endianness: 'big' | 'little'; // fat 头部字节序
  slices: ParsedSlice[];
  materials: RawMaterial[];
  fileSize: number;
  digest: string;
}

export interface ParsedSlice {
  ref: string;
  index: number;
  archName: string;
  cpuType: number;
  cpuSubtype: number;
  offset: number;
  size: number;
  alignExp: number;
  sliceEndian: 'big' | 'little';
  ncmds: number;
  sizeofcmds: number;
  commands: ParsedCommand[];
  signature?: ParsedSignature;
}

export interface ParsedCommand {
  index: number;
  cmd: number;
  cmdsize: number;
  at: number; // slice 内偏移
}

export interface ParsedSignature {
  dataoff: number; // 相对 slice 起点（文件坐标）
  datasize: number;
  superLength: number;
  blobs: { type: number; name: string; known: boolean; offset: number; length: number; magic: number }[];
  codeLimit: number;
  pageSizeExp: number;
  hashSize: number;
  hashType: number;
  slots: { index: number; pageOffset: number; length: number; expected: Uint8Array }[];
}

export class Reader {
  pos = 0;
  constructor(public buf: Uint8Array) {}
  u8() { return this.buf[this.pos++]; }
  get(i: number) {
    if (i < 0 || i >= this.buf.length) return undefined;
    return this.buf[i];
  }
  u32(le: boolean) {
    const b = this.buf;
    const p = this.pos;
    this.pos += 4;
    if (le) return (b[p] | (b[p + 1] << 8) | (b[p + 2] << 16) | (b[p + 3] << 24)) >>> 0;
    return (((b[p] << 24) | (b[p + 1] << 16) | (b[p + 2] << 8) | b[p + 3]) >>> 0);
  }
  i32(le: boolean) { return this.u32(le) | 0; }
  bytes(len: number) {
    const out = this.buf.subarray(this.pos, this.pos + len);
    this.pos += len;
    return out;
  }
  slice(pos: number, len: number) { return this.buf.subarray(pos, pos + len); }
  get eof() { return this.pos >= this.buf.length; }
}

export interface ParseResult {
  ok: boolean;
  outcome: 'ok' | 'budget_exhausted' | 'format_corrupt';
  diagnostics: { code: string; position: { offset: number; basis: 'file' | 'slice'; sliceId?: string }; message: string }[];
  parsed?: ParsedFile;
}

export function sha256(bytes: Uint8Array): string {
  return createHash('sha256').update(Buffer.from(bytes)).digest('hex');
}

export function toBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64');
}

/** 仅检查边界的忠实解析；语义判定留给规则层。 */
export function parseFat(data: Uint8Array, budget: ParseBudget = DEFAULT_BUDGET): ParseResult {
  const diagnostics: ParseResult['diagnostics'] = [];
  const fileSize = data.length;
  const digest = sha256(data);
  const materials: RawMaterial[] = [];

  if (fileSize > budget.maxBytes) {
    return {
      ok: false,
      outcome: 'budget_exhausted',
      diagnostics: [
        { code: 'budget.file_bytes', position: { offset: fileSize, basis: 'file' },
          message: `文件 ${fileSize} B 超过资源预算 ${budget.maxBytes} B` },
      ],
    };
  }
  if (fileSize < 8) {
    return {
      ok: false,
      outcome: 'format_corrupt',
      diagnostics: [
        { code: 'corrupt.truncated_header', position: { offset: 0, basis: 'file' },
          message: `不足 8 B，无法读取 fat magic（实际 ${fileSize} B）` },
      ],
    };
  }

  const r = new Reader(data);
  const magic = r.u32(false);
  const fatLE = magic === FAT_CIGAM;
  const fatBE = magic === FAT_MAGIC;
  if (!fatLE && !fatBE) {
    return {
      ok: false,
      outcome: 'format_corrupt',
      diagnostics: [
        { code: 'corrupt.fat_magic', position: { offset: 0, basis: 'file' },
          message: `未知 fat magic 0x${magic.toString(16).padStart(8, '0')}` },
      ],
    };
  }
  r.pos = 4;
  const nfat = r.u32(fatLE);
  if (nfat > budget.maxSlices) {
    return {
      ok: false,
      outcome: 'budget_exhausted',
      diagnostics: [
        { code: 'budget.slices', position: { offset: 4, basis: 'file' },
          message: `slice 数量 ${nfat} 超过预算 ${budget.maxSlices}` },
      ],
    };
  }
  if (8 + nfat * 20 > fileSize) {
    return {
      ok: false,
      outcome: 'format_corrupt',
      diagnostics: [
        { code: 'corrupt.fat_arch_table', position: { offset: 8, basis: 'file' },
          message: `fat_arch 表声明 ${nfat} 项 ×20 B，超出文件 ${fileSize} B` },
      ],
    };
  }
  materials.push({
    kind: 'fat_header',
    name: `fat_header(endian=${fatLE ? 'little' : 'big'}, nfat_arch=${nfat})`,
    raw: data.subarray(0, 8 + nfat * 20),
    meta: {
      magic: `0x${magic.toString(16).padStart(8, '0')}`,
      endianness: fatLE ? 'little' : 'big',
      nfat_arch: nfat,
      header_size_bytes: 8 + nfat * 20,
      basis: 'file',
    },
  });

  const slices: ParsedSlice[] = [];
  for (let i = 0; i < nfat; i++) {
    const archAt = r.pos;
    const cpuType = r.i32(fatLE);
    const cpuSubtype = r.i32(fatLE);
    const offset = r.u32(fatLE);
    const size = r.u32(fatLE);
    const alignExp = r.u32(fatLE);
    const archName = CPU_ARCH[cpuType >>> 0] ?? `unknown-cpu:0x${(cpuType >>> 0).toString(16)}`;
    const ref = `slice:${i}:${archName}`;
    const raw = data.subarray(archAt, archAt + 20);
    materials.push({
      kind: 'slice',
      name: `fat_arch[${i}] ${archName} offset=0x${offset.toString(16)} size=${size}B align=2^${alignExp}`,
      sliceRef: ref,
      raw,
      meta: {
        cputype: `0x${(cpuType >>> 0).toString(16).padStart(8, '0')}`,
        cpusubtype: cpuSubtype,
        offset_bytes: offset,
        size_bytes: size,
        align_exp: alignExp,
        arch_table_entry_offset_bytes: archAt,
        endianness: fatLE ? 'little' : 'big',
        basis: 'file',
      },
    });

    const slice: ParsedSlice = {
      ref, index: i, archName, cpuType: cpuType >>> 0, cpuSubtype,
      offset, size, alignExp, sliceEndian: 'little', ncmds: 0, sizeofcmds: 0, commands: [],
    };
    slices.push(slice);

    if (offset + size > fileSize || offset < 0 || size < 28) {
      diagnostics.push({
        code: 'corrupt.slice_range', position: { offset, basis: 'file', sliceId: ref },
        message: `slice[${i}] 范围 [0x${offset.toString(16)}, +${size}B) 超出文件边界（文件 ${fileSize} B）`,
      });
      continue;
    }

    const sr = new Reader(data);
    sr.pos = offset;
    const smagic = sr.u32(false);
    const le = smagic === MH_MAGIC;
    const be = smagic === MH_CIGAM;
    if (!le && !be) {
      diagnostics.push({
        code: 'corrupt.macho_magic', position: { offset, basis: 'file', sliceId: ref },
        message: `slice[${i}] Mach-O magic 0x${smagic.toString(16).padStart(8, '0')} 不被识别（不支持格式）`,
      });
      continue;
    }
    sr.pos = offset + 4;
    const sCpuType = sr.i32(le);
    const sCpuSub = sr.i32(le);
    sr.u32(le); // filetype
    const ncmds = sr.u32(le);
    const sizeofcmds = sr.u32(le);
    sr.u32(le); // flags
    slice.sliceEndian = le ? 'little' : 'big';
    slice.ncmds = ncmds;
    slice.sizeofcmds = sizeofcmds;

    materials.push({
      kind: 'load_command',
      name: `mach_header[${i}] ${archName} endian=${le ? 'little' : 'big'} ncmds=${ncmds}`,
      sliceRef: ref,
      raw: data.subarray(offset, offset + 28),
      meta: {
        magic: `0x${smagic.toString(16).padStart(8, '0')}`,
        endianness: le ? 'little' : 'big',
        cputype: `0x${(sCpuType >>> 0).toString(16).padStart(8, '0')}`,
        cpusubtype: sCpuSub,
        ncmds,
        sizeofcmds_bytes: sizeofcmds,
        offset_bytes: offset,
        basis: 'file',
      },
    });

    if (ncmds > budget.maxCommands) {
      diagnostics.push({
        code: 'budget.commands', position: { offset, basis: 'file', sliceId: ref },
        message: `slice[${i}] ncmds=${ncmds} 超过预算 ${budget.maxCommands}`,
      });
      continue;
    }

    let cp = offset + 28;
    let sigCmd: { dataoff: number; datasize: number; at: number; size: number } | undefined;
    for (let c = 0; c < ncmds; c++) {
      const at = cp;
      const cr = new Reader(data);
      cr.pos = at;
      const cmd = cr.u32(le);
      const cmdsize = cr.u32(le);
      const cm: ParsedCommand = { index: c, cmd, cmdsize, at };
      slice.commands.push(cm);
      materials.push({
        kind: 'load_command',
        name: `load_command[${i}][${c}] cmd=0x${cmd.toString(16)} cmdsize=${cmdsize}B`,
        sliceRef: ref,
        raw: data.subarray(at, at + Math.max(0, cmdsize)),
        meta: {
          cmd: `0x${cmd.toString(16).padStart(8, '0')}`,
          cmdsize_bytes: cmdsize,
          offset_bytes: at,
          basis: 'file',
          slice_basis_offset_bytes: at - offset,
        },
      });
      if (cmd === LC_CODE_SIGNATURE && cmdsize >= 16) {
        const dr = new Reader(data);
        dr.pos = at + 8;
        const dataoff = dr.u32(le);
        const datasize = dr.u32(le);
        sigCmd = { dataoff, datasize, at, size: cmdsize };
      }
      cp += cmdsize || 8;
    }

    if (sigCmd) {
      parseSignature(data, slice, sigCmd, budget, materials, diagnostics, le);
    }
  }

  materials.push({
    kind: 'file_digest',
    name: `sha256(${fileSize}B)`,
    raw: data,
    meta: { algo: 'sha256', digest, file_size_bytes: fileSize },
  });

  return {
    ok: diagnostics.length === 0,
    outcome: diagnostics.some((d) => d.code.startsWith('budget.'))
      ? 'budget_exhausted'
      : diagnostics.length > 0
        ? 'format_corrupt'
        : 'ok',
    diagnostics,
    parsed: {
      endianness: fatLE ? 'little' : 'big',
      slices,
      materials,
      fileSize,
      digest,
    },
  };
}

function parseSignature(
  data: Uint8Array,
  slice: ParsedSlice,
  sigCmd: { dataoff: number; datasize: number; at: number; size: number },
  budget: ParseBudget,
  materials: RawMaterial[],
  diagnostics: ParseResult['diagnostics'],
  le: boolean,
) {
  // 约定（在案例包 README 中声明）：fat 容器内 LC_CODE_SIGNATURE 的 dataoff
  // 为 slice 起点相对偏移，加 slice.offset 得到文件坐标。
  const sigFileOff = slice.offset + sigCmd.dataoff;
  const sr = new Reader(data);
  sr.pos = sigFileOff;
  const magic = sr.u32(false); // SuperBlob 恒为大端
  if (magic !== CSMAGIC_EMBEDDED_SIGNATURE) {
    diagnostics.push({
      code: 'unsupported.sig_magic', position: { offset: sigFileOff, basis: 'file', sliceId: slice.ref },
      message: `slice[${slice.index}] 签名 magic 0x${magic.toString(16).padStart(8, '0')} 不被支持`,
    });
    return;
  }
  const superLength = sr.u32(false);
  const count = sr.u32(false);
  const indexBase = sigFileOff + 12;
  const blobRaw = data.subarray(sigFileOff, sigFileOff + Math.min(sigCmd.datasize, superLength));
  materials.push({
    kind: 'signature_blob',
    name: `super_blob[${slice.index}] count=${count} length=${superLength}B`,
    sliceRef: slice.ref,
    raw: blobRaw,
    meta: {
      magic: `0x${magic.toString(16).padStart(8, '0')}`,
      length_bytes: superLength,
      count,
      dataoff_slice_basis_bytes: sigCmd.dataoff,
      offset_bytes: sigFileOff,
      basis: 'file',
    },
  });

  const sig: ParsedSignature = {
    dataoff: sigCmd.dataoff,
    datasize: sigCmd.datasize,
    superLength,
    blobs: [],
    codeLimit: 0,
    pageSizeExp: 12,
    hashSize: 32,
    hashType: 2,
    slots: [],
  };
  slice.signature = sig;

  for (let b = 0; b < count; b++) {
    sr.pos = indexBase + b * 8;
    const type = sr.u32(false);
    const blobOff = sr.u32(false);
    const br = new Reader(data);
    br.pos = sigFileOff + blobOff;
    const bmagic = br.u32(false);
    const blen = br.u32(false);
    const known = bmagic === CSMAGIC_CODEDIRECTORY || (type === CSSLOT_REQUIREMENTS);
    const name =
      type === CSSLOT_CODEDIRECTORY ? 'CodeDirectory'
      : type === CSSLOT_REQUIREMENTS ? 'Requirements'
      : `unknown-blob(type=0x${type.toString(16).padStart(8, 'x')})`;
    sig.blobs.push({ type, name, known, offset: sigFileOff + blobOff, length: blen, magic: bmagic });
    materials.push({
      kind: 'signature_blob',
      name: `blob[${slice.index}][${type}] ${name} length=${blen}B`,
      sliceRef: slice.ref,
      raw: data.subarray(sigFileOff + blobOff, sigFileOff + blobOff + blen),
      meta: {
        slot_type: type,
        slot_name: name,
        blob_magic: `0x${bmagic.toString(16).padStart(8, '0')}`,
        length_bytes: blen,
        offset_bytes: sigFileOff + blobOff,
        known,
        basis: 'file',
      },
    });

    if (bmagic === CSMAGIC_CODEDIRECTORY) {
      const cr = new Reader(data);
      cr.pos = sigFileOff + blobOff + 8;
      cr.u32(false); // version
      cr.u32(false); // flags
      const hashOffset = cr.u32(false);
      cr.u32(false); // identOffset
      const nSpecial = cr.u32(false);
      const nCodeSlots = cr.u32(false);
      const codeLimit = cr.u32(false);
      const hashSize = cr.u8();
      const hashType = cr.u8();
      cr.u8(); // platform
      const pageSizeExp = cr.u8();
      sig.codeLimit = codeLimit;
      sig.pageSizeExp = pageSizeExp;
      sig.hashSize = hashSize;
      sig.hashType = hashType;

      if (nCodeSlots > budget.maxCodeSlots) {
        diagnostics.push({
          code: 'budget.code_slots', position: { offset: sigFileOff + blobOff, basis: 'file', sliceId: slice.ref },
          message: `slice[${slice.index}] code slot 数量 ${nCodeSlots} 超过预算 ${budget.maxCodeSlots}`,
        });
        return;
      }
      const pageSize = 2 ** pageSizeExp;
      const hashesBase = sigFileOff + blobOff + hashOffset + nSpecial * hashSize;
      for (let s = 0; s < nCodeSlots; s++) {
        const expected = data.subarray(hashesBase + s * hashSize, hashesBase + (s + 1) * hashSize);
        const pageOffset = slice.offset + s * pageSize;
        const len = Math.min(pageSize, codeLimit - s * pageSize);
        sig.slots.push({ index: s, pageOffset, length: len, expected: Uint8Array.from(expected) });
        materials.push({
          kind: 'code_slot',
          name: `code_slot[${slice.index}][${s}] page@0x${pageOffset.toString(16)} ${len}B hashType=${hashType}`,
          sliceRef: slice.ref,
          raw: expected,
          meta: {
            slot_index: s,
            page_offset_bytes: pageOffset,
            page_length_bytes: len,
            page_size_exp: pageSizeExp,
            hash_type: hashType,
            hash_size_bytes: hashSize,
            basis: 'file',
          },
        });
      }
    }
  }
}
