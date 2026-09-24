// Mach-O / universal binary 解析层。
// 约定：fat 头与 code signature 一律大端；thin Mach-O 由自身 magic 决定字节序。
// 原始字节以 rawHex 保留；派生量携带 unit/basis；解析不做四舍五入式修正。
import { createHash } from 'node:crypto';
import type {
  BlobIndex, CodeSlot, Diagnostic, Finding, FindingCategory, FindingSeverity,
  MachoDocument, Quantity, SignatureInfo, SliceInfo,
} from '../../shared/types.js';

export const FAT_MAGIC = 0xcafebabe;
export const FAT_CIGAM = 0xbebafeca;
export const MH_MAGIC_64 = 0xfeedfacf;
export const LC_SEGMENT_64 = 0x19;
export const LC_CODE_SIGNATURE = 0x1d;
export const CS_SUPERBLOB_MAGIC = 0xfade0cc0;
export const CS_CODEDIRECTORY_MAGIC = 0xfade0c02;

const KNOWN_BLOB_MAGICS = new Map<number, string>([
  [0xfade0c02, 'CodeDirectory'],
  [0xfade0c00, 'Requirement'],
  [0xfade0c01, 'Requirements'],
  [0xfade7171, 'Entitlements'],
  [0xfade7172, 'DER-Entitlements'],
  [0xfade0b01, 'BlobWrapper'],
]);

const CMD_NAMES: Record<number, string> = {
  [LC_SEGMENT_64]: 'LC_SEGMENT_64',
  [LC_CODE_SIGNATURE]: 'LC_CODE_SIGNATURE',
  0x80000028: 'LC_MAIN',
  0x0b: 'LC_DYSYMTAB',
  0x02: 'LC_SYMTAB',
  0x80000022: 'LC_DYLD_INFO_ONLY',
  0x32: 'LC_BUILD_VERSION',
};

export interface ParseParams {
  endianPolicy: 'strict' | 'allow-swapped';
  maxCommandsPerSlice: number;
  maxSlices: number;
  maxFileBytes: number;
  alignmentMaxExponent: number;
}

export interface FindingDraft {
  ruleId: string;
  category: FindingCategory;
  severity: FindingSeverity;
  message: string;
  subjects: string[];
  evidence: Finding['evidence'];
  candidates?: { label: string; detail: string }[];
}

export interface ParseResult {
  document: MachoDocument | null;
  drafts: FindingDraft[];
  diagnostics: Diagnostic[];
}

export class BoundaryError extends Error {
  basis: string;
  offset: number;
  constructor(basis: string, offset: number, what: string) {
    super(what + ' @ ' + basis + '+0x' + offset.toString(16));
    this.basis = basis;
    this.offset = offset;
  }
}

export function q(value: number, unit: Quantity['unit'], basis: string): Quantity {
  return { value, unit, basis };
}

export function evidenceOf(basis: string, buf: Buffer, offset: number, length: number, note?: string) {
  const safeOff = Math.max(0, Math.min(offset, buf.length));
  const safeLen = Math.max(0, Math.min(length, buf.length - safeOff));
  const ev: Finding['evidence'][number] = {
    basis, offset: safeOff, length: safeLen,
    hex: buf.subarray(safeOff, safeOff + safeLen).toString('hex'),
  };
  if (note) ev.note = note;
  return [ev];
}

export function cpuName(cputype: number, cpusubtype: number): string {
  if (cputype === 0x0100000c) {
    if ((cpusubtype & 0xff) === 2) return 'arm64e';
    return 'arm64';
  }
  if (cputype === 0x01000007) return 'x86_64';
  return 'cpu_0x' + cputype.toString(16) + '_' + cpusubtype;
}

const HEX8 = '0x';
function hex(n: number): string { return HEX8 + (n >>> 0).toString(16).padStart(8, '0'); }

function readU32(buf: Buffer, off: number, basis: string, le: boolean): number {
  if (off + 4 > buf.length || off < 0) throw new BoundaryError(basis, off, 'u32 越界');
  return le ? buf.readUInt32LE(off) : buf.readUInt32BE(off);
}

// ------------------------------- Fat header -------------------------------

interface ParsedFat {
  magic: number;
  swapped: boolean;
  declaredOrder: 'big' | 'little';
  nfatArch: number;
  archRaw: { cputype: number; cpusubtype: number; offset: number; size: number; align: number; rawHex: string }[];
}

export function parseFatHeader(buf: Buffer, pp: ParseParams, drafts: FindingDraft[], diags: Diagnostic[]): ParsedFat | null {
  let magic = 0;
  try {
    magic = readU32(buf, 0, 'file', false);
  } catch (e) {
    const be = e as BoundaryError;
    diags.push({ code: 'FAT-TRUNC', message: 'fat header magic 读取越界', position: { basis: be.basis, offset: be.offset } });
    drafts.push({ ruleId: 'FAT-TRUNC-01', category: 'format', severity: 'violation', message: '文件不足 4 字节，无法读取 fat magic', subjects: ['fat'], evidence: [{ basis: 'file', offset: 0, length: buf.length, hex: buf.toString('hex') }] });
    return null;
  }
  const swapped = magic === FAT_CIGAM;
  const isFat = magic === FAT_MAGIC || swapped;
  if (!isFat) {
    diags.push({ code: 'FAT-MAGIC', message: 'fat magic 不被识别: ' + hex(magic), position: { basis: 'file', offset: 0 } });
    return null;
  }
  if (swapped && pp.endianPolicy === 'strict') {
    drafts.push({
      ruleId: 'ENDIAN-01', category: 'endian', severity: 'violation',
      message: 'fat magic 为 FAT_CIGAM（字节序反转），与 universal binary 大端规范冲突',
      subjects: ['fat'], evidence: evidenceOf('file', buf, 0, 4, 'FAT_CIGAM=0xbebafeca（按字节序翻转后的 magic）'),
    });
  } else if (swapped) {
    diags.push({ code: 'ENDIAN-SWAP', message: 'fat magic 为 FAT_CIGAM，按 allow-swapped 策略继续解析', position: { basis: 'file', offset: 0 } });
  }
  // CIGAM => 其余 fat 头字段为小端；正常 fat => 大端
  const le = swapped;
  const nfatArch = readU32(buf, 4, 'file', le);
  if (nfatArch > pp.maxSlices) {
    drafts.push({
      ruleId: 'RES-01', category: 'budget', severity: 'violation',
      message: `slice 数量 ${nfatArch} 超过预算 ${pp.maxSlices}（资源预算耗尽）`,
      subjects: ['fat'], evidence: evidenceOf('file', buf, 4, 4, 'nfat_arch'),
    });
  }
  const count = Math.min(nfatArch, pp.maxSlices);
  const archRaw: ParsedFat['archRaw'] = [];
  for (let i = 0; i < count; i++) {
    const off = 8 + i * 20;
    if (off + 20 > buf.length) {
      diags.push({ code: 'FAT-ARCH-TRUNC', message: `arch[${i}] 表项越界`, position: { basis: 'file', offset: off } });
      drafts.push({ ruleId: 'FAT-TRUNC-01', category: 'format', severity: 'violation', message: `fat arch[${i}] 表项超出文件边界`, subjects: [`arch[${i}]`], evidence: evidenceOf('file', buf, off, buf.length - off) });
      break;
    }
    archRaw.push({
      cputype: readU32(buf, off, 'file', le),
      cpusubtype: readU32(buf, off + 4, 'file', le),
      offset: readU32(buf, off + 8, 'file', le),
      size: readU32(buf, off + 12, 'file', le),
      align: readU32(buf, off + 16, 'file', le),
      rawHex: buf.subarray(off, off + 20).toString('hex'),
    });
  }
  return { magic, swapped, declaredOrder: swapped ? 'little' : 'big', nfatArch, archRaw };
}

// ------------------------------- Thin slices -------------------------------

interface ParsedSlice {
  slice: SliceInfo;
  codeSignatureOffset: number | null;
  codeSignatureSize: number | null;
  truncated: boolean;
}

function parseCommands(sliceBuf: Buffer, le: boolean, sliceId: string, pp: ParseParams,
  drafts: FindingDraft[], diags: Diagnostic[]) {
  const ncmds = le ? sliceBuf.readUInt32LE(16) : sliceBuf.readUInt32BE(16);
  const sizeofcmds = le ? sliceBuf.readUInt32LE(20) : sliceBuf.readUInt32BE(20);
  if (32 + sizeofcmds > sliceBuf.length) {
    drafts.push({
      ruleId: 'LC-01', category: 'load-command', severity: 'violation',
      message: `load command 区结束位置 0x${(32 + sizeofcmds).toString(16)} 越过 slice 边界 0x${sliceBuf.length.toString(16)}`,
      subjects: [`${sliceId}.lc-header`], evidence: evidenceOf('slice', sliceBuf, 20, 4, 'sizeofcmds'),
    });
  }
  if (ncmds > pp.maxCommandsPerSlice) {
    drafts.push({
      ruleId: 'RES-01', category: 'budget', severity: 'violation',
      message: `load command 数量 ${ncmds} 超过预算 ${pp.maxCommandsPerSlice}`,
      subjects: [`${sliceId}.lc-header`], evidence: evidenceOf('slice', sliceBuf, 16, 4, 'ncmds'),
    });
  }
  const commands: SliceInfo['commands'] = [];
  let off = 32;
  let codeSignatureOffset: number | null = null;
  let codeSignatureSize: number | null = null;
  const limit = Math.min(32 + sizeofcmds, sliceBuf.length);
  const count = Math.min(ncmds, pp.maxCommandsPerSlice);
  for (let i = 0; i < count; i++) {
    if (off + 8 > limit) {
      drafts.push({
        ruleId: 'LC-01', category: 'load-command', severity: 'violation',
        message: `load command[${i}] 头部越过 command 区/文件边界`,
        subjects: [`${sliceId}.lc[${i}]`], evidence: evidenceOf('slice', sliceBuf, off, Math.min(8, sliceBuf.length - off)),
      });
      break;
    }
    const cmd = le ? sliceBuf.readUInt32LE(off) : sliceBuf.readUInt32BE(off);
    const cmdsize = le ? sliceBuf.readUInt32LE(off + 4) : sliceBuf.readUInt32BE(off + 4);
    const endOffset = off + cmdsize;
    const withinHeader = endOffset <= 32 + sizeofcmds;
    const withinSlice = cmdsize >= 8 && off + cmdsize <= sliceBuf.length;
    if (!cmdsize || cmdsize < 8 || (cmdsize % 8 !== 0)) {
      diags.push({ code: 'LC-SIZE', message: `lc[${i}] cmdsize=${cmdsize} 非法（须 >=8 且 8 字节对齐）`, position: { basis: 'slice', offset: off + 4 } });
    }
    if (!withinHeader || !withinSlice) {
      drafts.push({
        ruleId: 'LC-01', category: 'load-command', severity: 'violation',
        message: `load command[${i}] ${CMD_NAMES[cmd] ?? '0x' + cmd.toString(16)} 越界：[0x${off.toString(16)},0x${endOffset.toString(16)})，cmdsize=${cmdsize}`,
        subjects: [`${sliceId}.lc[${i}]`], evidence: evidenceOf('slice', sliceBuf, off, 8, 'cmd/cmdsize'),
      });
    }
    const cmdName = CMD_NAMES[cmd] ?? 'UNKNOWN(' + hex(cmd) + ')';
    if (!CMD_NAMES[cmd]) diags.push({ code: 'LC-UNKNOWN', message: `lc[${i}] 未知 command ${hex(cmd)}，原始表示保留`, position: { basis: 'slice', offset: off } });
    commands.push({
      index: i, cmd, cmdHex: hex(cmd), cmdName,
      cmdsize: q(cmdsize, 'byte', 'slice'),
      offset: q(off, 'byte', 'slice'),
      endOffset, withinHeader, withinSlice: withinHeader && withinSlice,
      rawHex: sliceBuf.subarray(off, off + Math.min(8, sliceBuf.length - off)).toString('hex'),
    });
    if (cmd === LC_CODE_SIGNATURE && off + 16 <= sliceBuf.length) {
      codeSignatureOffset = le ? sliceBuf.readUInt32LE(off + 8) : sliceBuf.readUInt32BE(off + 8);
      codeSignatureSize = le ? sliceBuf.readUInt32LE(off + 12) : sliceBuf.readUInt32BE(off + 12);
    }
    // 越界的 command 不能再作为步进依据，避免级联误报
    if (!cmdsize || cmdsize < 8) break;
    off = endOffset;
  }
  return { commands, sizeofcmds, codeSignatureOffset, codeSignatureSize };
}

function parseSlice(file: Buffer, archIdx: number, fileOffset: number, sliceSize: number,
  alignExp: number, alignBytes: number, alignOverflow: boolean, pp: ParseParams,
  drafts: FindingDraft[], diags: Diagnostic[]): ParsedSlice | null {
  const sliceId = `slice[${archIdx}]`;
  if (fileOffset + sliceSize > file.length) {
    drafts.push({
      ruleId: 'SLICE-RANGE-01', category: 'slice-overlap', severity: 'violation',
      message: `${sliceId} [0x${fileOffset.toString(16)},+0x${sliceSize.toString(16)}) 越过文件末尾 0x${file.length.toString(16)}`,
      subjects: [sliceId], evidence: evidenceOf('file', file, fileOffset, Math.min(sliceSize, file.length - fileOffset)),
    });
  }
  const end = Math.min(fileOffset + sliceSize, file.length);
  const sliceBuf = file.subarray(fileOffset, end);
  let le = true;
  let magic = 0;
  if (sliceBuf.length >= 4) {
    const vLE = sliceBuf.readUInt32LE(0);
    const vBE = sliceBuf.readUInt32BE(0);
    if (vLE === MH_MAGIC_64) { le = true; magic = MH_MAGIC_64; }
    else if (vBE === MH_MAGIC_64) { le = false; magic = MH_MAGIC_64; }
    else {
      magic = vLE;
      diags.push({ code: 'MH-MAGIC', message: sliceId + ' 未知 thin magic ' + hex(vLE), position: { basis: 'slice', offset: 0 } });
      drafts.push({ ruleId: 'MH-MAGIC-01', category: 'format', severity: 'violation', message: sliceId + ' thin Mach-O magic 不被支持', subjects: [sliceId], evidence: evidenceOf('slice', sliceBuf, 0, 4) });
    }
  } else {
    drafts.push({ ruleId: 'FAT-TRUNC-01', category: 'format', severity: 'violation', message: sliceId + ' 不足 32 字节 mach_header_64', subjects: [sliceId], evidence: evidenceOf('file', file, fileOffset, sliceBuf.length) });
    return null;
  }
  let commands: SliceInfo['commands'] = [];
  let sizeofcmds = 0;
  let csOff: number | null = null;
  let csSize: number | null = null;
  let ncmds = 0;
  let truncated = false;
  if (sliceBuf.length >= 32) {
    ncmds = le ? sliceBuf.readUInt32LE(16) : sliceBuf.readUInt32BE(16);
    const parsed = parseCommands(sliceBuf, le, sliceId, pp, drafts, diags);
    commands = parsed.commands;
    sizeofcmds = parsed.sizeofcmds;
    csOff = parsed.codeSignatureOffset;
    csSize = parsed.codeSignatureSize;
  } else {
    truncated = true;
    drafts.push({ ruleId: 'FAT-TRUNC-01', category: 'format', severity: 'violation', message: sliceId + ' mach_header_64 被截断', subjects: [sliceId], evidence: evidenceOf('slice', sliceBuf, 0, sliceBuf.length) });
  }
  const cputype = sliceBuf.length >= 12 ? (le ? sliceBuf.readUInt32LE(4) : sliceBuf.readUInt32BE(4)) : 0;
  const cpusubtype = sliceBuf.length >= 12 ? (le ? sliceBuf.readUInt32LE(8) : sliceBuf.readUInt32BE(8)) : 0;
  const linkedit = csOff !== null && csSize !== null ? {
    dataoff: q(csOff, 'byte', 'slice'),
    datasize: q(csSize, 'byte', 'slice'),
    endOffset: csOff + csSize,
    withinSlice: csOff + csSize <= sliceBuf.length,
  } : null;
  const slice: SliceInfo = {
    sliceId, archIndex: archIdx, cpuName: cpuName(cputype, cpusubtype),
    range: { offset: fileOffset, size: sliceSize },
    align: q(alignExp, 'exponent', 'file'),
    alignBytes, alignOverflow,
    byteOrder: le ? 'little' : 'big',
    magicHex: hex(magic), is64: true, ncmds,
    sizeofcmds: q(sizeofcmds, 'byte', 'slice'),
    commands, linkedit, signature: null,
  };
  return { slice, codeSignatureOffset: csOff, codeSignatureSize: csSize, truncated };
}

// --------------------------- Code signature blob ---------------------------

function parseSignature(sliceBuf: Buffer, csOff: number, csSize: number, sliceId: string,
  drafts: FindingDraft[], diags: Diagnostic[]): SignatureInfo | null {
  if (csOff + csSize > sliceBuf.length) {
    drafts.push({
      ruleId: 'SIG-RANGE-01', category: 'signature-format', severity: 'violation',
      message: `LC_CODE_SIGNATURE 指向 [0x${csOff.toString(16)},+0x${csSize.toString(16)}) 越过 slice 末尾 0x${sliceBuf.length.toString(16)}`,
      subjects: [`${sliceId}.signature`], evidence: evidenceOf('slice', sliceBuf, csOff, Math.min(csSize, sliceBuf.length - csOff)),
    });
  }
  const end = Math.min(csOff + csSize, sliceBuf.length);
  const blob = sliceBuf.subarray(csOff, end);
  if (blob.length < 12) {
    drafts.push({ ruleId: 'SIG-FORMAT-01', category: 'signature-format', severity: 'violation', message: 'SuperBlob 头不足 12 字节', subjects: [`${sliceId}.signature`], evidence: evidenceOf('slice', sliceBuf, csOff, blob.length) });
    return null;
  }
  const magic = blob.readUInt32BE(0);
  const length = blob.readUInt32BE(4);
  const count = blob.readUInt32BE(8);
  if (magic !== CS_SUPERBLOB_MAGIC) {
    drafts.push({
      ruleId: 'SIG-FORMAT-01', category: 'signature-format', severity: 'violation',
      message: `签名 blob magic ${hex(magic)} 不是 CS_EMBEDDED_SIGNATURE(0xfade0cc0)，属于不支持格式`,
      subjects: [`${sliceId}.signature`], evidence: evidenceOf('slice', sliceBuf, csOff, 4, 'superblob magic'),
    });
    return null;
  }
  const blobs: BlobIndex[] = [];
  let cdOffset: number | null = null;
  for (let i = 0; i < count; i++) {
    const idxOff = 12 + i * 8;
    if (idxOff + 8 > blob.length) {
      drafts.push({ ruleId: 'SIG-FORMAT-01', category: 'signature-format', severity: 'violation', message: `SuperBlob index[${i}] 越界`, subjects: [`${sliceId}.signature`], evidence: evidenceOf('superblob', blob, idxOff, blob.length - idxOff) });
      break;
    }
    const type = blob.readUInt32BE(idxOff);
    const boff = blob.readUInt32BE(idxOff + 4);
    let bm: number | null = null;
    if (boff + 4 <= blob.length) bm = blob.readUInt32BE(boff);
    const recognized = bm !== null && KNOWN_BLOB_MAGICS.has(bm);
    if (!recognized) {
      drafts.push({
        ruleId: 'SIG-UNKNOWN-BLOB-01', category: 'signature-format', severity: 'violation',
        message: `SuperBlob index[${i}] type=${type} 指向未知 blob magic ${bm === null ? '(越界)' : hex(bm)}，属于不支持格式`,
        subjects: [`${sliceId}.signature.blob[${i}]`],
        evidence: boff + 4 <= blob.length ? evidenceOf('superblob', blob, boff, 4, 'unknown blob magic') : evidenceOf('superblob', blob, idxOff, 8, 'blob offset 越界'),
      });
    }
    if (type === 0 && bm === CS_CODEDIRECTORY_MAGIC) cdOffset = boff;
    blobs.push({
      type, typeName: type === 0 ? 'CSSLOT_CODEDIRECTORY' : 'type_' + type,
      offset: q(boff, 'byte', 'superblob'),
      magic: bm, magicHex: bm === null ? '(oob)' : hex(bm), recognized,
    });
  }
  let codeDirectory: SignatureInfo['codeDirectory'] = null;
  const slots: CodeSlot[] = [];
  if (cdOffset !== null && cdOffset + 44 <= blob.length) {
    const cd = blob.subarray(cdOffset);
    const hashType = cd[8 + 4 + 4 + 4 + 4 + 4 + 4 + 4] ?? 0; // 占位，下面用显式偏移
    // CodeDirectory 固定头：magic,length,version,flags,hashOffset,identOffset,nSpecialSlots,nCodeSlots,codeLimit,hashSize,hashType,platform,pageSize
    const hashOffset = cd.readUInt32BE(16);
    const nSpecialSlots = cd.readUInt32BE(24);
    const nCodeSlots = cd.readUInt32BE(28);
    const codeLimit = cd.readUInt32BE(32);
    const hashSize = cd[36] ?? 0;
    const hashTypeB = cd[37] ?? 0;
    const pageSizeExp = cd[39] ?? 0;
    const pageSizeBytes = pageSizeExp < 31 ? 2 ** pageSizeExp : 0;
    const hashTypeName = hashTypeB === 2 ? 'sha256' : hashTypeB === 1 ? 'sha1' : 'unknown(' + hashTypeB + ')';
    if (hashTypeB !== 2) {
      drafts.push({
        ruleId: 'SIG-HASH-TYPE-01', category: 'signature-format', severity: 'violation',
        message: `CodeDirectory hashType=${hashTypeB} 不是 sha256(2)，无法复核摘要，属于不支持格式`,
        subjects: [`${sliceId}.signature.cd`], evidence: evidenceOf('codedirectory', cd, 37, 1, 'hashType'),
      });
    } else {
      for (let s = 0; s < nCodeSlots; s++) {
        const slotOff = hashOffset + s * hashSize;
        if (slotOff + hashSize > cd.length) {
          diags.push({ code: 'CD-SLOT-OOB', message: `code slot[${s}] 摘要越界`, position: { basis: 'codedirectory', offset: slotOff } });
          break;
        }
        const expected = cd.subarray(slotOff, slotOff + hashSize).toString('hex');
        const pageOff = s * pageSizeBytes;
        if (pageOff >= codeLimit || pageSizeBytes === 0) {
          slots.push({ slotIndex: s, label: `code slot[${s}]`, expectedHashHex: expected, actualHashHex: null, match: null });
          continue;
        }
        const pageEnd = Math.min(pageOff + pageSizeBytes, codeLimit);
        const actual = createHash('sha256').update(sliceBuf.subarray(pageOff, pageEnd)).digest('hex');
        const match = actual === expected;
        if (!match) {
          drafts.push({
            ruleId: 'SIG-HASH-01', category: 'signature-hash', severity: 'violation',
            message: `code slot[${s}] 摘要不匹配（hash 不匹配）：期望 ${expected.slice(0, 16)}… 实际 ${actual.slice(0, 16)}…，页区间 [0x${pageOff.toString(16)},0x${pageEnd.toString(16)})`,
            subjects: [`${sliceId}.signature.cd.slot[${s}]`],
            evidence: evidenceOf('slice', sliceBuf, pageOff, Math.min(16, pageEnd - pageOff), 'slot 页首字节'),
          });
        }
        slots.push({ slotIndex: s, label: `code slot[${s}]`, expectedHashHex: expected, actualHashHex: actual, match });
      }
    }
    codeDirectory = {
      hashType: hashTypeB, hashTypeName, hashSize,
      pageSize: q(pageSizeExp, 'exponent', 'codedirectory'),
      pageSizeBytes,
      codeLimit: q(codeLimit, 'byte', 'slice'),
      nCodeSlots, nSpecialSlots, slots,
    };
    void hashType;
    // 覆盖带：signed 段 [0, codeLimit)，signature blob 段 [csOff, csOff+length)
    const sigLen = Math.min(length, csSize);
    const gaps: { offset: number; size: number }[] = [];
    if (codeLimit < csOff) gaps.push({ offset: codeLimit, size: csOff - codeLimit });
    if (csOff + sigLen < sliceBuf.length) gaps.push({ offset: csOff + sigLen, size: sliceBuf.length - (csOff + sigLen) });
    if (gaps.length > 0) {
      drafts.push({
        ruleId: 'SIG-COVERAGE-01', category: 'signature-coverage', severity: 'violation',
        message: `签名未覆盖尾部/间隙：${gaps.map((g) => `[0x${g.offset.toString(16)},+0x${g.size.toString(16)})`).join(' ')}（覆盖缺口）`,
        subjects: [`${sliceId}.signature`],
        evidence: gaps.map((g) => ({ basis: 'slice', offset: g.offset, length: Math.min(g.size, 16), hex: sliceBuf.subarray(g.offset, g.offset + Math.min(g.size, 16)).toString('hex'), note: '未覆盖区间首字节' })),
      });
    }
    return {
      range: { offset: csOff, size: csSize },
      fileRange: { offset: csOff, size: csSize },
      length: q(length, 'byte', 'superblob'),
      magicHex: hex(magic), count, blobs, codeDirectory,
      coverage: {
        signedRange: { offset: 0, size: codeLimit },
        signatureRange: { offset: csOff, size: sigLen },
        uncoveredGaps: gaps,
      },
    };
  }
  return {
    range: { offset: csOff, size: csSize },
    fileRange: { offset: csOff, size: csSize },
    length: q(length, 'byte', 'superblob'),
    magicHex: hex(magic), count, blobs, codeDirectory,
    coverage: { signedRange: { offset: 0, size: 0 }, signatureRange: { offset: csOff, size: Math.min(length, csSize) }, uncoveredGaps: [] },
  };
}

// ------------------------------- 主入口 ------------------------------------

export function parseMacho(buf: Buffer, pp: ParseParams): ParseResult {
  const drafts: FindingDraft[] = [];
  const diags: Diagnostic[] = [];
  if (buf.length > pp.maxFileBytes) {
    drafts.push({
      ruleId: 'RES-01', category: 'budget', severity: 'violation',
      message: `文件 ${buf.length} byte 超过预算 ${pp.maxFileBytes} byte（资源预算耗尽）`,
      subjects: ['file'], evidence: [],
    });
    return { document: null, drafts, diagnostics: diags };
  }
  const fat = parseFatHeader(buf, pp, drafts, diags);
  if (!fat) return { document: null, drafts, diagnostics: diags };

  const slices: SliceInfo[] = [];
  for (let i = 0; i < fat.archRaw.length; i++) {
    const a = fat.archRaw[i]!;
    // 对齐：指数换算溢出即违规，绝不做四舍五入修正
    let alignBytes = 0;
    let alignOverflow = false;
    if (a.align > 30) {
      alignOverflow = true;
      drafts.push({
        ruleId: 'ALIGN-01', category: 'alignment', severity: 'violation',
        message: `slice[${i}] 对齐指数 2^${a.align} 溢出（>2^30），无法换算为字节对齐`,
        subjects: [`slice[${i}]`], evidence: [{ basis: 'file', offset: 8 + i * 20 + 16, length: 4, hex: buf.subarray(8 + i * 20 + 16, 8 + i * 20 + 20).toString('hex'), note: 'align exponent' }],
      });
    } else {
      alignBytes = 2 ** a.align;
      if (a.offset % alignBytes !== 0) {
        drafts.push({
          ruleId: 'ALIGN-01', category: 'alignment', severity: 'violation',
          message: `slice[${i}] 偏移 0x${a.offset.toString(16)} 未满足 2^${a.align}=${alignBytes} 对齐（余数 ${a.offset % alignBytes}，不做四舍五入修正）`,
          subjects: [`slice[${i}]`], evidence: [{ basis: 'file', offset: 8 + i * 20 + 8, length: 12, hex: buf.subarray(8 + i * 20 + 8, 8 + i * 20 + 20).toString('hex'), note: 'offset/size/align' }],
        });
      }
    }
    const parsed = parseSlice(buf, i, a.offset, a.size, a.align, alignBytes, alignOverflow, pp, drafts, diags);
    if (!parsed) continue;
    const { slice, codeSignatureOffset, codeSignatureSize } = parsed;
    const sliceBuf = buf.subarray(a.offset, Math.min(a.offset + a.size, buf.length));
    if (codeSignatureOffset !== null && codeSignatureSize !== null && codeSignatureOffset < sliceBuf.length) {
      slice.signature = parseSignature(sliceBuf, codeSignatureOffset, codeSignatureSize, slice.sliceId, drafts, diags);
    }
    slices.push(slice);
  }

  // slice 重叠：按偏移排序后两两相邻比较，范围不得重叠
  const sorted = [...slices].sort((x, y) => x.range.offset - y.range.offset || x.archIndex - y.archIndex);
  for (let i = 1; i < sorted.length; i++) {
    const prev = sorted[i - 1]!;
    const cur = sorted[i]!;
    const prevEnd = prev.range.offset + prev.range.size;
    if (cur.range.offset < prevEnd) {
      drafts.push({
        ruleId: 'SLICE-OVERLAP-01', category: 'slice-overlap', severity: 'violation',
        message: `slice 范围重叠：${prev.sliceId} [0x${prev.range.offset.toString(16)},0x${prevEnd.toString(16)}) 与 ${cur.sliceId} [0x${cur.range.offset.toString(16)},0x${(cur.range.offset + cur.range.size).toString(16)})`,
        subjects: [prev.sliceId, cur.sliceId],
        evidence: [{ basis: 'file', offset: cur.range.offset, length: Math.min(16, buf.length - cur.range.offset), hex: buf.subarray(cur.range.offset, cur.range.offset + Math.min(16, buf.length - cur.range.offset)).toString('hex'), note: '重叠起点' }],
      });
    }
  }

  // 多架构同名：同一 cpu 名出现多个 slice
  const byCpu = new Map<string, string[]>();
  for (const s of slices) {
    const list = byCpu.get(s.cpuName) ?? [];
    list.push(s.sliceId);
    byCpu.set(s.cpuName, list);
  }
  for (const [cpu, ids] of byCpu) {
    if (ids.length > 1) {
      drafts.push({
        ruleId: 'ARCH-DUP-01', category: 'multi-arch', severity: 'warning',
        message: `多架构同名：${cpu} 出现 ${ids.length} 个 slice（${ids.join(', ')}），目标架构策略无法唯一决定`,
        subjects: ids,
        evidence: [],
        candidates: ids.map((id) => ({ label: id, detail: `选择 ${id} 作为 ${cpu} 的目标 slice` })),
      });
    }
  }

  const document: MachoDocument = {
    fat: {
      magic: fat.magic,
      magicHex: hex(fat.magic),
      byteOrder: 'big',
      declaredOrder: fat.declaredOrder,
      swappedMagic: fat.swapped,
      nfatArch: fat.nfatArch,
      archs: fat.archRaw.map((a, i) => ({
        index: i,
        cputype: a.cputype,
        cpusubtype: a.cpusubtype,
        cpuName: cpuName(a.cputype, a.cpusubtype),
        offset: q(a.offset, 'byte', 'file'),
        size: q(a.size, 'byte', 'file'),
        align: q(a.align, 'exponent', 'file'),
        alignBytes: a.align > 30 ? 0 : 2 ** a.align,
        alignOverflow: a.align > 30,
        rawHex: a.rawHex,
      })),
    },
    slices,
    fileSize: q(buf.length, 'byte', 'file'),
  };
  return { document, drafts, diagnostics: diags };
}
