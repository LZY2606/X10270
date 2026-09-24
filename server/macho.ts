// Mach-O / universal(fat) binary parser.
// Coordinates: every offset is an absolute byte coordinate in the imported file
// (basis: "file") unless explicitly marked basis: "slice".
// Raw on-disk representation is preserved; normalization happens only in derived layers.

import { createHash } from 'node:crypto';

export const FAT_MAGIC = 0xcafebabe;
export const FAT_CIGAM = 0xcefaedfe;
export const FAT_MAGIC_64 = 0xcafebabf;
export const FAT_CIGAM_64 = 0xbfbafeca;
export const MH_MAGIC = 0xfeedface;
export const MH_CIGAM = 0xcefaedfe;
export const MH_MAGIC_64 = 0xfeedfacf;
export const MH_CIGAM_64 = 0xcffaedfe;

export const LC_SEGMENT = 0x1;
export const LC_SYMTAB = 0x2;
export const LC_DYSYMTAB = 0xb;
export const LC_SEGMENT_64 = 0x19;
export const LC_UUID = 0x1b;
export const LC_CODE_SIGNATURE = 0x1d;
export const LC_ENCRYPTION_INFO_64 = 0x2c;
export const LC_DYLD_INFO = 0x22;
export const LC_DYLD_INFO_ONLY = 0x80000022;
export const LC_MAIN = 0x80000028;
export const LC_BUILD_VERSION = 0x32;
export const LC_DYLD_EXPORTS_TRIE = 0x80000033;
export const LC_DYLD_CHAINED_FIXUPS = 0x80000034;

export const CSMAGIC_EMBEDDED_SIGNATURE = 0xfade0cc0;
export const CSMAGIC_CODEDIRECTORY = 0xfade0c02;
export const CSMAGIC_REQUIREMENT = 0xfade0c00;
export const CSMAGIC_REQUIREMENTS = 0xfade0c01;

export type Endian = 'big' | 'little';

export interface Diagnostic {
  path: string;
  message: string;
  byteOffset?: number;
  raw?: unknown;
}

export interface SliceView {
  id: string;
  index: number;
  cputype: number;
  cpusubtype: number;
  archName: string;
  offset: number;
  size: number;
  alignExponent: number;
  alignBytes: number | null;
  alignNormalizable: boolean;
  endian: Endian;
}

export interface CommandView {
  id: string;
  sliceId: string;
  index: number;
  cmd: number;
  cmdName: string;
  cmdsize: number;
  offset: number;
  endOffset: number;
  relOffset: number;
  withinSlice: boolean;
  detail: Record<string, unknown>;
}

export interface SigBlobView {
  slotType: number;
  offset: number;
  end: number;
  magic: number;
  magicName: string;
  supported: boolean;
}

export interface CodeSlotView {
  index: number;
  offset: number;
  length: number;
  basis: string;
  expected: string;
  actual: string | null;
  match: boolean | null;
}

export interface SignatureView {
  sliceId: string;
  dataoff: number;
  datasize: number;
  absOffset: number;
  absEnd: number;
  magic: number;
  magicName: string;
  supported: boolean;
  blobs: SigBlobView[];
  codeLimit: number | null;
  hashType: number | null;
  hashTypeName: string;
  hashSize: number | null;
  pageSize: number | null;
  coverageStart: number;
  coverageEnd: number | null;
  slots: CodeSlotView[];
}

export interface ParseOptions {
  maxSlices?: number;
  maxCommands?: number;
  maxBlobs?: number;
}

export interface ParseResult {
  status: 'ok' | 'malformed' | 'budget_exhausted';
  fileKind: 'fat' | 'fat64' | 'thin' | null;
  endian: Endian | null;
  magic: number | null;
  fileSize: number;
  digest: string;
  rawHeader: Array<{ field: string; raw: string; note?: string }>;
  slices: SliceView[];
  commands: CommandView[];
  signatures: SignatureView[];
  diagnostics: Diagnostic[];
  budget?: { limit: string; used: number; max: number };
}

function archName(cputype: number, cpusubtype: number): string {
  switch (cputype) {
    case 7:
      return 'i386';
    case 12:
      return 'arm';
    case 18:
      return 'ppc';
    case 0x01000007:
      return 'x86_64';
    case 0x0100000c:
      return cpusubtype === 2 ? 'arm64e' : 'arm64';
    default:
      return `unknown-arch(0x${(cputype >>> 0).toString(16).padStart(8, '0')})`;
  }
}

export function commandName(cmd: number): string {
  const names: Record<number, string> = {
    [LC_SEGMENT]: 'LC_SEGMENT',
    [LC_SYMTAB]: 'LC_SYMTAB',
    [LC_DYSYMTAB]: 'LC_DYSYMTAB',
    [LC_SEGMENT_64]: 'LC_SEGMENT_64',
    [LC_UUID]: 'LC_UUID',
    [LC_CODE_SIGNATURE]: 'LC_CODE_SIGNATURE',
    [LC_ENCRYPTION_INFO_64]: 'LC_ENCRYPTION_INFO_64',
    [LC_DYLD_INFO]: 'LC_DYLD_INFO',
    [LC_DYLD_INFO_ONLY]: 'LC_DYLD_INFO_ONLY',
    [LC_MAIN]: 'LC_MAIN',
    [LC_BUILD_VERSION]: 'LC_BUILD_VERSION',
    [LC_DYLD_EXPORTS_TRIE]: 'LC_DYLD_EXPORTS_TRIE',
    [LC_DYLD_CHAINED_FIXUPS]: 'LC_DYLD_CHAINED_FIXUPS',
  };
  return names[cmd] ?? `LC_UNKNOWN(0x${(cmd >>> 0).toString(16).padStart(8, '0')})`;
}

function hashName(hashType: number): string {
  switch (hashType) {
    case 1:
      return 'SHA1';
    case 2:
      return 'SHA256';
    default:
      return `UNSUPPORTED_HASH_TYPE(${hashType})`;
  }
}

export function sha256hex(data: Buffer): string {
  return createHash('sha256').update(data).digest('hex');
}

export function parseMachO(data: Buffer, options: ParseOptions = {}): ParseResult {
  const maxSlices = options.maxSlices ?? 64;
  const maxCommands = options.maxCommands ?? 4096;
  const maxBlobs = options.maxBlobs ?? 32;
  const diagnostics: Diagnostic[] = [];
  const fileSize = data.length;
  const result: ParseResult = {
    status: 'ok',
    fileKind: null,
    endian: null,
    magic: null,
    fileSize,
    digest: sha256hex(data),
    rawHeader: [],
    slices: [],
    commands: [],
    signatures: [],
    diagnostics,
  };

  if (fileSize < 4) {
    result.status = 'malformed';
    diagnostics.push({ path: '$', message: 'file shorter than 4 bytes, cannot read any magic', byteOffset: 0 });
    return result;
  }

  const magic = data.readUInt32BE(0);
  result.magic = magic >>> 0;

  if (magic === FAT_MAGIC || magic === FAT_CIGAM || magic === FAT_MAGIC_64 || magic === FAT_CIGAM_64) {
    const little = magic === FAT_CIGAM || magic === FAT_CIGAM_64;
    const is64 = magic === FAT_MAGIC_64 || magic === FAT_CIGAM_64;
    return parseFat(data, magic, little, is64, result, diagnostics, maxSlices, maxCommands, maxBlobs);
  }
  if (magic === MH_MAGIC || magic === MH_CIGAM || magic === MH_MAGIC_64 || magic === MH_CIGAM_64) {
    result.fileKind = 'thin';
    const slice: SliceView = {
      id: 'slice/0',
      index: 0,
      cputype: 0,
      cpusubtype: 0,
      archName: 'thin',
      offset: 0,
      size: data.length,
      alignExponent: 0,
      alignBytes: 1,
      alignNormalizable: true,
      endian: 'big',
    };
    result.slices.push(slice);
    parseSlice(data, slice, result, diagnostics, maxCommands, maxBlobs);
    return result;
  }

  result.status = 'malformed';
  diagnostics.push({
    path: '$.magic',
    byteOffset: 0,
    raw: '0x' + magic.toString(16).padStart(8, '0'),
    message: 'unrecognized magic: neither fat header nor thin Mach-O',
  });
  return result;
}

function parseFat(
  buf: Buffer,
  magic: number,
  little: boolean,
  is64: boolean,
  result: ParseResult,
  diagnostics: Diagnostic[],
  maxSlices: number,
  maxCommands: number,
  maxBlobs: number,
): ParseResult {
  const e: Endian = little ? 'little' : 'big';
  result.fileKind = is64 ? 'fat64' : 'fat';
  result.endian = e;
  const readU32 = (off: number) => (little ? buf.readUInt32LE(off) : buf.readUInt32BE(off));
  const entrySize = is64 ? 32 : 20;
  const headerSize = 8;
  if (buf.length < headerSize) {
    result.status = 'malformed';
    diagnostics.push({ path: '$.fat_header', byteOffset: 0, message: 'truncated fat header' });
    return result;
  }
  const nfatArch = readU32(4) >>> 0;
  result.rawHeader = [
    { field: 'magic', raw: '0x' + (magic >>> 0).toString(16).padStart(8, '0'), note: `on-disk uint32; fat fields are ${e}-endian` },
    { field: 'nfat_arch', raw: String(nfatArch) },
  ];
  if (buf.length < headerSize + nfatArch * entrySize) {
    result.status = 'malformed';
    diagnostics.push({
      path: '$.fat_arch[]',
      byteOffset: headerSize,
      raw: nfatArch,
      message: `fat header declares ${nfatArch} arches (table needs ${headerSize + nfatArch * entrySize} bytes) but file has ${buf.length}`,
    });
    return result;
  }
  if (nfatArch > maxSlices) {
    result.status = 'budget_exhausted';
    result.budget = { limit: 'maxSlices', used: nfatArch, max: maxSlices };
    diagnostics.push({ path: '$.fat_header.nfat_arch', message: `slice budget exhausted: ${nfatArch} > ${maxSlices}` });
    return result;
  }

  for (let i = 0; i < nfatArch; i++) {
    const p = headerSize + i * entrySize;
    const cputype = readU32(p) >>> 0;
    const cpusubtype = readU32(p + 4) >>> 0;
    const offset = readU32(p + 8) >>> 0;
    const size = readU32(p + 12) >>> 0;
    const alignExponent = readU32(p + 16) >>> 0;
    let alignBytes: number | null = null;
    let normalizable = false;
    // 2^align, exact powers only: if it cannot be represented safely the raw
    // exponent stays in place with a diagnostic; no rounding correction.
    if (alignExponent <= 52) {
      alignBytes = 2 ** alignExponent;
      normalizable = true;
    } else {
      diagnostics.push({
        path: `$.fat_arch[${i}].align`,
        byteOffset: p + 16,
        raw: alignExponent,
        message: `alignment exponent ${alignExponent} overflows safe byte normalization (2^${alignExponent}); raw value retained, no rounding applied`,
      });
    }
    const slice: SliceView = {
      id: `slice/${i}`,
      index: i,
      cputype,
      cpusubtype,
      archName: archName(cputype, cpusubtype),
      offset,
      size,
      alignExponent,
      alignBytes,
      alignNormalizable: normalizable,
      endian: 'big',
    };
    result.slices.push(slice);
    const end = offset + size;
    if (offset >= buf.length || end > buf.length) {
      result.status = 'malformed';
      diagnostics.push({
        path: `$.fat_arch[${i}]`,
        byteOffset: offset,
        raw: { offset, size },
        message: `slice range [${offset}, ${end}) extends beyond file of ${buf.length} bytes`,
      });
    }
  }

  for (const slice of result.slices) {
    parseSlice(buf, slice, result, diagnostics, maxCommands, maxBlobs);
    if (result.status === 'budget_exhausted') return result;
  }
  return result;
}

function parseSlice(
  buf: Buffer,
  slice: SliceView,
  result: ParseResult,
  diagnostics: Diagnostic[],
  maxCommands: number,
  maxBlobs: number,
): void {
  const base = slice.offset;
  if (base + 32 > buf.length) {
    result.status = 'malformed';
    diagnostics.push({ path: `${slice.id}.header`, byteOffset: base, message: 'truncated mach header' });
    return;
  }
  const hm = buf.readUInt32BE(base) >>> 0;
  let little: boolean;
  let is64: boolean;
  switch (hm) {
    case MH_MAGIC:
      little = false; is64 = false; break;
    case MH_CIGAM:
      little = true; is64 = false; break;
    case MH_MAGIC_64:
      little = false; is64 = true; break;
    case MH_CIGAM_64:
      little = true; is64 = true; break;
    default:
      result.status = 'malformed';
      diagnostics.push({
        path: `${slice.id}.magic`,
        byteOffset: base,
        raw: '0x' + hm.toString(16).padStart(8, '0'),
        message: `slice ${slice.index} starts with invalid Mach-O magic`,
      });
      return;
  }
  slice.endian = little ? 'little' : 'big';
  const u32 = (off: number) => (little ? buf.readUInt32LE(off) : buf.readUInt32BE(off));
  const cputype = u32(base + 4) >>> 0;
  const cpusubtype = u32(base + 8) >>> 0;
  if (result.fileKind === 'thin') {
    slice.cputype = cputype;
    slice.cpusubtype = cpusubtype;
    slice.archName = archName(cputype, cpusubtype);
  }
  const ncmds = u32(base + 16) >>> 0;
  const sizeofcmds = u32(base + 20) >>> 0;
  const headerSize = is64 ? 32 : 28;
  let cursor = base + headerSize;
  const cmdTableEnd = Math.min(base + slice.size, buf.length);
  if (ncmds > maxCommands) {
    result.status = 'budget_exhausted';
    result.budget = { limit: 'maxCommands', used: ncmds, max: maxCommands };
    diagnostics.push({ path: `${slice.id}.header.ncmds`, message: `load command budget exhausted: ${ncmds} > ${maxCommands}` });
    return;
  }
  if (base + headerSize + sizeofcmds > cmdTableEnd) {
    diagnostics.push({
      path: `${slice.id}.header.sizeofcmds`,
      byteOffset: base + headerSize,
      raw: sizeofcmds,
      message: `declared command table ${sizeofcmds} bytes reaches ${base + headerSize + sizeofcmds}, beyond slice end ${base + slice.size}`,
    });
  }
  for (let i = 0; i < ncmds; i++) {
    if (cursor + 8 > cmdTableEnd) {
      diagnostics.push({
        path: `${slice.id}.load_commands[${i}]`,
        byteOffset: cursor,
        message: `command ${i} header truncated (need 8 bytes)`,
      });
      break;
    }
    const cmd = u32(cursor) >>> 0;
    const cmdsize = u32(cursor + 4) >>> 0;
    const endOffset = cursor + cmdsize;
    const withinSlice = cmdsize >= 8 && endOffset <= base + slice.size && endOffset <= buf.length;
    const cmdView: CommandView = {
      id: `${slice.id}/cmd/${i}`,
      sliceId: slice.id,
      index: i,
      cmd,
      cmdName: commandName(cmd),
      cmdsize,
      offset: cursor,
      endOffset,
      relOffset: cursor - base,
      withinSlice,
      detail: {},
    };
    if (cmd === LC_CODE_SIGNATURE && cmdsize >= 16) {
      const dataoff = u32(cursor + 8) >>> 0;
      const datasize = u32(cursor + 12) >>> 0;
      cmdView.detail = {
        dataoff: { value: dataoff, unit: 'byte', basis: 'slice-start' },
        datasize: { value: datasize, unit: 'byte' },
      };
      parseSignature(buf, slice, cmdView, dataoff, datasize, result, diagnostics, maxBlobs);
    }
    if (cmd === LC_SEGMENT_64 && cmdsize >= 72) {
      const segname = buf.subarray(cursor + 8, cursor + 24).toString('utf8').replace(/\0+$/g, '');
      const filesize = (little ? buf.readBigUInt64LE(cursor + 64) : buf.readBigUInt64BE(cursor + 64));
      cmdView.detail = {
        segname,
        filesize: { value: filesize.toString(), unit: 'byte', basis: 'slice-start' },
        linkedit: segname === '__LINKEDIT',
      };
    }
    result.commands.push(cmdView);
    if (!withinSlice) {
      diagnostics.push({
        path: `${slice.id}.load_commands[${i}]`,
        byteOffset: cursor,
        raw: { cmd: cmdView.cmdName, cmdsize },
        message: `load command range [${cursor}, ${endOffset}) crosses slice end ${base + slice.size}`,
      });
    }
    if (cmdsize < 8) {
      diagnostics.push({ path: `${slice.id}.load_commands[${i}]`, byteOffset: cursor + 4, raw: cmdsize, message: 'cmdsize smaller than command header (8 bytes)' });
      break;
    }
    cursor = endOffset;
  }
}

function parseSignature(
  buf: Buffer,
  slice: SliceView,
  cmd: CommandView,
  dataoff: number,
  datasize: number,
  result: ParseResult,
  diagnostics: Diagnostic[],
  maxBlobs: number,
): void {
  const base = slice.offset;
  const absOffset = base + dataoff;
  const absEnd = absOffset + datasize;
  const sig: SignatureView = {
    sliceId: slice.id,
    dataoff,
    datasize,
    absOffset,
    absEnd,
    magic: 0,
    magicName: 'none',
    supported: true,
    blobs: [],
    codeLimit: null,
    hashType: null,
    hashTypeName: 'none',
    hashSize: null,
    pageSize: null,
    coverageStart: base,
    coverageEnd: null,
    slots: [],
  };
  result.signatures.push(sig);
  if (absEnd > buf.length || absOffset < base) {
    sig.supported = false;
    diagnostics.push({
      path: `${cmd.id}.LC_CODE_SIGNATURE`,
      byteOffset: absOffset,
      raw: { dataoff, datasize },
      message: `signature range [${absOffset}, ${absEnd}) is outside file/slice`,
    });
    return;
  }
  if (datasize < 8) {
    sig.supported = false;
    diagnostics.push({ path: `${cmd.id}.LC_CODE_SIGNATURE`, byteOffset: absOffset, raw: datasize, message: 'signature blob shorter than 8 bytes' });
    return;
  }
  const magic = buf.readUInt32BE(absOffset) >>> 0;
  sig.magic = magic;
  if (magic !== CSMAGIC_EMBEDDED_SIGNATURE) {
    sig.supported = false;
    sig.magicName = `UNKNOWN(0x${magic.toString(16).padStart(8, '0')})`;
    diagnostics.push({
      path: `${cmd.id}.LC_CODE_SIGNATURE.magic`,
      byteOffset: absOffset,
      raw: '0x' + magic.toString(16).padStart(8, '0'),
      message: 'unsupported signature container format: not CSMAGIC_EMBEDDED_SIGNATURE',
    });
    return;
  }
  sig.magicName = 'CSMAGIC_EMBEDDED_SIGNATURE';
  const len = buf.readUInt32BE(absOffset + 4) >>> 0;
  const count = buf.readUInt32BE(absOffset + 8) >>> 0;
  if (count > maxBlobs) {
    result.status = 'budget_exhausted';
    result.budget = { limit: 'maxBlobs', used: count, max: maxBlobs };
    diagnostics.push({ path: `${cmd.id}.blob_index`, message: `blob budget exhausted: ${count} > ${maxBlobs}` });
    return;
  }
  if (len > datasize) {
    diagnostics.push({
      path: `${cmd.id}.LC_CODE_SIGNATURE.length`,
      byteOffset: absOffset + 4,
      raw: len,
      message: `superblob declared length ${len} exceeds datasize ${datasize}`,
    });
  }
  const indexBase = absOffset + 12;
  for (let i = 0; i < count; i++) {
    const ie = indexBase + i * 8;
    const slotType = buf.readUInt32BE(ie) >>> 0;
    const relBlob = buf.readUInt32BE(ie + 4) >>> 0;
    const boff = absOffset + relBlob;
    if (boff + 8 > absEnd) {
      diagnostics.push({ path: `${cmd.id}.blob_index[${i}]`, byteOffset: ie, raw: relBlob, message: 'blob index points past signature datasize' });
      continue;
    }
    const bmagic = buf.readUInt32BE(boff) >>> 0;
    const blen = buf.readUInt32BE(boff + 4) >>> 0;
    const supported =
      bmagic === CSMAGIC_CODEDIRECTORY || bmagic === CSMAGIC_REQUIREMENT || bmagic === CSMAGIC_REQUIREMENTS;
    const blobView: SigBlobView = {
      slotType,
      offset: boff,
      end: boff + blen,
      magic: bmagic,
      magicName:
        bmagic === CSMAGIC_CODEDIRECTORY
          ? 'CSMAGIC_CODEDIRECTORY'
          : bmagic === CSMAGIC_REQUIREMENT
            ? 'CSMAGIC_REQUIREMENT'
            : bmagic === CSMAGIC_REQUIREMENTS
              ? 'CSMAGIC_REQUIREMENTS'
              : `UNKNOWN(0x${bmagic.toString(16).padStart(8, '0')})`,
      supported,
    };
    sig.blobs.push(blobView);
    if (!supported) {
      diagnostics.push({
        path: `${cmd.id}.blob[${i}]`,
        byteOffset: boff,
        raw: '0x' + bmagic.toString(16).padStart(8, '0'),
        message: `unsupported signature blob format at slot type ${slotType}`,
      });
    }
    if (slotType === 0 && bmagic === CSMAGIC_CODEDIRECTORY) {
      parseCodeDirectory(buf, sig, boff, base, slice, cmd, diagnostics);
    }
  }
}

function parseCodeDirectory(
  buf: Buffer,
  sig: SignatureView,
  off: number,
  base: number,
  slice: SliceView,
  cmd: CommandView,
  diagnostics: Diagnostic[],
): void {
  const u32 = (p: number) => buf.readUInt32BE(p) >>> 0;
  const length = u32(off + 4);
  const hashOffset = u32(off + 20);
  const nSpecialSlots = u32(off + 28) >>> 0;
  const nCodeSlots = u32(off + 32) >>> 0;
  const codeLimit = u32(off + 36) >>> 0;
  const hashSize = buf[off + 40];
  const hashType = buf[off + 41];
  const pageSizeExp = buf[off + 43];
  sig.codeLimit = codeLimit;
  sig.hashType = hashType;
  sig.hashTypeName = hashName(hashType);
  sig.hashSize = hashSize;
  sig.pageSize = 2 ** pageSizeExp;
  sig.coverageEnd = base + codeLimit;
  if (hashType !== 1 && hashType !== 2) {
    diagnostics.push({
      path: `${cmd.id}.blob.CS_CodeDirectory.hashType`,
      byteOffset: off + 41,
      raw: hashType,
      message: `code slot hash type ${hashType} is not supported; verification cannot decide, raw value retained`,
    });
    for (let i = 0; i < nCodeSlots; i++) {
      const so = off + hashOffset + (nSpecialSlots + i) * hashSize;
      sig.slots.push({
        index: i,
        offset: so,
        length: hashSize,
        basis: 'file',
        expected: buf.subarray(so, so + hashSize).toString('hex'),
        actual: null,
        match: null,
      });
    }
    return;
  }
  const algo = hashType === 1 ? 'sha1' : 'sha256';
  const page = sig.pageSize as number;
  if (length > sig.datasize) {
    diagnostics.push({ path: `${cmd.id}.blob.CS_CodeDirectory.length`, byteOffset: off + 4, raw: length, message: 'CodeDirectory length exceeds signature datasize' });
  }
  for (let i = 0; i < nCodeSlots; i++) {
    const so = off + hashOffset + (nSpecialSlots + i) * hashSize;
    const expected = buf.subarray(so, so + hashSize).toString('hex');
    const pageStart = base + i * page;
    const pageEnd = Math.min(base + codeLimit, pageStart + page);
    const chunk = buf.subarray(pageStart, pageEnd);
    const actual = createHash(algo).update(chunk).digest('hex');
    sig.slots.push({
      index: i,
      offset: so,
      length: hashSize,
      basis: 'file',
      expected,
      actual,
      match: actual === expected,
    });
    if (actual !== expected) {
      diagnostics.push({
        path: `${cmd.id}.blob.CS_CodeDirectory.code_slot[${i}]`,
        byteOffset: i * page,
        raw: { page: i, expected: expected.slice(0, 16) + '…', actual: actual.slice(0, 16) + '…' },
        message: `code slot ${i} digest mismatch on ${algo} page [${pageStart}, ${pageEnd})`,
      });
    }
  }
  const expectedSlots = Math.ceil(codeLimit / page);
  if (nCodeSlots !== expectedSlots) {
    diagnostics.push({
      path: `${cmd.id}.blob.CS_CodeDirectory.nCodeSlots`,
      byteOffset: off + 32,
      raw: nCodeSlots,
      message: `nCodeSlots=${nCodeSlots} but codeLimit ${codeLimit} with page ${page} requires ${expectedSlots} slots`,
    });
  }
}

export function hexEvidence(buf: Buffer, offset: number, length: number): { offset: number; length: number; hex: string; ascii: string } {
  const start = Math.max(0, offset);
  const end = Math.min(buf.length, offset + length);
  const chunk = buf.subarray(start, end);
  let ascii = '';
  for (const b of chunk) ascii += b >= 32 && b < 127 ? String.fromCharCode(b) : '.';
  return { offset: start, length: chunk.length, hex: chunk.toString('hex'), ascii };
}
