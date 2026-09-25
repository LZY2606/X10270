// Mach-O / universal binary parsing primitives.
// Every domain quantity keeps its raw representation, unit and coordinate base.
// Normalization happens here (derived layer); unconvertible values stay in place
// with a diagnostic attached instead of being silently dropped.

export type Endian = 'big' | 'little';

export interface Diagnostic {
  code: string;
  message: string;
  offset?: number; // container coordinate, unit: byte
  length?: number; // unit: byte
  sliceIndex?: number;
}

export interface Quantity {
  raw: string; // original representation as imported
  unit: 'byte';
  coord: 'container' | 'slice';
  value: number | null; // normalized value; null when unconvertible
  diagnostic?: string;
}

export function quantity(raw: string, coord: Quantity['coord'], value: number | null, diagnostic?: string): Quantity {
  return { raw, unit: 'byte', coord, value, diagnostic };
}

export function normalizeQuantity(raw: string): { value: number | null; diagnostic?: string } {
  const t = raw.trim();
  let v: number;
  if (/^0x[0-9a-fA-F]+$/.test(t)) v = parseInt(t, 16);
  else if (/^[0-9]+$/.test(t)) v = parseInt(t, 10);
  else return { value: null, diagnostic: `cannot normalize quantity "${raw}" to bytes; left in place` };
  if (!Number.isSafeInteger(v)) return { value: null, diagnostic: `quantity "${raw}" exceeds safe integer range; left in place` };
  return { value: v };
}

export const FAT_MAGICS: Record<number, { endian: Endian; is64: boolean }> = {
  0xcafebabe: { endian: 'big', is64: false },
  0xbebafeca: { endian: 'little', is64: false },
  0xcafebabf: { endian: 'big', is64: true },
  0xbfbafeca: { endian: 'little', is64: true },
};

export const CPU_TYPE_NAMES: Record<number, string> = {
  7: 'x86',
  12: 'arm',
  18: 'powerpc',
  0x01000007: 'x86_64',
  0x0100000c: 'arm64',
  0x01000012: 'powerpc64',
};

export function archName(cputype: number): string {
  return CPU_TYPE_NAMES[cputype >>> 0] ?? `cpu_0x${(cputype >>> 0).toString(16)}`;
}

export const LOAD_COMMAND_NAMES: Record<number, string> = {
  0x1: 'LC_SEGMENT',
  0x2: 'LC_SYMTAB',
  0xb: 'LC_DYSYMTAB',
  0xc: 'LC_LOAD_DYLINKER',
  0xe: 'LC_LOAD_DYLIB',
  0x19: 'LC_SEGMENT_64',
  0x1b: 'LC_UUID',
  0x1d: 'LC_CODE_SIGNATURE',
  0x21: 'LC_ENCRYPTION_INFO',
  0x24: 'LC_VERSION_MIN_MACOSX',
  0x26: 'LC_FUNCTION_STARTS',
  0x29: 'LC_DATA_IN_CODE',
  0x2c: 'LC_ENCRYPTION_INFO_64',
  0x32: 'LC_BUILD_VERSION',
};

export function loadCommandName(cmd: number): string {
  return LOAD_COMMAND_NAMES[cmd] ?? `cmd_0x${cmd.toString(16)}`;
}

export const CS_BLOB_MAGICS: Record<number, string> = {
  0xfade0c01: 'CSMAGIC_REQUIREMENTS',
  0xfade0c02: 'CSMAGIC_CODEDIRECTORY',
  0xfade0b01: 'CSMAGIC_CMS_SIGNATURE',
  0xfade7171: 'CSMAGIC_ENTITLEMENTS',
  0xfade0cc0: 'CSMAGIC_EMBEDDED_SIGNATURE',
};

export class Reader {
  private view: DataView;
  constructor(
    public buf: Uint8Array,
    public endian: Endian,
  ) {
    this.view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  }
  u16(off: number): number {
    return this.view.getUint16(off, this.endian === 'little');
  }
  u32(off: number): number {
    return this.view.getUint32(off, this.endian === 'little');
  }
  u64(off: number): number {
    const hi = this.u32(off);
    const lo = this.u32(off + 4);
    return this.endian === 'little' ? lo * 2 ** 32 + hi : hi * 2 ** 32 + lo;
  }
  has(off: number, len: number): boolean {
    return off >= 0 && off + len <= this.buf.length;
  }
}

export interface FatArchEntry {
  index: number;
  cputype: number;
  cpusubtype: number;
  offset: number; // bytes, container coord
  size: number; // bytes
  alignExp: number; // alignment = 2^alignExp bytes
  is64: boolean;
}

export interface FatParseOk {
  ok: true;
  endian: Endian;
  is64: boolean;
  magicHex: string;
  nfatArch: number;
  entries: FatArchEntry[];
  diagnostics: Diagnostic[];
}

export interface ParseCorrupt {
  ok: false;
  diagnostics: Diagnostic[];
}

export function parseFat(buf: Uint8Array): FatParseOk | ParseCorrupt {
  if (buf.length < 8) {
    return { ok: false, diagnostics: [{ code: 'truncated_header', message: 'file smaller than fat header (8 bytes)', offset: 0, length: buf.length }] };
  }
  const magicBE = new Reader(buf, 'big').u32(0);
  const spec = FAT_MAGICS[magicBE];
  if (!spec) {
    return {
      ok: false,
      diagnostics: [{ code: 'bad_magic', message: `unrecognized fat magic 0x${magicBE.toString(16).padStart(8, '0')}`, offset: 0, length: 4 }],
    };
  }
  const r = new Reader(buf, spec.endian);
  const nfatArch = r.u32(4);
  const entrySize = spec.is64 ? 32 : 20;
  const entries: FatArchEntry[] = [];
  const diagnostics: Diagnostic[] = [];
  for (let i = 0; i < nfatArch; i++) {
    const off = 8 + i * entrySize;
    if (!r.has(off, entrySize)) {
      diagnostics.push({ code: 'truncated_arch_entry', message: `fat arch entry ${i} extends past end of file`, offset: off, length: entrySize });
      break;
    }
    entries.push({
      index: i,
      cputype: r.u32(off),
      cpusubtype: r.u32(off + 4),
      offset: spec.is64 ? r.u64(off + 8) : r.u32(off + 8),
      size: spec.is64 ? r.u64(off + 16) : r.u32(off + 12),
      alignExp: r.u32(off + (spec.is64 ? 24 : 16)),
      is64: spec.is64,
    });
  }
  return {
    ok: true,
    endian: spec.endian,
    is64: spec.is64,
    magicHex: `0x${magicBE.toString(16).padStart(8, '0')}`,
    nfatArch,
    entries,
    diagnostics,
  };
}

export interface MachOHeader {
  endian: Endian;
  is64: boolean;
  magicHex: string;
  cputype: number;
  cpusubtype: number;
  filetype: number;
  ncmds: number;
  sizeofcmds: number;
  flags: number;
  headerSize: number; // bytes
}

export function parseMachOHeader(buf: Uint8Array): { ok: true; header: MachOHeader } | ParseCorrupt {
  if (buf.length < 28) {
    return { ok: false, diagnostics: [{ code: 'truncated_macho', message: 'slice smaller than mach-o header (28 bytes)', offset: 0, length: buf.length }] };
  }
  const magicBE = new Reader(buf, 'big').u32(0);
  let endian: Endian;
  let is64: boolean;
  if (magicBE === 0xfeedface) { endian = 'big'; is64 = false; }
  else if (magicBE === 0xcefaedfe) { endian = 'little'; is64 = false; }
  else if (magicBE === 0xfeedfacf) { endian = 'big'; is64 = true; }
  else if (magicBE === 0xcffaedfe) { endian = 'little'; is64 = true; }
  else {
    return { ok: false, diagnostics: [{ code: 'bad_macho_magic', message: `unrecognized mach-o magic 0x${magicBE.toString(16).padStart(8, '0')}`, offset: 0, length: 4 }] };
  }
  const r = new Reader(buf, endian);
  const headerSize = is64 ? 32 : 28;
  if (!r.has(0, headerSize)) {
    return { ok: false, diagnostics: [{ code: 'truncated_macho', message: 'slice smaller than 64-bit mach-o header (32 bytes)', offset: 0, length: buf.length }] };
  }
  return {
    ok: true,
    header: {
      endian,
      is64,
      magicHex: `0x${magicBE.toString(16).padStart(8, '0')}`,
      cputype: r.u32(4),
      cpusubtype: r.u32(8),
      filetype: r.u32(12),
      ncmds: r.u32(16),
      sizeofcmds: r.u32(20),
      flags: r.u32(24),
      headerSize,
    },
  };
}

export interface CodeDirectoryInfo {
  hashType: number;
  hashTypeName: string;
  hashSize: number; // bytes per slot
  pageSizeLog2: number;
  nCodeSlots: number;
  codeLimit: number; // bytes, slice coord
  hashOffset: number; // bytes, relative to CodeDirectory start
  knownHash: boolean;
}

export function parseCodeDirectory(buf: Uint8Array): { ok: true; cd: CodeDirectoryInfo } | ParseCorrupt {
  // CodeDirectory blobs are always big-endian.
  if (buf.length < 44) {
    return { ok: false, diagnostics: [{ code: 'truncated_codedirectory', message: 'CodeDirectory blob smaller than 44-byte header', offset: 0, length: buf.length }] };
  }
  const r = new Reader(buf, 'big');
  const hashType = buf[9];
  const hashNames: Record<number, string> = { 1: 'sha1', 2: 'sha256', 3: 'sha256-truncated', 4: 'sha384', 5: 'sha512' };
  const hashSizes: Record<number, number> = { 1: 20, 2: 32, 3: 20, 4: 48, 5: 64 };
  const knownHash = hashType in hashNames;
  return {
    ok: true,
    cd: {
      hashType,
      hashTypeName: hashNames[hashType] ?? `unknown_${hashType}`,
      hashSize: buf[8] || hashSizes[hashType] || 0,
      pageSizeLog2: buf[11],
      nCodeSlots: r.u32(28),
      codeLimit: r.u32(32),
      hashOffset: r.u32(16),
      knownHash,
    },
  };
}
