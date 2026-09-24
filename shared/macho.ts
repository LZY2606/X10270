// Mach-O / 通用二进制解析层：只读原始字节，保留原始表示，不做任何规范化修正。
import type {
  ByteOrder, FatHeaderView, SliceView, LoadCommandView, SignatureView,
  BlobView, CoverageRegion, Quantity,
} from './types.ts';

export class ParseError extends Error {
  constructor(
    public code: 'format_corrupt' | 'unsupported_format',
    message: string,
    public offset?: number,
  ) { super(message); this.name = 'ParseError'; }
}

const q = (value: number, basis: Quantity['basis'], unit: Quantity['unit'] = 'byte'): Quantity => ({ value, unit, basis });
const raw = (buf: Uint8Array, offset: number, length: number) => ({
  hex: hexSlice(buf, offset, length), offset, length,
});

export function hexSlice(buf: Uint8Array, offset: number, length: number): string {
  const end = Math.min(offset + length, buf.length);
  const out: string[] = [];
  for (let i = Math.max(0, offset); i < end; i++) out.push(buf[i].toString(16).padStart(2, '0'));
  return out.join(' ');
}

class Reader {
  private view: DataView;
  constructor(public buf: Uint8Array, public order: ByteOrder) {
    this.view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  }
  u32(off: number): number {
    if (off < 0 || off + 4 > this.buf.length) throw new ParseError('format_corrupt', `u32 read out of range at ${off}`, off);
    return this.view.getUint32(off, this.order === 'le');
  }
}

export const CPU_NAMES: Record<number, string> = {
  7: 'x86', 0x01000007: 'x86_64', 12: 'arm', 0x0100000c: 'arm64',
  0x0100000c | 2: 'arm64', 18: 'ppc', 0x01000012: 'ppc64',
};

export const LC_NAMES: Record<number, string> = {
  0x1: 'LC_SEGMENT', 0x19: 'LC_SEGMENT_64', 0x2: 'LC_SYMTAB', 0xb: 'LC_DYSYMTAB',
  0xc: 'LC_LOAD_DYLIB', 0x1d: 'LC_CODE_SIGNATURE', 0x21: 'LC_ENCRYPTION_INFO',
  0x2c: 'LC_ENCRYPTION_INFO_64', 0x24: 'LC_VERSION_MIN_MACOSX', 0x32: 'LC_BUILD_VERSION',
  0x80000028: 'LC_MAIN', 0x26: 'LC_FUNCTION_STARTS', 0x29: 'LC_DATA_IN_CODE',
  0x1b: 'LC_UUID', 0x2a: 'LC_SOURCE_VERSION', 0x1f: 'LC_DYLD_INFO_ONLY',
};

export const BLOB_MAGICS: Record<number, string> = {
  0xfade0c00: 'CSMAGIC_REQUIREMENT', 0xfade0c01: 'CSMAGIC_REQUIREMENTS',
  0xfade0c02: 'CSMAGIC_CODEDIRECTORY', 0xfade0cc0: 'CSMAGIC_EMBEDDED_SIGNATURE',
  0xfade0cc1: 'CSMAGIC_DETACHED_SIGNATURE', 0xfade0b01: 'CSMAGIC_BLOBWRAPPER',
  0xfade7171: 'CSMAGIC_ENTITLEMENTS', 0xfade7172: 'CSMAGIC_DER_ENTITLEMENTS',
};

export const HASH_NAMES: Record<number, string> = {
  1: 'sha1', 2: 'sha256', 3: 'sha256-truncated', 4: 'sha384', 5: 'sha512',
};

export interface ParsedFat {
  header: FatHeaderView;
  slices: SliceView[];
  commands: LoadCommandView[];
  signatures: SignatureView[];
}

export interface ParseBudget {
  maxSlices: number;
  maxCommands: number;
}

export class BudgetExhausted extends Error {
  constructor(public what: string, public limit: number) { super(`budget exhausted: ${what} > ${limit}`); }
}

export function detectFatOrder(buf: Uint8Array): ByteOrder {
  if (buf.length < 4) throw new ParseError('format_corrupt', 'file too small for fat header', 0);
  if (buf[0] === 0xca && buf[1] === 0xfe && buf[2] === 0xba && buf[3] === 0xbe) return 'be';
  if (buf[0] === 0xbe && buf[1] === 0xba && buf[2] === 0xfe && buf[3] === 0xca) return 'le';
  throw new ParseError('format_corrupt', `unknown fat magic ${hexSlice(buf, 0, 4)}`, 0);
}

export function parseFat(buf: Uint8Array, idPrefix: string, budget: ParseBudget): ParsedFat {
  const order = detectFatOrder(buf);
  const r = new Reader(buf, order);
  const nfatArch = r.u32(4);
  if (nfatArch > budget.maxSlices) throw new BudgetExhausted('nfat_arch', budget.maxSlices);
  if (8 + nfatArch * 20 > buf.length) throw new ParseError('format_corrupt', 'fat_arch table extends past end of file', 8);

  const header: FatHeaderView = {
    id: `${idPrefix}/fat-header`,
    magic: raw(buf, 0, 4),
    byteOrder: order,
    nfatArch: q(nfatArch, 'none', 'count'),
  };

  const slices: SliceView[] = [];
  for (let i = 0; i < nfatArch; i++) {
    const base = 8 + i * 20;
    const cputype = r.u32(base);
    const cpusubtype = r.u32(base + 4);
    const offset = r.u32(base + 8);
    const size = r.u32(base + 12);
    const align = r.u32(base + 16);
    slices.push({
      id: `${idPrefix}/slice/${i}`,
      index: i,
      cputype: { ...raw(buf, base, 4), value: cputype },
      cpusubtype: { ...raw(buf, base + 4, 4), value: cpusubtype },
      archName: CPU_NAMES[cputype] ?? `cpu-${cputype}`,
      offset: q(offset, 'file'),
      size: q(size, 'file'),
      alignExponent: align,
      alignBytes: align < 31 ? 2 ** align : null, // 溢出则保留 null + 诊断，绝不取整修正
      rawEntry: raw(buf, base, 20),
    });
  }

  const commands: LoadCommandView[] = [];
  const signatures: SignatureView[] = [];
  for (const slice of slices) {
    const off = slice.offset.value;
    const size = slice.size.value;
    if (off + size > buf.length || off + 32 > buf.length) continue; // 越界由 verify 层裁决
    const parsed = parseSlice(buf, off, size, slice.id, idPrefix, budget);
    commands.push(...parsed.commands);
    if (parsed.signature) signatures.push(parsed.signature);
  }
  return { header, slices, commands, signatures };
}

function parseSlice(buf: Uint8Array, off: number, size: number, sliceId: string, idPrefix: string, budget: ParseBudget) {
  const commands: LoadCommandView[] = [];
  let signature: SignatureView | undefined;
  // mach_header_64 (LE) — 只支持 64 位小端 slice 头；其它魔数由 verify 层记 unsupported。
  const is64le = buf[off] === 0xcf && buf[off + 1] === 0xfa && buf[off + 2] === 0xed && buf[off + 3] === 0xfe;
  if (!is64le) return { commands, signature };
  const r = new Reader(buf, 'le');
  const ncmds = r.u32(off + 16);
  if (ncmds > budget.maxCommands) throw new BudgetExhausted('ncmds', budget.maxCommands);
  let cursor = off + 32;
  for (let i = 0; i < ncmds; i++) {
    if (cursor + 8 > buf.length) break; // 越界由 verify 层裁决
    const cmd = r.u32(cursor);
    const cmdsize = r.u32(cursor + 4);
    const cmdId = `${sliceId}/cmd/${i}`;
    commands.push({
      id: cmdId,
      sliceId,
      index: i,
      cmd,
      cmdName: LC_NAMES[cmd] ?? `LC_UNKNOWN_0x${cmd.toString(16)}`,
      cmdsize: q(cmdsize, 'none'),
      fileOffset: q(cursor, 'file'),
      sliceOffset: q(cursor - off, 'slice'),
      raw: raw(buf, cursor, Math.min(cmdsize, 32)),
    });
    if (cmd === 0x1d && cmdsize >= 16) {
      const dataoff = r.u32(cursor + 8);
      const datasize = r.u32(cursor + 12);
      signature = parseSignature(buf, off, dataoff, datasize, sliceId, cmdId);
    }
    if (cmdsize < 8) break; // 无法前进，越界裁决交给 verify
    cursor += cmdsize;
  }
  return { commands, signature };
}

function parseSignature(buf: Uint8Array, sliceOff: number, dataoff: number, datasize: number, sliceId: string, cmdId: string): SignatureView {
  const sigId = `${sliceId}/signature`;
  const base = sliceOff + dataoff;
  const blobs: BlobView[] = [];
  let superblobMagic = 'unknown';
  let codeDirectory: SignatureView['codeDirectory'];
  const coverage: CoverageRegion[] = [];

  if (base + 12 <= buf.length) {
    const r = new Reader(buf, 'be'); // 签名 blob 一律大端
    const magic = r.u32(base);
    superblobMagic = BLOB_MAGICS[magic] ?? `0x${magic.toString(16)}`;
    if (magic === 0xfade0cc0) {
      const count = r.u32(base + 8);
      for (let i = 0; i < count && base + 12 + i * 8 + 8 <= buf.length; i++) {
        const type = r.u32(base + 12 + i * 8);
        const boff = r.u32(base + 16 + i * 8);
        const abs = base + boff;
        if (abs + 8 > buf.length) continue;
        const bmagic = r.u32(abs);
        const blen = r.u32(abs + 4);
        const known = bmagic in BLOB_MAGICS;
        blobs.push({
          id: `${sigId}/blob/${i}`,
          type, magic: bmagic,
          magicName: BLOB_MAGICS[bmagic] ?? `0x${bmagic.toString(16)}`,
          known,
          offset: q(abs - sliceOff, 'slice'),
          length: q(blen, 'blob'),
        });
        if (bmagic === 0xfade0c02 && abs + 44 <= buf.length) {
          codeDirectory = parseCodeDirectory(buf, abs, blen, r);
        }
      }
    }
  }

  // 覆盖带：代码槽覆盖 [0, codeLimit)，签名 blob 覆盖 [dataoff, dataoff+datasize)，其余为缺口。
  const codeLimit = codeDirectory?.codeLimit.value ?? 0;
  const pageSize = codeDirectory ? 2 ** codeDirectory.pageSizeExponent : 4096;
  if (codeDirectory) {
    const nSlots = codeDirectory.nCodeSlots;
    for (let i = 0; i < nSlots; i++) {
      const start = i * pageSize;
      const len = Math.min(pageSize, codeLimit - start);
      coverage.push({
        id: `${sigId}/cov/slot-${i}`,
        kind: 'code-slot',
        start: q(start, 'slice'),
        length: q(len, 'slice'),
        pageIndex: i,
        hashOk: codeDirectory.slotDigests[i]?.match,
      });
    }
  }
  if (codeLimit < dataoff) {
    coverage.push({
      id: `${sigId}/cov/gap-0`,
      kind: 'gap',
      start: q(codeLimit, 'slice'),
      length: q(dataoff - codeLimit, 'slice'),
    });
  }
  coverage.push({
    id: `${sigId}/cov/sig`,
    kind: 'signature',
    start: q(dataoff, 'slice'),
    length: q(datasize, 'slice'),
  });

  return {
    id: sigId,
    sliceId,
    dataoff: q(dataoff, 'slice'),
    datasize: q(datasize, 'slice'),
    superblobMagic,
    blobs,
    codeDirectory,
    coverage,
  };
}

function parseCodeDirectory(buf: Uint8Array, abs: number, blen: number, r: Reader): NonNullable<SignatureView['codeDirectory']> {
  const hashOffset = r.u32(abs + 16);
  const nSpecialSlots = r.u32(abs + 20);
  const nCodeSlots = r.u32(abs + 24);
  const codeLimit = r.u32(abs + 28);
  const hashSize = buf[abs + 32];
  const hashType = buf[abs + 33];
  const pageSize = buf[abs + 35];
  const slotDigests = [];
  for (let i = 0; i < nCodeSlots; i++) {
    const hOff = abs + hashOffset + i * hashSize;
    if (hOff + hashSize > buf.length) break;
    slotDigests.push({
      index: i,
      expected: hexSlice(buf, hOff, hashSize).replace(/ /g, ''),
      actual: '', // 由 verify 层填充
      match: false,
    });
  }
  return {
    hashType,
    hashTypeName: HASH_NAMES[hashType] ?? `unknown-${hashType}`,
    hashSize,
    pageSizeExponent: pageSize,
    nCodeSlots,
    nSpecialSlots,
    codeLimit: q(codeLimit, 'slice'),
    slotDigests,
  };
}
