// Domain parser: universal Mach-O image -> immutable FatImageMaterial.
//
// Strictness contract:
//  * Never fabricates defaults. Every truncated/illegal field is reported with
//    a position-bearing diagnostic (finding), and the offending object keeps
//    whatever raw bytes were available.
//  * Raw on-the-wire representations are preserved on every material row; the
//    derivation layer performs the only normalization.
//  * All coordinates carry an explicit basis (FAT_BYTE / SLICE_BYTE).

import {
  ByteWindow,
  CSMAGIC_EMBEDDED_SIGNATURE,
  FAT_CIGAM_BE,
  FAT_MAGIC_BE,
  MH_CIGAM_64,
  MH_MAGIC_64,
  toHex,
} from './binio';
import {
  archKey,
  archLabel,
  blobTypeName,
  digestHex,
  loadCommandName,
  shortDigest,
  stableId,
} from './identity';
import type {
  CodeSlotMaterial,
  FatHeaderMaterial,
  FatImageMaterial,
  ImageDigestMaterial,
  LinkeditMaterial,
  LoadCommandMaterial,
  RawField,
  SignatureBlobMaterial,
  SliceMaterial,
} from './types';

export const MAX_ALIGN_SHIFT = 30; // domain ceiling: 2^30 bytes
const MACH64_HEADER_SIZE = 32;
const PAGE_SIZE = 0x4000;

export interface ParseOptions {
  maxObjects?: number;
  label?: string;
}

export interface RawFinding {
  code:
    | 'FAT_BAD_MAGIC'
    | 'FAT_BYTE_ORDER_SWAP'
    | 'SLICE_ALIGN_SHIFT_OVERFLOW'
    | 'SLICE_MISALIGNED'
    | 'SLICE_OUT_OF_BOUNDS'
    | 'THIN_MAGIC_BYTE_ORDER_SWAP'
    | 'LC_OUT_OF_BOUNDS'
    | 'SIGNATURE_BLOB_OUT_OF_BOUNDS'
    | 'SLICE_OVERLAP'
    | 'SIGNATURE_UNKNOWN_BLOB_TYPE'
    | 'BUDGET_EXHAUSTED';
  message: string;
  subjectKind: 'fat_header' | 'slice' | 'load_command' | 'signature_blob' | 'image';
  subjectId: string;
  at: { basis: 'FAT_BYTE' | 'SLICE_BYTE'; sliceKey?: string; start: number; length: number };
  expectedHex?: string;
  observedHex?: string;
  affected: string[];
}

export interface ParseResult {
  image: FatImageMaterial;
  parseFindings: RawFinding[];
  objectCount: number;
  budgetExhausted: boolean;
  diagnostics: { position: string; message: string }[];
}

function rawField(
  field: string,
  value: number | string,
  unit: RawField['unit'],
  rawHex: string,
  byteOrder: 'be' | 'le',
  at: number,
  width: 8 | 16 | 32 | 64,
): RawField {
  return { field, value, unit, rawHex, byteOrder, at, width };
}

function be32Hex(v: number): string {
  return (v >>> 0).toString(16).padStart(8, '0');
}

export function parseFatImage(bytes: Uint8Array, options: ParseOptions = {}): ParseResult {
  const maxObjects = options.maxObjects ?? 4096;
  const diagnostics: { position: string; message: string }[] = [];
  const findings: RawFinding[] = [];
  let objectCount = 0;
  const budget = () => {
    objectCount += 1;
    return objectCount <= maxObjects;
  };
  if (!budget()) {
    return exhaustedResult(bytes, options.label ?? 'imported.image', 0, []);
  }

  const imageId = `img:${shortDigest(digestHex(bytes))}`;
  const win = new ByteWindow(bytes);
  const imageSha = digestHex(bytes);

  // --- FAT header -----------------------------------------------------------
  const magic = win.u32(0, 'be');
  let fatHeader: FatHeaderMaterial | null = null;
  let nfat = 0;
  let headerBytes = 8;

  if (magic === FAT_MAGIC_BE || magic === FAT_CIGAM_BE) {
    const declaredByteOrder: 'be' | 'le' = magic === FAT_MAGIC_BE ? 'be' : 'le';
    const nfatRaw = win.u32(4, declaredByteOrder);
    nfat = nfatRaw ?? 0;
    headerBytes = 8 + nfat * 20;
    objectCount += 1;
    fatHeader = {
      id: stableId('fathdr', [imageId]),
      kind: 'fat_header',
      magic: magic >>> 0,
      declaredByteOrder,
      nfatArch: nfat,
      headerBytes,
      coordinates: { basis: 'FAT_BYTE' },
      raw: [
        rawField('magic', magic >>> 0, 'MAGIC', toHex(bytes.subarray(0, 4)), 'be', 0, 32),
        rawField(
          'nfat_arch',
          nfat,
          'ORDINAL',
          toHex(bytes.subarray(4, 8)),
          declaredByteOrder,
          4,
          32,
        ),
      ],
    };
  } else {
    findings.push({
      code: 'FAT_BAD_MAGIC',
      message: `fat header magic 0x${(magic ?? 0).toString(16).padStart(8, '0')} 不是 0xcafebabe/0xbebafeca，无法定位 fat arch 表`,
      subjectKind: 'fat_header',
      subjectId: stableId('fathdr', [imageId]),
      at: { basis: 'FAT_BYTE', start: 0, length: 4 },
      expectedHex: be32Hex(FAT_MAGIC_BE),
      observedHex: toHex(bytes.subarray(0, 4)),
      affected: [stableId('fathdr', [imageId])],
    });
    diagnostics.push({ position: 'FAT_BYTE:0+4', message: 'fat magic 无法识别' });
  }

  const slices: SliceMaterial[] = [];
  const loadCommands: LoadCommandMaterial[] = [];
  const linkedit: LinkeditMaterial[] = [];
  const signatureBlobs: SignatureBlobMaterial[] = [];
  const codeSlots: CodeSlotMaterial[] = [];

  // --- fat_arch entries + thin slices --------------------------------------
  for (let i = 0; i < nfat; i++) {
    const entryAt = 8 + i * 20;
    const entryWin = new ByteWindow(bytes, entryAt, 20);
    const cpuType = entryWin.u32(0, 'be');
    const cpuSubtype = entryWin.u32(4, 'be');
    const offset = entryWin.u32(8, 'be');
    const size = entryWin.u32(12, 'be');
    const alignShift = entryWin.u32(16, 'be');

    if ([cpuType, cpuSubtype, offset, size, alignShift].some((v) => v === undefined)) {
      diagnostics.push({ position: `FAT_BYTE:${entryAt}+20`, message: `fat_arch[${i}] 被截断` });
      if (!budget()) return exhaustedResult(bytes, options.label ?? 'imported.image', objectCount, findings);
      continue;
    }

    const sliceId = stableId('slice', [imageId, i]);
    const aKey = archKey(cpuType!, cpuSubtype!);

    // Endian swap heuristic: a plausible entry interpreted LE while the FAT is BE.
    // Rounding/normalization is never used to "repair" this.
    const swappedType = swap32(cpuType!);
    const swappedOffset = swap32(offset!);
    const looksSwapped =
      swappedType in { 0x01000007: 1, 0x0100000c: 1, 0x0100000d: 1 } &&
      swappedOffset > 0 &&
      swappedOffset % PAGE_SIZE === 0 &&
      (cpuType! & 0xff000000) === 0;
    if (looksSwapped) {
      findings.push({
        code: 'FAT_BYTE_ORDER_SWAP',
        message: `fat_arch[${i}] 字段呈小端布局（按大端解析得到 cpuType=0x${cpuType!.toString(16)}），字节序与 fat header 不一致`,
        subjectKind: 'slice',
        subjectId: sliceId,
        at: { basis: 'FAT_BYTE', start: entryAt, length: 20 },
        expectedHex: be32Hex(0x0100000c),
        observedHex: be32Hex(cpuType!),
        affected: [sliceId],
      });
    }

    // Alignment shift domain ceiling (alignment overflow), no rounding fix.
    if (alignShift! > MAX_ALIGN_SHIFT) {
      findings.push({
        code: 'SLICE_ALIGN_SHIFT_OVERFLOW',
        message: `fat_arch[${i}] align=${alignShift!} 超过域上限 2^${MAX_ALIGN_SHIFT} 字节，无法表达合法对齐`,
        subjectKind: 'slice',
        subjectId: sliceId,
        at: { basis: 'FAT_BYTE', start: entryAt + 16, length: 4 },
        observedHex: be32Hex(alignShift!),
        affected: [sliceId],
      });
    } else if (!looksSwapped && offset! % Math.pow(2, alignShift!) !== 0) {
      findings.push({
        code: 'SLICE_MISALIGNED',
        message: `fat_arch[${i}] offset=${offset!} 不是 2^${alignShift!} 的整数倍；不做四舍五入修正`,
        subjectKind: 'slice',
        subjectId: sliceId,
        at: { basis: 'FAT_BYTE', start: entryAt + 8, length: 12 },
        observedHex: be32Hex(offset!),
        affected: [sliceId],
      });
    }

    // Slice extent bounds in the FAT image.
    const end = offset! + size!;
    if (offset! < headerBytes || end > bytes.length) {
      findings.push({
        code: 'SLICE_OUT_OF_BOUNDS',
        message: `fat_arch[${i}] 区间 [${offset!}, ${end}) 越过 fat 镜像边界 ${bytes.length}`,
        subjectKind: 'slice',
        subjectId: sliceId,
        at: { basis: 'FAT_BYTE', start: offset!, length: size! },
        affected: [sliceId],
      });
    }

    const sliceBytes = bytes.subarray(offset!, end > bytes.length ? bytes.length : end);
    const thinMagic = sliceBytes.length >= 4 ? read32(sliceBytes, 0, 'be') : undefined;
    let thinOrder: 'be' | 'le' | null = null;
    let thinFileType: number | null = null;
    if (thinMagic === MH_MAGIC_64) thinOrder = 'le';
    else if (thinMagic === MH_CIGAM_64) thinOrder = 'be';
    if (thinOrder) {
      const fw = new ByteWindow(sliceBytes, 0, MACH64_HEADER_SIZE);
      thinFileType = fw.u32(12, thinOrder) ?? null;
    } else if (thinMagic !== undefined) {
      findings.push({
        code: 'THIN_MAGIC_BYTE_ORDER_SWAP',
        message: `slice[${i}] 起始 magic=0x${thinMagic.toString(16).padStart(8, '0')} 与 MH_MAGIC_64/MH_CIGAM_64 均不匹配`,
        subjectKind: 'slice',
        subjectId: sliceId,
        at: { basis: 'SLICE_BYTE', sliceKey: aKey, start: 0, length: 4 },
        observedHex: thinMagic.toString(16).padStart(8, '0'),
        affected: [sliceId],
      });
    }

    if (!budget()) {
      return exhaustedResult(bytes, options.label ?? 'imported.image', objectCount, findings);
    }

    const slice: SliceMaterial = {
      id: sliceId,
      kind: 'slice',
      index: i,
      cpuType: cpuType!,
      cpuSubtype: cpuSubtype!,
      archKey: aKey,
      offset: offset!,
      size: size!,
      alignShift: alignShift!,
      coordinates: { basis: 'FAT_BYTE' },
      thinMagic: thinMagic ?? null,
      thinByteOrder: thinOrder,
      thinFileType,
      raw: [
        rawField('cputype', cpuType!, 'HEX32', entryWin.hex(0, 4), 'be', entryAt, 32),
        rawField('cpusubtype', cpuSubtype!, 'HEX32', entryWin.hex(4, 4), 'be', entryAt + 4, 32),
        rawField('offset', offset!, 'FAT_BYTE', entryWin.hex(8, 4), 'be', entryAt + 8, 32),
        rawField('size', size!, 'FILE_BYTES', entryWin.hex(12, 4), 'be', entryAt + 12, 32),
        rawField('align', alignShift!, 'ALIGN_BITS', entryWin.hex(16, 4), 'be', entryAt + 16, 32),
      ],
    };
    slices.push(slice);

    if (thinOrder && thinMagic !== undefined) {
      parseThinSlice({
        slice,
        sliceBytes,
        imageId,
        loadCommands,
        linkedit,
        signatureBlobs,
        codeSlots,
        findings,
        diagnostics,
        budget,
        budgetFail: () =>
          exhaustedResult(bytes, options.label ?? 'imported.image', objectCount, findings),
      });
    }
  }

  // --- Slice overlap (FAT_BYTE ranges must be disjoint; no merging) --------
  const ordered = [...slices].sort((a, b) => a.offset - b.offset || a.size - b.size);
  for (let i = 1; i < ordered.length; i++) {
    const prev = ordered[i - 1];
    const cur = ordered[i];
    if (cur.offset < prev.offset + prev.size) {
      findings.push({
        code: 'SLICE_OVERLAP',
        message: `slice 区间重叠：${prev.archKey}[${prev.offset},${prev.offset + prev.size}) 与 ${cur.archKey}[${cur.offset},${cur.offset + cur.size})`,
        subjectKind: 'slice',
        subjectId: cur.id,
        at: { basis: 'FAT_BYTE', start: cur.offset, length: Math.min(prev.offset + prev.size - cur.offset, cur.size) },
        affected: [prev.id, cur.id],
      });
    }
  }

  const digestMaterial: ImageDigestMaterial = {
    id: stableId('imgdigest', [imageId]),
    kind: 'image_digest',
    imageId,
    sha256: imageSha,
    byteLength: bytes.length,
    unit: 'SHA256_HEX',
    raw: [
      rawField('sha256', imageSha, 'SHA256_HEX', imageSha, 'be', 0, 8),
      rawField('byteLength', bytes.length, 'FILE_BYTES', '', 'be', 0, 64),
    ],
  };

  const image: FatImageMaterial = {
    imageId,
    sourceLabel: options.label ?? 'imported.image',
    byteLength: bytes.length,
    sha256: imageSha,
    fatHeader,
    slices: [...slices].sort((a, b) => a.index - b.index),
    loadCommands: [...loadCommands].sort((a, b) => a.sliceKey.localeCompare(b.sliceKey) || a.commandIndex - b.commandIndex),
    linkedit: [...linkedit].sort((a, b) => a.sliceKey.localeCompare(b.sliceKey)),
    signatureBlobs: [...signatureBlobs].sort((a, b) => a.sliceKey.localeCompare(b.sliceKey)),
    codeSlots: [...codeSlots].sort((a, b) => a.sliceKey.localeCompare(b.sliceKey) || a.slotIndex - b.slotIndex),
  };

  return { image, parseFindings: findings, objectCount, budgetExhausted: false, diagnostics };
}

function exhaustedResult(
  bytes: Uint8Array,
  label: string,
  objectCount: number,
  findings: RawFinding[],
): ParseResult {
  const imageId = `img:${shortDigest(digestHex(bytes))}`;
  return {
    image: {
      imageId,
      sourceLabel: label,
      byteLength: bytes.length,
      sha256: digestHex(bytes),
      fatHeader: null,
      slices: [],
      loadCommands: [],
      linkedit: [],
      signatureBlobs: [],
      codeSlots: [],
    },
    parseFindings: [
      ...findings,
      {
        code: 'BUDGET_EXHAUSTED',
        message: `资源预算耗尽：已处理 ${objectCount} 个对象`,
        subjectKind: 'image',
        subjectId: imageId,
        at: { basis: 'FAT_BYTE', start: 0, length: bytes.length },
        affected: [imageId],
      },
    ],
    objectCount,
    budgetExhausted: true,
    diagnostics: [{ position: 'ENGINE:budget', message: 'object budget exhausted' }],
  };
}

function read32(b: Uint8Array, at: number, order: 'be' | 'le'): number | undefined {
  if (at + 4 > b.length) return undefined;
  if (order === 'be') {
    return ((b[at] << 24) | (b[at + 1] << 16) | (b[at + 2] << 8) | b[at + 3]) >>> 0;
  }
  return ((b[at + 3] << 24) | (b[at + 2] << 16) | (b[at + 1] << 8) | b[at]) >>> 0;
}

function swap32(v: number): number {
  return (
    (((v >>> 0) & 0xff) << 24) |
    (((v >>> 8) & 0xff) << 16) |
    (((v >>> 16) & 0xff) << 8) |
    (((v >>> 24) & 0xff) << 0)
  ) >>> 0;
}

interface ThinParseCtx {
  slice: SliceMaterial;
  sliceBytes: Uint8Array;
  imageId: string;
  loadCommands: LoadCommandMaterial[];
  linkedit: LinkeditMaterial[];
  signatureBlobs: SignatureBlobMaterial[];
  codeSlots: CodeSlotMaterial[];
  findings: RawFinding[];
  diagnostics: { position: string; message: string }[];
  budget: () => boolean;
  budgetFail: () => ParseResult;
}

function parseThinSlice(ctx: ThinParseCtx): ParseResult | null {
  const { slice, sliceBytes, imageId, loadCommands, linkedit, signatureBlobs, codeSlots, findings, diagnostics, budget } = ctx;
  const order = slice.thinByteOrder!;
  const win = new ByteWindow(sliceBytes);
  const ncmds = win.u32(16, order);
  const sizeofcmds = win.u32(20, order);
  if (ncmds === undefined || sizeofcmds === undefined) {
    diagnostics.push({ position: `SLICE_BYTE[${slice.archKey}]:16`, message: 'mach header 截断' });
    return null;
  }

  // Load command window must stay inside declared header extent.
  let cursor = MACH64_HEADER_SIZE;
  const cmdWindowEnd = MACH64_HEADER_SIZE + sizeofcmds;
  if (cmdWindowEnd > sliceBytes.length) {
    findings.push({
      code: 'LC_OUT_OF_BOUNDS',
      message: `slice ${slice.archKey} load commands 声明跨度 ${sizeofcmds} 越过 slice 边界 ${sliceBytes.length}`,
      subjectKind: 'slice',
      subjectId: slice.id,
      at: { basis: 'SLICE_BYTE', sliceKey: slice.archKey, start: sliceBytes.length, length: 0 },
      affected: [slice.id],
    });
  }

  let codesigOffset: number | null = null;
  let codesigSize: number | null = null;

  for (let ci = 0; ci < ncmds; ci++) {
    const cmd = win.u32(cursor, order);
    const cmdsize = win.u32(cursor + 4, order);
    if (cmd === undefined || cmdsize === undefined || cmdsize < 8) {
      findings.push({
        code: 'LC_OUT_OF_BOUNDS',
        message: `slice ${slice.archKey} load_command[${ci}] @${cursor} 被截断或 cmdsize<8`,
        subjectKind: 'load_command',
        subjectId: stableId('lc', [imageId, slice.archKey, ci]),
        at: { basis: 'SLICE_BYTE', sliceKey: slice.archKey, start: cursor, length: 8 },
        affected: [stableId('lc', [imageId, slice.archKey, ci])],
      });
      break;
    }
    const end = cursor + cmdsize;
    const inHeaderWindow = end <= cmdWindowEnd;
    const inSlice = end <= sliceBytes.length;
    const id = stableId('lc', [imageId, slice.archKey, ci]);
    if (!inHeaderWindow || !inSlice || cursor > cmdWindowEnd) {
      findings.push({
        code: 'LC_OUT_OF_BOUNDS',
        message: `slice ${slice.archKey} load_command[${ci}] ${loadCommandName(cmd)} 区间 [${cursor},${end}) 越界(headerWindow=${Math.min(cmdWindowEnd, sliceBytes.length)})`,
        subjectKind: 'load_command',
        subjectId: id,
        at: { basis: 'SLICE_BYTE', sliceKey: slice.archKey, start: cursor, length: cmdsize },
        observedHex: win.hex(cursor, Math.min(cmdsize, Math.max(0, sliceBytes.length - cursor))),
        affected: [id],
      });
    }

    const payloadLen = Math.min(cmdsize, Math.max(0, sliceBytes.length - cursor));
    const material: LoadCommandMaterial = {
      id,
      kind: 'load_command',
      sliceKey: slice.archKey,
      commandIndex: ci,
      cmd,
      cmdName: loadCommandName(cmd),
      cmdsize,
      offsetInSlice: cursor,
      payloadHex: win.hex(cursor, payloadLen),
      coordinates: { basis: 'SLICE_BYTE', sliceKey: slice.archKey },
      raw: [
        rawField('cmd', cmd, 'HEX32', win.hex(cursor, 4), order, cursor, 32),
        rawField('cmdsize', cmdsize, 'FILE_BYTES', win.hex(cursor + 4, 4), order, cursor + 4, 32),
      ],
    };
    loadCommands.push(material);
    if (!budget()) return ctx.budgetFail();

    if (cmd === 0x19) {
      const segname = win.hex(cursor + 8, 16);
      const segName = decodeSegmentName(sliceBytes, cursor + 8);
      const vmaddr = win.u64(cursor + 24, order);
      const vmsize = win.u64(cursor + 32, order);
      const fileoff = win.u64(cursor + 40, order);
      const filesize = win.u64(cursor + 48, order);
      if (segName === '__LINKEDIT' && fileoff !== undefined && filesize !== undefined) {
        linkedit.push({
          id: stableId('linkedit', [imageId, slice.archKey]),
          kind: 'linkedit',
          sliceKey: slice.archKey,
          fileOffset: fileoff,
          fileSize: filesize,
          vmAddr: vmaddr ?? 0,
          vmSize: vmsize ?? 0,
          coordinates: { basis: 'SLICE_BYTE', sliceKey: slice.archKey },
          raw: [
            rawField('segname', segName, 'ENUM', segname, order, cursor + 8, 64),
            rawField('fileoff', fileoff, 'SLICE_BYTE', win.hex(cursor + 40, 8), order, cursor + 40, 64),
            rawField('filesize', filesize, 'FILE_BYTES', win.hex(cursor + 48, 8), order, cursor + 48, 64),
          ],
        });
      }
    }

    if (cmd === 0x1d && cmdsize >= 16) {
      codesigOffset = win.u32(cursor + 8, order) ?? null;
      codesigSize = win.u32(cursor + 12, order) ?? null;
    }

    if (!inHeaderWindow || !inSlice) break; // further cursor movement would be fabricated
    cursor = end;
  }

  if (codesigOffset !== null && codesigSize !== null) {
    parseCodeSignature({
      ctx,
      codesigOffset,
      codesigSize,
      signatureBlobs,
      codeSlots,
      findings,
      diagnostics,
    });
  }
  return null;
}

function decodeSegmentName(b: Uint8Array, at: number): string {
  let end = at;
  while (end < at + 16 && b[end] !== 0) end++;
  return new TextDecoder().decode(b.subarray(at, end));
}

interface SigCtx {
  ctx: ThinParseCtx;
  codesigOffset: number;
  codesigSize: number;
  signatureBlobs: SignatureBlobMaterial[];
  codeSlots: CodeSlotMaterial[];
  findings: RawFinding[];
  diagnostics: { position: string; message: string }[];
}

// Code signature structures are ALWAYS big-endian (CSMAGIC_EMBEDDED_SIGNATURE),
// independent of the thin slice byte order.
function parseCodeSignature(s: SigCtx): void {
  const { ctx, codesigOffset, codesigSize, signatureBlobs, codeSlots, findings } = s;
  const { slice, sliceBytes, imageId, budget, budgetFail } = ctx;
  const win = new ByteWindow(sliceBytes);
  const sigEnd = codesigOffset + codesigSize;

  if (codesigOffset < 0 || sigEnd > sliceBytes.length) {
    findings.push({
      code: 'SIGNATURE_BLOB_OUT_OF_BOUNDS',
      message: `slice ${slice.archKey} LC_CODE_SIGNATURE 区间 [${codesigOffset},${sigEnd}) 越过 slice 边界 ${sliceBytes.length}`,
      subjectKind: 'signature_blob',
      subjectId: stableId('sig', [imageId, slice.archKey]),
      at: { basis: 'SLICE_BYTE', sliceKey: slice.archKey, start: codesigOffset, length: codesigSize },
      affected: [stableId('sig', [imageId, slice.archKey])],
    });
    return;
  }

  const magic = win.u32(codesigOffset, 'be');
  const length = win.u32(codesigOffset + 4, 'be');
  const count = win.u32(codesigOffset + 8, 'be');
  if (magic !== CSMAGIC_EMBEDDED_SIGNATURE || length === undefined || count === undefined) {
    findings.push({
      code: 'SIGNATURE_BLOB_OUT_OF_BOUNDS',
      message: `slice ${slice.archKey} 签名 SuperBlob magic=0x${(magic ?? 0).toString(16).padStart(8, '0')} 不受支持或被截断`,
      subjectKind: 'signature_blob',
      subjectId: stableId('sig', [imageId, slice.archKey]),
      at: { basis: 'SLICE_BYTE', sliceKey: slice.archKey, start: codesigOffset, length: Math.min(12, codesigSize) },
      observedHex: win.hex(codesigOffset, Math.min(12, codesigSize)),
      affected: [stableId('sig', [imageId, slice.archKey])],
    });
    return;
  }

  const indexes: SignatureBlobMaterial['indexes'] = [];
  let codeDirectoryOffset: number | null = null;
  for (let bi = 0; bi < count; bi++) {
    const idxAt = codesigOffset + 12 + bi * 8;
    const type = win.u32(idxAt, 'be');
    const off = win.u32(idxAt + 4, 'be');
    const supported = type === 0;
    if (type !== undefined) {
      indexes.push({
        type,
        typeName: blobTypeName(type),
        offset: off ?? 0,
        supported,
      });
      if (!supported) {
        findings.push({
          code: 'SIGNATURE_UNKNOWN_BLOB_TYPE',
          message: `slice ${slice.archKey} 签名包含不支持的 blob 类型 ${blobTypeName(type)}（索引 ${bi}，偏移 ${off}）`,
          subjectKind: 'signature_blob',
          subjectId: stableId('sig', [imageId, slice.archKey]),
          at: { basis: 'SLICE_BYTE', sliceKey: slice.archKey, start: idxAt, length: 8 },
          observedHex: win.hex(idxAt, 8),
          affected: [stableId('sig', [imageId, slice.archKey])],
        });
      }
      if (type === 0 && off !== undefined) codeDirectoryOffset = codesigOffset + off;
    }
  }

  signatureBlobs.push({
    id: stableId('sig', [imageId, slice.archKey]),
    kind: 'signature_blob',
    sliceKey: slice.archKey,
    fileOffset: codesigOffset,
    blobSize: codesigSize,
    magic: magic!,
    length: length!,
    count: count!,
    indexes,
    coordinates: { basis: 'SLICE_BYTE', sliceKey: slice.archKey },
    raw: [
      rawField('magic', magic!, 'MAGIC', win.hex(codesigOffset, 4), 'be', codesigOffset, 32),
      rawField('length', length!, 'FILE_BYTES', win.hex(codesigOffset + 4, 4), 'be', codesigOffset + 4, 32),
      rawField('count', count!, 'ORDINAL', win.hex(codesigOffset + 8, 4), 'be', codesigOffset + 8, 32),
    ],
  });
  if (!budget()) {
    budgetFail();
    return;
  }

  if (codeDirectoryOffset === null) return;
  parseCodeDirectory({
    imageId,
    slice,
    sliceBytes,
    codeDirectoryOffset,
    codeSlots,
    budget,
    budgetFail,
  });
}

interface CdCtx {
  imageId: string;
  slice: SliceMaterial;
  sliceBytes: Uint8Array;
  codeDirectoryOffset: number;
  codeSlots: CodeSlotMaterial[];
  budget: () => boolean;
  budgetFail: () => ParseResult;
}

function parseCodeDirectory(c: CdCtx): void {
  const { imageId, slice, sliceBytes, codeDirectoryOffset: cdAt, codeSlots, budget, budgetFail } = c;
  const win = new ByteWindow(sliceBytes);
  // CS_CodeDirectory layout is fixed big-endian.
  const hashOffset = win.u16(cdAt + 16, 'be');
  const identOffset = win.u16(cdAt + 20, 'be');
  const nSpecialSlots = win.u16(cdAt + 24, 'be');
  const nCodeSlots = win.u16(cdAt + 28, 'be');
  const codeLimit = win.u32(cdAt + 32, 'be');
  const hashSize = win.u8(cdAt + 36);
  const hashType = win.u8(cdAt + 37);
  const pageShift = win.u8(cdAt + 39);
  const codeLimit64 = win.u32(cdAt + 56, 'be') ?? 0;
  if (
    hashType === undefined ||
    hashSize === undefined ||
    codeLimit === undefined ||
    hashOffset === undefined ||
    nCodeSlots === undefined
  ) {
    return;
  }
  const realCodeLimit = codeLimit + codeLimit64 * 0x100000000;
  const digestName = hashType === 2 && hashSize === 32 ? 'SHA256_HEX' : null;

  const hashBase = cdAt + hashOffset;
  const specialStart = hashBase;
  const codeStart = specialStart + (nSpecialSlots ?? 0) * hashSize;

  for (let slot = 0; slot < nCodeSlots; slot++) {
    const digestAt = codeStart + slot * hashSize;
    const expectedBytes = win.slice(digestAt, hashSize);
    const expectedHex = expectedBytes ? toHex(expectedBytes) : null;
    const pageLen = pageShift ? 2 ** pageShift : PAGE_SIZE;
    const pageStart = slot * pageLen;
    let pageEnd = pageStart + pageLen;
    if (pageEnd > realCodeLimit) pageEnd = realCodeLimit;
    const pageBytes = sliceBytes.subarray(pageStart, pageEnd);
    const padded = new Uint8Array(pageLen);
    padded.set(pageBytes);
    const observedHex = digestName ? digestHex(padded) : null;

    codeSlots.push({
      id: stableId('slot', [imageId, slice.archKey, slot]),
      kind: 'code_slot',
      sliceKey: slice.archKey,
      slotIndex: slot,
      special: false,
      codeOffset: pageStart,
      codeLength: pageEnd - pageStart,
      expectedDigest: expectedHex,
      observedDigest: observedHex,
      digestUnit: 'SHA256_HEX',
      coordinates: { basis: 'SLICE_BYTE', sliceKey: slice.archKey },
      raw: [
        rawField(
          'cd_digest',
          expectedHex ?? 'UNCONVERTIBLE',
          digestName ?? 'UNSUPPORTED_HASHTYPE',
          expectedHex ?? '',
          'be',
          digestAt,
          32 * 8,
        ),
        rawField('page_start', pageStart, 'SLICE_BYTE', '', 'be', pageStart, 32),
      ],
    });
    if (!budget()) {
      budgetFail();
      return;
    }
  }

}
