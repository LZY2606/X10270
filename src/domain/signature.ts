import { createHash } from 'node:crypto';
import { Reader, CorruptError, toHex } from './binary.js';
import type { ByteRange, Diagnostic, ResultKind } from './units.js';
import { byteRange } from './units.js';

export const CSMAGIC_EMBEDDED_SIGNATURE = 0xfade0cc0;
export const CSMAGIC_CODEDIRECTORY = 0xfade0c02;
export const CSMAGIC_REQUIREMENT = 0xfade0c01;
export const CSMAGIC_REQUIREMENTS = 0xfade0c00;
export const CSMAGIC_BLOBWRAPPER = 0xfade0b01;
export const CSMAGIC_ENTITLEMENTS = 0xfade7171;
export const CSMAGIC_DER_ENTITLEMENTS = 0xfade7172;

export const KNOWN_BLOB_MAGICS: Record<number, string> = {
  [CSMAGIC_EMBEDDED_SIGNATURE]: 'CSMAGIC_EMBEDDED_SIGNATURE',
  [CSMAGIC_CODEDIRECTORY]: 'CSMAGIC_CODEDIRECTORY',
  [CSMAGIC_REQUIREMENT]: 'CSMAGIC_REQUIREMENT',
  [CSMAGIC_REQUIREMENTS]: 'CSMAGIC_REQUIREMENTS',
  [CSMAGIC_BLOBWRAPPER]: 'CSMAGIC_BLOBWRAPPER',
  [CSMAGIC_ENTITLEMENTS]: 'CSMAGIC_ENTITLEMENTS',
  [CSMAGIC_DER_ENTITLEMENTS]: 'CSMAGIC_DER_ENTITLEMENTS',
};

export const CSSLOT_NAMES: Record<number, string> = {
  0: 'CSSLOT_CODEDIRECTORY',
  1: 'CSSLOT_INFOSLOT',
  2: 'CSSLOT_REQUIREMENTS',
  3: 'CSSLOT_RESOURCEDIR',
  4: 'CSSLOT_APPLICATION',
  5: 'CSSLOT_ENTITLEMENTS',
  7: 'CSSLOT_DER_ENTITLEMENTS',
  0x10000: 'CSSLOT_SIGNATURESLOT',
};

export const HASH_TYPES: Record<number, { name: string; size: number; node: string }> = {
  1: { name: 'sha1', size: 20, node: 'sha1' },
  2: { name: 'sha256', size: 32, node: 'sha256' },
};

export interface BlobIndexEntry {
  type: number;
  typeName: string;
  offset: number; // blob-offset
  magic: number | null;
  magicName: string;
  known: boolean;
  rawMagicHex: string;
}

export interface CodeSlot {
  index: number;
  pageRange: ByteRange; // slice-offset
  expectedHex: string;
  actualHex: string | null;
  match: boolean;
}

export interface SignatureVerification {
  kind: ResultKind;
  /** ok | coverage_gap | hash_mismatch | unsupported_format —— 四种结果明确区分 */
  outcome: 'ok' | 'coverage_gap' | 'hash_mismatch' | 'unsupported_format';
  superblob: {
    magic: RawMagic;
    length: number;
    count: number;
    entries: BlobIndexEntry[];
  } | null;
  codeDirectory: {
    hashType: number;
    hashTypeName: string;
    hashSize: number;
    pageShift: number;
    nCodeSlots: number;
    codeLimit: number;
    supported: boolean;
    unsupportedReason?: string;
  } | null;
  signatureRange: ByteRange | null; // slice-offset
  uncoveredRanges: ByteRange[]; // slice-offset，签名未覆盖的区域（含尾部）
  codeSlots: CodeSlot[];
  diagnostics: Diagnostic[];
}

interface RawMagic {
  rawHex: string;
  value: number | null;
  name: string;
}

const hashBytes = (algo: string, data: Uint8Array): string =>
  createHash(algo).update(data).digest('hex');

/**
 * 校验单个 slice 的代码签名：
 * - 覆盖缺口（coverage_gap）：[0, sliceSize) 内既不在 [0, codeLimit) 也不在签名 blob 内的字节
 * - hash 不匹配（hash_mismatch）：任一 code slot 的页摘要与目录记录不符
 * - 不支持格式（unsupported_format）：未知 superblob/blob magic 或未知 hash 类型
 */
export function verifySignature(
  sliceBytes: Uint8Array,
  sigDataOff: number,
  sigDataSize: number,
  budget: { maxSlots: number } = { maxSlots: 65536 },
): SignatureVerification {
  const diagnostics: Diagnostic[] = [];
  const base: SignatureVerification = {
    kind: 'ok',
    outcome: 'ok',
    superblob: null,
    codeDirectory: null,
    signatureRange: null,
    uncoveredRanges: [],
    codeSlots: [],
    diagnostics,
  };

  const sliceSize = sliceBytes.length;
  if (sigDataOff < 0 || sigDataSize < 0 || sigDataOff + sigDataSize > sliceSize) {
    diagnostics.push({
      code: 'codesig.range.out-of-bounds',
      message: `signature range [${sigDataOff}, ${sigDataOff + sigDataSize}) exceeds slice size ${sliceSize}`,
      range: byteRange(sigDataOff, Math.min(sigDataOff + sigDataSize, sliceSize), 'slice-offset'),
    });
    base.kind = 'format_corrupt';
    base.outcome = 'unsupported_format';
    return base;
  }
  base.signatureRange = byteRange(sigDataOff, sigDataOff + sigDataSize, 'slice-offset');

  const r = new Reader(sliceBytes, 'slice-offset');
  try {
    const magicVal = r.u32(sigDataOff, 'big');
    const rawMagicHex = toHex(sliceBytes, sigDataOff, 4);
    const magicName = KNOWN_BLOB_MAGICS[magicVal] ?? `UNKNOWN(0x${magicVal.toString(16)})`;
    if (magicVal !== CSMAGIC_EMBEDDED_SIGNATURE) {
      base.superblob = {
        magic: { rawHex: rawMagicHex, value: magicVal, name: magicName },
        length: 0,
        count: 0,
        entries: [],
      };
      diagnostics.push({
        code: 'codesig.blob.unsupported',
        message: `blob magic ${magicName} is not a supported embedded signature superblob`,
        range: byteRange(sigDataOff, sigDataOff + 4, 'slice-offset'),
        rawHex: rawMagicHex,
      });
      base.outcome = 'unsupported_format';
      return base;
    }
    const length = r.u32(sigDataOff + 4, 'big');
    const count = r.u32(sigDataOff + 8, 'big');
    if (count > 256) {
      diagnostics.push({
        code: 'budget.slots',
        message: `superblob index count ${count} exceeds budget`,
        range: byteRange(sigDataOff + 8, sigDataOff + 12, 'slice-offset'),
      });
      base.kind = 'budget_exhausted';
      return base;
    }
    const entries: BlobIndexEntry[] = [];
    for (let i = 0; i < count; i++) {
      const at = sigDataOff + 12 + i * 8;
      const type = r.u32(at, 'big');
      const offset = r.u32(at + 4, 'big');
      const blobAt = sigDataOff + offset;
      let magic: number | null = null;
      let rawHex = '';
      if (blobAt + 4 <= sigDataOff + sigDataSize && blobAt + 4 <= sliceSize) {
        magic = r.u32(blobAt, 'big');
        rawHex = toHex(sliceBytes, blobAt, 4);
      }
      const magicName2 = magic === null ? 'unreadable' : (KNOWN_BLOB_MAGICS[magic] ?? `UNKNOWN(0x${magic.toString(16)})`);
      entries.push({
        type,
        typeName: CSSLOT_NAMES[type] ?? `UNKNOWN_SLOT(0x${type.toString(16)})`,
        offset,
        magic,
        magicName: magicName2,
        known: magic !== null && magic in KNOWN_BLOB_MAGICS,
        rawMagicHex: rawHex,
      });
    }
    base.superblob = {
      magic: { rawHex: rawMagicHex, value: magicVal, name: magicName },
      length,
      count,
      entries,
    };

    const unknown = entries.filter((e) => !e.known);
    if (unknown.length > 0) {
      for (const u of unknown) {
        diagnostics.push({
          code: 'codesig.blob.unknown',
          message: `slot ${u.typeName} references unsupported blob magic ${u.magicName}`,
          range: byteRange(sigDataOff + u.offset, sigDataOff + u.offset + 4, 'slice-offset'),
          rawHex: u.rawMagicHex,
        });
      }
      base.outcome = 'unsupported_format';
      return base;
    }

    const cdEntry = entries.find((e) => e.type === 0);
    if (!cdEntry || cdEntry.magic !== CSMAGIC_CODEDIRECTORY) {
      diagnostics.push({
        code: 'codesig.codedirectory.missing',
        message: 'no CodeDirectory blob in superblob index',
      });
      base.outcome = 'unsupported_format';
      return base;
    }

    const cdAt = sigDataOff + cdEntry.offset;
    const hashOffset = r.u32(cdAt + 16, 'big');
    const nSpecialSlots = r.u32(cdAt + 24, 'big');
    const nCodeSlots = r.u32(cdAt + 28, 'big');
    const codeLimit = r.u32(cdAt + 32, 'big');
    const hashSize = r.u8(cdAt + 36);
    const hashType = r.u8(cdAt + 37);
    const pageShift = r.u8(cdAt + 39);

    const hashSpec = HASH_TYPES[hashType];
    const supported = !!hashSpec && hashSpec.size === hashSize;
    base.codeDirectory = {
      hashType,
      hashTypeName: hashSpec?.name ?? `unknown(${hashType})`,
      hashSize,
      pageShift,
      nCodeSlots,
      codeLimit,
      supported,
      unsupportedReason: supported
        ? undefined
        : !hashSpec
          ? `hash type ${hashType} is not supported`
          : `hashSize ${hashSize} does not match ${hashSpec.name} (${hashSpec.size})`,
    };
    if (!supported) {
      diagnostics.push({
        code: 'codesig.hash.unsupported',
        message: base.codeDirectory.unsupportedReason!,
        range: byteRange(cdAt + 36, cdAt + 40, 'slice-offset'),
      });
      base.outcome = 'unsupported_format';
      return base;
    }
    if (nCodeSlots > budget.maxSlots) {
      diagnostics.push({
        code: 'budget.slots',
        message: `nCodeSlots=${nCodeSlots} exceeds budget maxSlots=${budget.maxSlots}`,
        range: byteRange(cdAt + 28, cdAt + 32, 'slice-offset'),
      });
      base.kind = 'budget_exhausted';
      return base;
    }

    // 覆盖缺口：补集([0, codeLimit) ∪ [sigDataOff, sigDataOff+sigDataSize)) within [0, sliceSize)
    const covered: Array<[number, number]> = [
      [0, Math.min(codeLimit, sliceSize)],
      [sigDataOff, sigDataOff + sigDataSize],
    ].sort((a, b) => a[0] - b[0]);
    let cursor = 0;
    for (const [s, e] of covered) {
      if (s > cursor) base.uncoveredRanges.push(byteRange(cursor, s, 'slice-offset'));
      cursor = Math.max(cursor, e);
    }
    if (cursor < sliceSize) base.uncoveredRanges.push(byteRange(cursor, sliceSize, 'slice-offset'));

    // code slot 摘要核验
    const pageSize = 1 << pageShift;
    const slots: CodeSlot[] = [];
    let anyMismatch = false;
    for (let i = 0; i < nCodeSlots; i++) {
      const pageStart = i * pageSize;
      const pageEnd = Math.min(pageStart + pageSize, codeLimit);
      const expectedAt = cdAt + hashOffset + i * hashSize;
      const expectedHex =
        expectedAt + hashSize <= sliceSize ? toHex(sliceBytes, expectedAt, hashSize) : '';
      const actualHex =
        pageStart < pageEnd ? hashBytes(hashSpec!.node, sliceBytes.subarray(pageStart, pageEnd)) : null;
      const match = actualHex !== null && expectedHex === actualHex;
      if (!match) anyMismatch = true;
      slots.push({
        index: i,
        pageRange: byteRange(pageStart, pageEnd, 'slice-offset'),
        expectedHex,
        actualHex,
        match,
      });
    }
    base.codeSlots = slots;

    if (base.uncoveredRanges.length > 0) {
      base.outcome = 'coverage_gap';
      for (const gap of base.uncoveredRanges) {
        diagnostics.push({
          code: 'codesig.coverage.gap',
          message: `bytes [${gap.start.value}, ${gap.end.value}) are covered neither by code slots nor by the signature blob`,
          range: gap,
        });
      }
    } else if (anyMismatch) {
      base.outcome = 'hash_mismatch';
      const bad = slots.find((s) => !s.match)!;
      diagnostics.push({
        code: 'codesig.hash.mismatch',
        message: `code slot ${bad.index}: expected ${bad.expectedHex}, computed ${bad.actualHex}`,
        range: bad.pageRange,
      });
    }
    return base;
  } catch (err) {
    if (err instanceof CorruptError) {
      diagnostics.push(new Reader(sliceBytes, 'slice-offset').diagnostic(err));
      base.kind = 'format_corrupt';
      base.outcome = 'unsupported_format';
      return base;
    }
    throw err;
  }
}
