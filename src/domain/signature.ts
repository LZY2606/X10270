import { sha256hex } from '../shared/id';
import { q, type Diag, type Verdict } from '../shared/types';

export interface SigView {
  present: boolean;
  dataoff?: number;
  datasize?: number;
  blobMagic?: string;
  supported?: boolean;
  codeLimit?: number;
  nCodeSlots?: number;
  pageSizeExp?: number;
  hashSize?: number;
  coverageEnd?: number;
  verdict: Verdict;
  diags: Diag[];
}

const CSMAGIC_EMBEDDED_SIGNATURE = 0xfade0cc0;
const CSMAGIC_CODEDIRECTORY = 0xfade0c02;
const CSSLOT_CODEDIRECTORY = 0;
const CS_HASHTYPE_SHA256 = 2;

/**
 * Verifies code-signature coverage of one slice.
 * Distinguishes, as separate verdict kinds:
 *  - coverage_gap       (signature does not cover the tail before the blob)
 *  - hash_mismatch      (a code slot digest differs)
 *  - unsupported_format (unknown / unsupported blob)
 */
export function verifySignature(
  slice: Buffer,
  codeSig: { dataoff: number; datasize: number } | undefined,
  sliceId: string,
): SigView {
  const diags: Diag[] = [];
  if (!codeSig) {
    return { present: false, verdict: { kind: 'not_signed' }, diags };
  }
  const { dataoff, datasize } = codeSig;
  const sigObjectId = `${sliceId}_sig`;
  if (dataoff + datasize > slice.length) {
    diags.push({
      code: 'signature_out_of_bounds',
      message: `signature blob [0x${dataoff.toString(16)}, 0x${(dataoff + datasize).toString(16)}) escapes slice size 0x${slice.length.toString(16)}`,
      objectId: sigObjectId,
      position: q(dataoff, 'byte', 'slice'),
    });
    return {
      present: true,
      dataoff,
      datasize,
      verdict: { kind: 'unsupported_format', blobMagic: 'unreadable' },
      diags,
    };
  }
  const blobMagicNum = slice.readUInt32BE(dataoff);
  const blobMagic = '0x' + blobMagicNum.toString(16).padStart(8, '0');
  if (blobMagicNum !== CSMAGIC_EMBEDDED_SIGNATURE) {
    return {
      present: true,
      dataoff,
      datasize,
      blobMagic,
      supported: false,
      verdict: { kind: 'unsupported_format', blobMagic },
      diags,
    };
  }
  const count = slice.readUInt32BE(dataoff + 8);
  let cdOffset = -1;
  for (let i = 0; i < count; i++) {
    const entryBase = dataoff + 12 + i * 8;
    if (entryBase + 8 > dataoff + datasize) break;
    if (slice.readUInt32BE(entryBase) === CSSLOT_CODEDIRECTORY) {
      cdOffset = dataoff + slice.readUInt32BE(entryBase + 4);
      break;
    }
  }
  if (cdOffset < 0 || cdOffset + 44 > dataoff + datasize) {
    return {
      present: true,
      dataoff,
      datasize,
      blobMagic,
      supported: false,
      verdict: { kind: 'unsupported_format', blobMagic: 'missing-codedirectory' },
      diags,
    };
  }
  if (slice.readUInt32BE(cdOffset) !== CSMAGIC_CODEDIRECTORY) {
    const bad = '0x' + slice.readUInt32BE(cdOffset).toString(16).padStart(8, '0');
    return {
      present: true,
      dataoff,
      datasize,
      blobMagic,
      supported: false,
      verdict: { kind: 'unsupported_format', blobMagic: bad },
      diags,
    };
  }
  const hashOffset = slice.readUInt32BE(cdOffset + 16);
  const nCodeSlots = slice.readUInt32BE(cdOffset + 28);
  const codeLimit = slice.readUInt32BE(cdOffset + 32);
  const hashSize = slice.readUInt8(cdOffset + 36);
  const hashType = slice.readUInt8(cdOffset + 37);
  const pageSizeExp = slice.readUInt8(cdOffset + 39);
  if (hashType !== CS_HASHTYPE_SHA256 || hashSize !== 32 || pageSizeExp > 32) {
    return {
      present: true,
      dataoff,
      datasize,
      blobMagic,
      supported: false,
      codeLimit,
      nCodeSlots,
      pageSizeExp,
      hashSize,
      verdict: { kind: 'unsupported_format', blobMagic: `hashType=0x${hashType.toString(16)}` },
      diags,
    };
  }
  const pageSize = 2 ** pageSizeExp;
  const coverageEnd = Math.min(nCodeSlots * pageSize, codeLimit);
  const view: Omit<SigView, 'verdict'> = {
    present: true,
    dataoff,
    datasize,
    blobMagic,
    supported: true,
    codeLimit,
    nCodeSlots,
    pageSizeExp,
    hashSize,
    coverageEnd,
    diags,
  };
  if (coverageEnd < dataoff) {
    return {
      ...view,
      verdict: {
        kind: 'coverage_gap',
        gapStart: q(coverageEnd, 'byte', 'slice'),
        gapEnd: q(dataoff, 'byte', 'slice'),
      },
    };
  }
  for (let slot = 0; slot < nCodeSlots; slot++) {
    const start = slot * pageSize;
    const end = Math.min(start + pageSize, codeLimit);
    const actual = sha256hex(slice.subarray(start, end));
    const expected = slice.subarray(cdOffset + hashOffset + slot * hashSize, cdOffset + hashOffset + (slot + 1) * hashSize).toString('hex');
    if (actual !== expected) {
      return { ...view, verdict: { kind: 'hash_mismatch', slot, expected, actual } };
    }
  }
  return { ...view, verdict: { kind: 'ok', slots: nCodeSlots } };
}
