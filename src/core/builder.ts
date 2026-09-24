import { ByteWriter, concatBytes } from './binary.js';
import { sha256Bytes } from './ids.js';
import {
  CSMAGIC_CODEDIRECTORY,
  CSMAGIC_EMBEDDED_SIGNATURE,
  CSSLOT_CODEDIRECTORY,
  LC_CODE_SIGNATURE,
  LC_SEGMENT_64,
  LC_UUID,
  MH_MAGIC_64,
  MH_CIGAM_64,
} from './constants.js';
import type { BuiltArtifact, FatLayout, FatRecipe, FieldLoc, SliceLayout, SliceRecipe } from './recipe.js';

const MH_FILETYPE_EXECUTE = 2;
const MACH64_HEADER = 32;
const LC_SEGMENT_64_SIZE = 72;
const LC_CODE_SIGNATURE_SIZE = 16;
const LC_UUID_SIZE = 24;
const IDENT = new TextEncoder().encode('case-macho\0');

function pad8(n: number): number {
  return (n + 7) & ~7;
}

function deterministicPage(seed: number, page: number, size: number): Uint8Array {
  const out = new Uint8Array(size);
  let x = (seed ^ (page * 0x9e3779b9)) >>> 0;
  for (let i = 0; i < size; i++) {
    x = (x * 1664525 + 1013904223 + i) >>> 0;
    out[i] = x & 0xff;
  }
  return out;
}

interface BuiltSlice {
  bytes: Uint8Array;
  codeLimit: number;
  blobLength: number;
  blobOffsetInSlice: number;
  codeDigestLength: number;
  ncmds: number;
  sizeofcmds: number;
}

/** Build the embedded code signature (big-endian regardless of slice order). */
function buildSignature(sliceBytesCode: Uint8Array, recipe: SliceRecipe, codeLimit: number)
  : { blob: Uint8Array; blobLength: number; codeSlotOffsets: number[] } {
  const nCodeSlots = recipe.codePages;
  const digestLen = recipe.signature.hashType === 2 ? 32 : 20;
  const codeSlotOffsets: number[] = [];
  // CodeDirectory layout.
  const identOffset = 0x58;
  const headerEnd = identOffset + IDENT.length;
  const hashOffset = pad8(headerEnd);
  for (let i = 0; i < nCodeSlots; i++) codeSlotOffsets.push(hashOffset + i * digestLen);
  const cdLength = pad8(hashOffset + nCodeSlots * digestLen);
  const cd = new ByteWriter(cdLength);
  cd.fill(0, cdLength);
  cd.u32(CSMAGIC_CODEDIRECTORY, false, 0);
  cd.u32(cdLength, false, 4);
  cd.u32(0xfde0000 | 0x20100, false, 8); // version
  cd.u32(0, false, 12); // flags
  cd.u32(hashOffset, false, 16);
  cd.u32(identOffset, false, 20);
  cd.u32(0, false, 24); // nSpecialSlots
  cd.u32(nCodeSlots, false, 28);
  cd.u32(codeLimit, false, 32);
  cd.u32(digestLen, false, 36); // hashSize (u8) + hashType(u8) packed
  cd.u32((Math.log2(recipe.pageSize) & 0xff) << 24, false, 40); // pageSize at offset 39
  cd.bytes(IDENT, identOffset);
  // Code slots: sha256 of each page of the code region.
  for (let page = 0; page < nCodeSlots; page++) {
    const start = page * recipe.pageSize;
    const end = Math.min(start + recipe.pageSize, codeLimit);
    const digest = sha256(sliceBytesCode.subarray(start, end));
    if (recipe.signature.corruption.kind === 'hash-mismatch') {
      const c = recipe.signature.corruption;
      if (start <= c.containerCodeOffset && c.containerCodeOffset < end) {
        digest[0] = digest[0] ^ c.xorByte;
      }
    }
    cd.bytes(digest, codeSlotOffsets[page]);
  }
  // SuperBlob with one CodeDirectory at slot 0.
  const superLen = pad8(12 + 8 + cdLength);
  const sup = new ByteWriter(superLen);
  sup.fill(0, superLen);
  sup.u32(CSMAGIC_EMBEDDED_SIGNATURE, false, 0);
  sup.u32(superLen, false, 4);
  sup.u32(1, false, 8);
  const cdOffset = 12 + 8;
  sup.u32(CSSLOT_CODEDIRECTORY, false, 12);
  sup.u32(cdOffset, false, 16);
  sup.bytes(cd.result(), cdOffset);
  return { blob: sup.result(), blobLength: superLen, codeSlotOffsets: codeSlotOffsets.map((o) => cdOffset + o) };
}

// sha256 with sha1 fallback kept simple: case pack uses sha256.
function sha256(data: Uint8Array): Uint8Array {
  return sha256Bytes(data);
}
