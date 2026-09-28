import { DataReader } from './reader.js';
import {
  MH_MAGIC, MH_MAGIC_64, MH_CIGAM, MH_CIGAM_64,
  LC_SEGMENT, LC_SEGMENT_64, LC_CODE_SIGNATURE,
  loadCommandName, archName,
  CSMAGIC_EMBEDDED_SIGNATURE, CSMAGIC_DETACHED_SIGNATURE,
  CSMAGIC_CODEDIRECTORY, CSMAGIC_REQUIREMENTS, CSMAGIC_ENTITLEMENTS,
  CSMAGIC_BLOBWRAPPER,
  hashTypeName, blobTypeName, isKnownBlobType,
  CS_HASHTYPE_SHA256,
} from './constants.js';
import { sha256Digest, sha256Hex } from './digest.js';
import type {
  CodeDirectoryView, CodeSlotView, CoverageBand, LinkEditInfo,
  LoadCommandView, MachHeaderView, SignatureBlobView, SliceView,
  DomainValue,
} from '../../shared/types.js';
import { bytes, cid, count, dv, flagNum } from '../domain.js';

export interface SliceParseInput {
  sliceId: string;
  index: number;
  containerStart: number; // fat-container coordinate
  data: Uint8Array;       // slice bytes only
  pageSize: number;
  maxLoadCommands: number;
}

export class SliceFatal extends Error {
  constructor(readonly code: 'format-corrupt' | 'budget-exhausted' | 'command-out-of-bounds',
              message: string, readonly localOffset: number) {
    super(message);
  }
}

function readHeader(r: DataReader): { header: MachHeaderView; is64: boolean } {
  const magic = r.u32(0) >>> 0;
  const is64 = magic === MH_MAGIC_64 || magic === MH_CIGAM_64;
  const le = r.littleEndian;
  if (![MH_MAGIC, MH_CIGAM, MH_MAGIC_64, MH_CIGAM_64].includes(magic)) {
    throw new SliceFatal('format-corrupt', `bad Mach-O magic 0x${magic.toString(16)}`, 0);
  }
  const hdrSize = is64 ? 32 : 28;
  const header: MachHeaderView = {
    magic: dv(`0x${magic.toString(16)}`, magic, 'magic-word', 'slice-local'),
    is64,
    byteOrder: le ? 'le' : 'be',
    cpuType: flagNum(r.u32(4)),
    cpuSubtype: flagNum(r.u32(8)),
    fileType: dv(`0x${(r.u32(12) >>> 0).toString(16)}`, r.u32(12) >>> 0, 'file-type', 'slice-local'),
    ncmds: count(r.u32(16), 'load-command'),
    sizeofcmds: bytes(r.u32(20)),
    flags: flagNum(r.u32(24)),
    reserved: is64 ? flagNum(r.u32(28)) : undefined,
    headerSize: bytes(hdrSize),
  };
  return { header, is64 };
}

function readLoadCommands(r: DataReader, header: MachHeaderView, maxCmds: number): {
  commands: LoadCommandView[]; linkedit: LinkEditInfo;
} {
  const ncmds = header.ncmds.value!;
  const sizeofcmds = header.sizeofcmds.value!;
  if (ncmds > maxCmds) {
    throw new SliceFatal('budget-exhausted',
      `ncmds=${ncmds} exceeds load-command budget ${maxCmds}`, 0);
  }
  const start = header.headerSize.value!;
  const end = start + sizeofcmds;
  // command region itself must be inside the slice
  if (!r.covers(start, sizeofcmds)) {
    throw new SliceFatal('command-out-of-bounds',
      `load command region [0x${start.toString(16)},0x${end.toString(16)}) exceeds slice end 0x${r.length.toString(16)}`, start);
  }

  const commands: LoadCommandView[] = [];
  const linkedit: LinkEditInfo = { dataOffset: null, dataSize: null };
  let cursor = start;
  for (let i = 0; i < ncmds; i++) {
    if (cursor + 8 > end) {
      throw new SliceFatal('command-out-of-bounds',
        `command #${i} header overruns declared command region at 0x${cursor.toString(16)}`, cursor);
    }
    const cmd = r.u32(cursor) >>> 0;
    const cmdsize = r.u32(cursor + 4);
    if (cmdsize < 8 || cursor + cmdsize > end) {
      throw new SliceFatal('command-out-of-bounds',
        `command #${i} (${loadCommandName(cmd)}) cmdsize=${cmdsize} leaves region at 0x${cursor.toString(16)}`, cursor);
    }
    const payload: Record<string, DomainValue> = {};
    let segName = '';
    if (cmd === LC_SEGMENT_64 && cmdsize >= 72) {
      const nameBytes = r.slice(cursor + 8, 16);
      segName = Buffer.from(nameBytes).toString('utf8').replace(/\0+$/g, '');
      payload.vmaddr = dv(`0x${r.u64(cursor + 24).toString(16)}`, Number(r.u64(cursor + 24)), 'vm-byte', 'slice-local');
      payload.vmsize = bytes(Number(r.u64(cursor + 32)));
      payload.fileoff = bytes(Number(r.u64(cursor + 40)));
      payload.filesize = bytes(Number(r.u64(cursor + 48)));
    } else if (cmd === LC_SEGMENT && cmdsize >= 56) {
      segName = Buffer.from(r.slice(cursor + 8, 16)).toString('utf8').replace(/\0+$/g, '');
      payload.fileoff = bytes(r.u32(cursor + 32));
      payload.filesize = bytes(r.u32(cursor + 36));
    } else if (cmd === LC_CODE_SIGNATURE && cmdsize >= 16) {
      const dataoff = r.u32(cursor + 8);
      const datasize = r.u32(cursor + 12);
      payload.dataoff = bytes(dataoff);
      payload.datasize = bytes(datasize);
      linkedit.dataOffset = bytes(dataoff);
      linkedit.dataSize = bytes(datasize);
    }
    const view: LoadCommandView = {
      id: cid('lc', [cursor, cmd, cmdsize]),
      index: i,
      cmd: flagNum(cmd),
      cmdName: segName ? `${loadCommandName(cmd)}(${segName})` : loadCommandName(cmd),
      cmdsize: bytes(cmdsize),
      range: { start: bytes(cursor), end: bytes(cursor + cmdsize) },
      recognized: [LC_SEGMENT, LC_SEGMENT_64, LC_CODE_SIGNATURE].includes(cmd),
      payload,
    };
    if (segName === '__LINKEDIT' && (cmd === LC_SEGMENT_64 || cmd === LC_SEGMENT)) {
      linkedit.linkeditSegment = view;
    }
    if (cmd === LC_CODE_SIGNATURE) linkedit.codeSignatureCommand = view;
    commands.push(view);
    cursor += cmdsize;
  }
  return { commands, linkedit };
}

interface SuperBlobResult {
  blobs: SignatureBlobView[];
  codeDirectory?: CodeDirectoryView;
  bands: CoverageBand[];
  signatureRange: { start: number; end: number } | null;
}

function knownMagic(magic: number): boolean {
  return [
    CSMAGIC_CODEDIRECTORY, CSMAGIC_REQUIREMENTS,
    CSMAGIC_ENTITLEMENTS, CSMAGIC_BLOBWRAPPER,
  ].includes(magic >>> 0);
}

function readSignature(r: DataReader, linkedit: LinkEditInfo, sliceLen: number, pageSize: number):
  SuperBlobResult {
  const empty: SuperBlobResult = { blobs: [], bands: [], signatureRange: null };
  const off = linkedit.dataOffset?.value;
  const size = linkedit.dataSize?.value;
  if (off === undefined || size === undefined) return empty;

  if (!r.covers(off, size)) {
    throw new SliceFatal('format-corrupt',
      `LC_CODE_SIGNATURE range [0x${off.toString(16)},+${size}) exceeds slice end`, off);
  }

  // SuperBlob header is always big-endian.
  const br = r.order(false);
  const magic = br.u32(off) >>> 0;
  if (magic !== CSMAGIC_EMBEDDED_SIGNATURE && magic !== CSMAGIC_DETACHED_SIGNATURE) {
    throw new SliceFatal('format-corrupt',
      `bad code signature superblob magic 0x${magic.toString(16)}`, off);
  }
  const count = br.u32(off + 8);
  if (count < 1 || count > 256) {
    throw new SliceFatal('format-corrupt', `implausible blob count ${count}`, off + 8);
  }
  if (!br.covers(off + 12, count * 8)) {
    throw new SliceFatal('format-corrupt', 'blob index exceeds superblob', off + 12);
  }

  const blobs: SignatureBlobView[] = [];
  let codeDirectory: CodeDirectoryView | undefined;
  for (let i = 0; i < count; i++) {
    const entryOff = off + 12 + i * 8;
    const type = br.u32(entryOff);
    const blobOffRel = br.u32(entryOff + 4);
    const blobOff = off + blobOffRel;
    if (blobOff + 8 > off + size) {
      throw new SliceFatal('format-corrupt',
        `blob #${i} header outside declared signature size`, blobOff);
    }
    const bMagic = br.u32(blobOff) >>> 0;
    const bLen = br.u32(blobOff + 4);
    if (bLen < 8 || blobOff + bLen > off + size) {
      throw new SliceFatal('format-corrupt',
        `blob #${i} length ${bLen} overruns signature size`, blobOff + 4);
    }
    const typeName = blobTypeName(type);
    blobs.push({
      id: cid('sigblob', [blobOff, type, bMagic, bLen]),
      indexInSuper: i,
      type: dv(`${type} (${typeName})`, type, 'blob-slot-type', 'slice-local'),
      typeName,
      known: isKnownBlobType(type),
      offset: bytes(blobOff),
      length: bytes(bLen),
      range: { start: bytes(blobOff), end: bytes(blobOff + bLen) },
      magic: dv(`0x${bMagic.toString(16)}`, bMagic, 'blob-magic', 'slice-local',
        knownMagic(bMagic) ? undefined : 'unknown blob magic'),
    });
    if (bMagic === CSMAGIC_CODEDIRECTORY && !codeDirectory) {
      codeDirectory = readCodeDirectory(br, blobOff, bLen, r, pageSize, i);
    }
  }

  // signature extent = [min blob start, declared dataoff+datasize]
  const starts = blobs.map((b) => b.offset.value!);
  const sigStart = Math.min(off, ...starts);
  const sigEnd = off + size;
  const bands: CoverageBand[] = [];
  if (codeDirectory) {
    const limit = codeDirectory.codeLimit.value!;
    // hashed pages
    for (const slot of codeDirectory.codeSlots) {
      bands.push({
        id: cid('band-hashed', [slot.index, slot.pageRange.start.value, slot.pageRange.end.value]),
        start: bytes(slot.pageRange.start.value!),
        end: bytes(slot.pageRange.end.value!),
        label: `hashed page ${slot.index}`,
        covered: slot.matches,
      });
    }
    // gap between codeLimit and signature start (uncovered)
    if (limit < sigStart) {
      bands.push({
        id: cid('band-gap', [limit, sigStart]),
        start: bytes(limit), end: bytes(sigStart),
        label: 'pre-signature uncovered gap', covered: false,
      });
    }
  }
  // signed blob band
  bands.push({
    id: cid('band-sig', [sigStart, sigEnd]),
    start: bytes(sigStart), end: bytes(sigEnd),
    label: 'code signature blob', covered: true,
  });
  // uncovered tail past the signature extent
  if (sigEnd < sliceLen) {
    bands.push({
      id: cid('band-tail', [sigEnd, sliceLen]),
      start: bytes(sigEnd), end: bytes(sliceLen),
      label: 'uncovered tail after signature', covered: false,
    });
  }
  return { blobs, codeDirectory, bands, signatureRange: { start: sigStart, end: sigEnd } };
}

function digestFor(type: number, data: Uint8Array): Uint8Array | null {
  const { createHash } = await_import_crypto();
  if (type === CS_HASHTYPE_SHA256) return new Uint8Array(createHash('sha256').update(data).digest());
  return null;
}

// tiny indirection keeps the file synchronous (Node hash helpers already sync)
import { createHash } from 'node:crypto';
function await_import_crypto() { return { createHash }; }

function readCodeDirectory(
  br: DataReader, cdOff: number, cdLen: number, sliceReader: DataReader,
  pageSizeHint: number, blobIndex: number,
): CodeDirectoryView {
  const version = br.u32(cdOff + 8);
  const flags = br.u32(cdOff + 12);
  const hashOffset = br.u32(cdOff + 16);
  const identOffset = br.u32(cdOff + 20);
  const nSpecial = br.u32(cdOff + 24);
  const nCode = br.u32(cdOff + 28);
  const codeLimit = br.u32(cdOff + 32);
  const hashSize = br.u8at(cdOff + 36);
  const hashType = br.u8at(cdOff + 37);
  const pageExp = br.u8at(cdOff + 39);
  const pageSize = pageExp ? 2 ** pageExp : pageSizeHint;

  let ident = '';
  if (identOffset > 0 && cdOff + identOffset < cdOff + cdLen) {
    const start = cdOff + identOffset;
    let end = start;
    while (end < cdOff + cdLen && br.u8at(end) !== 0) end++;
    ident = Buffer.from(sliceReader.bytes.subarray(
      sliceReader.base + start, sliceReader.base + end)).toString('utf8');
  }

  const supported = hashType === CS_HASHTYPE_SHA256;
  const slots: CodeSlotView[] = [];
  for (let i = 0; i < nCode; i++) {
    const slotOff = cdOff + hashOffset + nSpecial * hashSize + i * hashSize;
    if (slotOff + hashSize > cdOff + cdLen) {
      throw new SliceFatal('format-corrupt', `code slot ${i} outside code directory`, slotOff);
    }
    const expectedBytes = br.slice(slotOff, hashSize);
    const pageStart = i * pageSize;
    const pageEnd = Math.min((i + 1) * pageSize, codeLimit);
    let actual: Uint8Array | null = null;
    if (supported && pageStart < codeLimit) {
      actual = new Uint8Array(createHash('sha256').update(sliceReader.slice(pageStart, pageEnd - pageStart)).digest());
    }
    const matches = actual !== null && Buffer.compare(actual, expectedBytes) === 0;
    const zero = expectedBytes.every((b) => b === 0);
    const toHex = (b: Uint8Array | null) =>
      b === null ? null : Buffer.from(b).toString('hex');
    slots.push({
      index: i,
      kind: 'code',
      pageRange: { start: bytes(pageStart), end: bytes(pageEnd) },
      expectedDigest: dv(
        zero ? '00…(absent)' : `sha256:${toHex(expectedBytes)}`,
        null, 'digest-hex', 'slice-local',
        zero ? 'special/code slot is zero: page not covered' : undefined,
      ),
      actualDigest: dv(
        actual ? `sha256:${toHex(actual)}` : `unavailable (hashType=${hashTypeName(hashType)})`,
        null, 'digest-hex', 'slice-local',
        supported ? undefined : `unsupported hash type ${hashType}`,
      ),
      matches: zero ? false : matches,
    });
  }

  return {
    blobIndex,
    version: dv(`0x${version.toString(16)}`, version, 'code-directory-version', 'slice-local'),
    flags: flagNum(flags),
    hashType: dv(`${hashType} (${hashTypeName(hashType)})`, hashType, 'hash-type-id', 'slice-local',
      supported ? undefined : `unsupported hash type ${hashType}`),
    hashTypeName: hashTypeName(hashType),
    pageSize: bytes(pageSize),
    codeLimit: bytes(codeLimit),
    ident,
    codeSlots: slots,
  };
}
