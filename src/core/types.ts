// Parsed domain objects. Every byte-derived quantity keeps its raw on-disk
// representation plus a unit/coordinate basis; normalization happens only in
// derived layers. Stable ids are assigned at import time and never depend on
// array position.

import { Finding, OutcomeClass } from './diagnostics.js';
import { Endian } from './reader.js';

export interface Dimensional {
  value: number;
  unit: string;          // e.g. 'bytes'
  basis: string;         // e.g. 'absolute-file-offset'
  raw: string;           // original representation preserved from the source
  endian?: Endian;
}

export interface FatHeaderView {
  id: string;
  magic: number;
  magicHex: string;
  declaredEndian: Endian;
  is64: boolean;
  nFatArch: number;
  headerSizeBytes: number;  // 8 + n * sizeof(fat_arch[_64])
  fileSizeBytes: number;
}

export interface SliceView {
  id: string;                 // stable: sha1(fileId + arch + index...)? see ids.ts
  index: number;              // position in fat header (source order)
  arch: string;
  cpuType: number;
  cpuSubtype: number;
  offset: Dimensional;        // absolute file offset (bytes)
  sliceSize: Dimensional;     // bytes
  alignExponent: Dimensional; // raw power-of-two exponent, NOT rounded
  alignGranularity: number;   // 2^exponent
  magic: number;
  magicHex: string;
  endian: Endian;
  is64: boolean;
  reserved?: number;
}

export interface LoadCommandView {
  id: string;
  sliceId: string;
  ordinal: number;                 // order within slice, 0-based
  cmd: number;
  cmdName: string;
  cmdsize: number;                 // unit bytes
  headerRelativeOffset: number;    // bytes from slice start
  fileAbsoluteOffset: number;      // bytes from file start
  payloadSummary?: string;
  codeSignature?: { dataoff: number; datasize: number }; // slice-relative
}

export interface BlobIndexEntry {
  slot: number;
  slotName: string;
  offset: number;   // superblob-relative bytes
  blobMagic: number;
  blobMagicHex: string;
  blobLength: number;
  known: boolean;
}

export interface CodeSlotHash {
  slot: number;        // negative = special slot; >=0 = code page slot
  slotName: string;
  expectedDigestHex: string;
  actualDigestHex: string | null;  // null when the page bytes are unavailable
  pageStart?: number;              // slice-relative
  pageLength?: number;             // bytes
  match: boolean | null;          // null = not verifiable (coverage gap)
}

export interface SignatureView {
  id: string;
  sliceId: string;
  linkeditDataoff: number;   // slice-relative bytes
  linkeditDatasize: number;
  superblobMagic: number;
  superblobLength: number;
  codeDirectoryOffset: number | null;
  hashType: number;
  hashTypeName: string;
  digestLength: number;
  pageSize: number;          // 2^codeLimit pageSize field
  codeLimit: number;         // signed byte span within the slice
  identifiedOffset: number;  // start of signed region relative to slice (always 0)
  blobIndex: BlobIndexEntry[];
  codeSlots: CodeSlotHash[];
  coverageBands: CoverageBand[];
  unsupportedBlobMagics: number[];
}

export interface CoverageBand {
  kind: 'signed' | 'gap' | 'signature-data' | 'outside';
  start: number;  // slice-relative bytes
  end: number;    // exclusive, bytes
  label: string;
}

export interface ParsedFatFile {
  id: string;
  importId: string;              // correlates a material with later mutations
  sourceLabel: string;
  bytesLength: number;
  sha256: string;
  fat: FatHeaderView | null;
  slices: SliceView[];
  commands: LoadCommandView[];
  signatures: SignatureView[];
  findings: Finding[];
  outcomeClass: OutcomeClass;
  importedAt: string;            // ISO-8601 with explicit UTC basis label
}

// Policy / parameter document. Versioned; every derivation records the exact
// version it used.
export interface ReviewPolicy {
  version: string;
  preferredArch: string;
  unknownBlobPolicy: 'error' | 'warning';
  hashAlgorithms: number[];      // accepted CS_HASHTYPE_*
  pageHashLastPage: 'truncated' | 'padded';
  budget: {
    maxBytesRead: number;
    maxSlices: number;
    maxCommandsPerSlice: number;
    maxCodeSlots: number;
  };
}
