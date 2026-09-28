import type { ByteCoordinate, Quantity, QuantityUnit } from './quantities.js';

export type Endian = 'be' | 'le';

export type FindingCode =
  | 'ENDIAN_MISMATCH'
  | 'SLICE_OVERLAP'
  | 'SLICE_OUT_OF_BOUNDS'
  | 'ALIGNMENT_VIOLATION'
  | 'ALIGNMENT_OVERFLOW'
  | 'COMMAND_OUT_OF_BOUNDS'
  | 'SIG_COVERAGE_GAP'
  | 'CODESLOT_HASH_MISMATCH'
  | 'UNSUPPORTED_SIGNATURE_FORMAT'
  | 'UNKNOWN_BLOB'
  | 'ARCH_DUPLICATE'
  | 'BUDGET_EXHAUSTED'
  | 'FORMAT_CORRUPT'
  | 'SEMANTIC_AMBIGUOUS';

export type Severity = 'fatal' | 'error' | 'warning' | 'info';

export type OutcomeClass =
  | 'OK'
  | 'CORRUPT'
  | 'AMBIGUOUS'
  | 'BUDGET_EXHAUSTED';

export interface ByteRange {
  start: number;
  end: number;
  unit: 'byte';
  basis: string;
}

export interface ByteEvidence {
  start: number;
  end: number;
  expected?: string;
  actual?: string;
  note: string;
}

export interface Finding {
  code: FindingCode;
  severity: Severity;
  subject: string;
  message: string;
  coordinate?: ByteCoordinate;
  range?: ByteRange;
  evidence?: ByteEvidence;
  candidates?: CandidateInterpretation[];
}

export interface CandidateInterpretation {
  id: string;
  label: string;
  reason: string;
  adopted: boolean;
}

export interface FatHeader {
  id: string;
  magic: Quantity;
  endian: Endian;
  fatKind: 'fat32' | 'fat64';
  nfatArch: Quantity;
  entrySize: Quantity;
  fields: Quantity[];
  range: ByteRange;
}

export interface FatSliceEntry {
  id: string;
  index: number;
  cputype: Quantity;
  cpusubtype: Quantity;
  offset: Quantity;
  size: Quantity;
  align: Quantity;
  reserved: Quantity | null;
  endian: Endian;
  fields: Quantity[];
  range: ByteRange;
}

export interface SliceHeader {
  magic: Quantity;
  endian: Endian;
  cputype: Quantity;
  cpusubtype: Quantity;
  filetype: Quantity;
  ncmds: Quantity;
  sizeofcmds: Quantity;
  flags: Quantity;
  reserved: Quantity | null;
  fields: Quantity[];
}

export interface LoadCommand {
  id: string;
  index: number;
  cmd: Quantity;
  cmdsize: Quantity;
  range: ByteRange;
  commandEndian: Endian;
  kind: 'SEGMENT_64' | 'CODE_SIGNATURE' | 'LINKEDIT_HINT' | 'OTHER';
  detail?: Record<string, Quantity | string>;
  blobIndex?: number;
}

export interface LinkEditInfo {
  id: string;
  segname: string;
  vmaddr: Quantity;
  vmsize: Quantity;
  fileoff: Quantity;
  filesize: Quantity;
  range: ByteRange;
}

export interface SigBlob {
  id: string;
  index: number;
  blobType: Quantity;
  offset: Quantity;
  magic: Quantity;
  length: Quantity;
  known: boolean;
  range: ByteRange;
  unsupportedReason?: string;
}

export interface CodeSlot {
  id: string;
  index: number;
  kind: 'code' | 'special';
  storedDigest: string;
  computedDigest: string | null;
  match: boolean | null;
  pageRange: ByteRange | null;
  offsetInCodeDir: Quantity;
}

export interface SignatureCoverage {
  id: string;
  superblobRange: ByteRange;
  coveredRange: ByteRange | null;
  tailGapRange: ByteRange | null;
  codeLimit: Quantity;
  identifiedEnd: number;
  blobs: SigBlob[];
  slots: CodeSlot[];
}

export interface Slice {
  id: string;
  fatEntry: FatSliceEntry;
  archName: string;
  header: SliceHeader;
  commandRegion: { start: number; end: number };
  commands: LoadCommand[];
  linkedit: LinkEditInfo | null;
  signature: SignatureCoverage | null;
  findings: Finding[];
}

export interface FatContainer {
  id: string;
  header: FatHeader;
  entries: FatSliceEntry[];
  slices: Slice[];
  range: ByteRange;
}

export interface RuleParamsV {
  ruleSetVersion: string;
  pageSize: number;
  acceptedCodeDirHashTypes: number[];
  hashTypeNames: Record<number, string>;
  requireExplicitPageSize: boolean;
  maxCommands: number;
  maxSlots: number;
  maxSlices: number;
  maxBytes: number;
  maxCommandBytes: number;
  maxDepth: number;
  alignmentRounding: 'forbidden' | 'nearest';
}

export interface AnalysisTarget {
  materialId: string;
  policyName: string;
  requestedArch: string[] | null;
}

export interface Analysis {
  id: string;
  materialId: string;
  materialSha256: string;
  ruleSetVersion: string;
  params: RuleParamsV;
  policyName: string;
  target: AnalysisTarget;
  container: FatContainer | null;
  findings: Finding[];
  outcome: OutcomeClass;
  inputDigest: string;
  parents: string[];
  createdAt: number;
  counterexampleId?: string;
}

export interface UnitMeta {
  unit: QuantityUnit;
  label: string;
}
