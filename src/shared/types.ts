// 领域类型：Mach-O / universal binary / code signature 覆盖核验。
// 所有导入材料都是不可变的；派生结论只引用材料与参数版本。

export type Endian = 'le' | 'be';

export type ByteUnit = 'bytes';
export type AlignUnit = 'alignExponent' | 'bytes';
export type TimeUnit = 'unixEpochMs';
export type HashUnit = 'sha256Hex';

export interface Coordinate {
  // 坐标基准：文件级字节偏移，或 slice 相对偏移。
  basis: 'file' | 'slice';
  start: number;
  size: number;
  unit: ByteUnit;
}

export interface RawField {
  // 导入时保留原始表示，仅派生层做规范化。
  name: string;
  raw: string | number;
  numeric?: number;
  rawBase?: 10 | 16;
  unit?: string;
  basis?: 'file' | 'slice';
  convertError?: string;
}

export type Severity = 'info' | 'warn' | 'error';

export type MaterialKind =
  | 'fatHeader'
  | 'fatArch'
  | 'machHeader'
  | 'loadCommand'
  | 'linkedit'
  | 'signatureBlob'
  | 'codeSlot'
  | 'rawDigest';

export interface MaterialBase {
  id: string;
  packId: string;
  revision: number;
  kind: MaterialKind;
  sliceOrdinal: number | null;
  coords: Coordinate[];
  endian: Endian | null;
  rawFields: RawField[];
}

export interface FatHeaderMaterial extends MaterialBase {
  kind: 'fatHeader';
  isFat64: boolean;
  magic: string;
  narch: number;
}

export interface FatArchMaterial extends MaterialBase {
  kind: 'fatArch';
  index: number;
  cpuType: number;
  cpuSubtype: number;
  offset: number;
  size: number;
  align: number;
  declaredEndian: Endian;
}

export interface MachHeaderMaterial extends MaterialBase {
  kind: 'machHeader';
  magic: string;
  cpuType: number;
  cpuSubtype: number;
  fileType: number;
  ncmds: number;
  sizeofcmds: number;
  sliceEndian: Endian;
  declaredEndian: Endian;
  is64: boolean;
}

export interface LoadCommandMaterial extends MaterialBase {
  kind: 'loadCommand';
  index: number;
  cmd: number;
  cmdName: string;
  cmdsize: number;
  payloadFields: RawField[];
}

export interface LinkeditMaterial extends MaterialBase {
  kind: 'linkedit';
  fileoff: number;
  filesize: number;
  vmaddr: number;
  vmsize: number;
}

export interface SignatureBlobMaterial extends MaterialBase {
  kind: 'signatureBlob';
  magics: RawField[];
  length: number;
  lengthField: number;
  slots: {
    type: number;
    typeName: string;
    offset: number;
    magic?: string;
    length?: number;
    supported: boolean;
  }[];
  codeDirectoryId: string | null;
  codeLimitField: number;
  hashType: number;
  hashSize: number;
  pageSize: number;
  ident: string;
  specialSlotCount: number;
  codeSlotCount: number;
  unsupportedReason: string | null;
}

export interface CodeSlotMaterial extends MaterialBase {
  kind: 'codeSlot';
  slot: number; // -1..-n special slots, 0..n-1 code slots
  pageStart: number | null;
  pageEnd: number | null;
  expectedDigest: string | null;
  actualDigest: string | null;
  hashUnit: HashUnit;
  match: boolean | null;
  status: 'ok' | 'mismatch' | 'uncovered' | 'unsupported';
}

export interface RawDigestMaterial extends MaterialBase {
  kind: 'rawDigest';
  algorithm: string;
  value: string;
  source: 'codeDirectory' | 'specialSlot' | 'ident';
  slotRef: number | null;
}

export type Material =
  | FatHeaderMaterial
  | FatArchMaterial
  | MachHeaderMaterial
  | LoadCommandMaterial
  | LinkeditMaterial
  | SignatureBlobMaterial
  | CodeSlotMaterial
  | RawDigestMaterial;

export type FindingRule =
  | 'ENDIAN_INCONSISTENT'
  | 'SLICE_OVERLAP'
  | 'ALIGN_OVERFLOW'
  | 'ALIGN_MISALIGNED'
  | 'COMMAND_OUT_OF_BOUNDS'
  | 'COVERAGE_GAP'
  | 'HASH_MISMATCH'
  | 'UNSUPPORTED_FORMAT'
  | 'UNKNOWN_BLOB'
  | 'DUPLICATE_ARCH'
  | 'BUDGET_EXHAUSTED'
  | 'FORMAT_CORRUPT';

export type FindingStatus =
  | 'open'
  | 'accepted'
  | 'rejected'
  | 'conflict'
  | 'candidate';

export interface EvidenceByte {
  offset: number;
  basis: 'file' | 'slice';
  expected: string;
  actual: string;
  note: string;
}

export interface Finding {
  id: string;
  rule: FindingRule;
  severity: Severity;
  title: string;
  sliceOrdinal: number | null;
  // 受影响对象（材料稳定身份）。
  affectedMaterials: string[];
  coords: Coordinate[];
  message: string;
  // 签名验证三类必须可机器区分。
  category:
    | 'coverage'
    | 'hash'
    | 'unsupported'
    | 'layout'
    | 'endian'
    | 'identity'
    | 'budget'
    | 'corrupt';
  status: FindingStatus;
  candidates: string[];
  evidence: EvidenceByte[];
  evidenceUnit: ByteUnit | null;
  basis: string; // 判断依据（人类可读，与 rule 机器键并存）
}

export type AnalysisStatus =
  | 'ok'
  | 'rejected'
  | 'semantic_unresolved'
  | 'format_corrupt'
  | 'budget_exhausted';

export interface DerivationResult {
  id: string;
  packId: string;
  revision: number;
  paramVersion: number;
  parentDerivationId: string | null;
  inputDigest: string;
  slices: ParsedSlice[];
  findings: Finding[];
  status: AnalysisStatus;
  createdAt: number;
  createdAtBasis: TimeUnit;
}

export interface ParsedSlice {
  ordinal: number;
  cpuType: number;
  cpuSubtype: number;
  archName: string;
  declaredEndian: Endian;
  fileStart: number;
  fileSize: number;
  align: number;
  parseable: boolean;
  signatureId: string | null;
  coverageBand: {
    signedStart: number;
    signedEnd: number;
    tailStart: number;
    tailEnd: number;
    unit: ByteUnit;
  } | null;
}

export type Params = {
  maxSlices: number;
  codePageSize: number;
  codePageSizeUnit: ByteUnit;
  maxAlignExponent: number;
  strictEndian: boolean;
  rejectUnknownBlob: boolean;
  requireSignature: boolean;
  maxEvidenceBytes: number;
};

export const DEFAULT_PARAMS: Params = {
  maxSlices: 64,
  codePageSize: 4096,
  codePageSizeUnit: 'bytes',
  maxAlignExponent: 31,
  strictEndian: false,
  rejectUnknownBlob: false,
  requireSignature: true,
  maxEvidenceBytes: 64,
};

export type EventType =
  | 'import'
  | 'sourceRevise'
  | 'paramRevise'
  | 'decision'
  | 'analysis';

export interface EventBase {
  seq: number;
  packId: string;
  at: number;
  atBasis: TimeUnit;
  revision: number;
  paramVersion: number;
  derivationId: string | null;
}

export interface ImportEvent extends EventBase {
  type: 'import';
  inputDigest: string;
  byteLength: number;
  byteLengthUnit: ByteUnit;
  sourceName: string;
}

export interface SourceReviseEvent extends EventBase {
  type: 'sourceRevise';
  note: string;
  changeKind: string;
  inputDigest: string;
  byteLength: number;
  patches: { offset: number; bytesBefore: string; bytesAfter: string; basis: 'file' }[];
}

export interface ParamReviseEvent extends EventBase {
  type: 'paramRevise';
  changes: { key: keyof Params; from: Params[keyof Params]; to: Params[keyof Params] }[];
}

export interface DecisionEvent extends EventBase {
  type: 'decision';
  decision: 'accept' | 'reject' | 'conflict' | 'parameterAdjust';
  targetFindingIds: string[];
  rationale: string;
  conflictsWith: string | null;
}

export interface AnalysisEvent extends EventBase {
  type: 'analysis';
  status: AnalysisStatus;
  findingIds: string[];
}

export type TimelineEvent =
  | ImportEvent
  | SourceReviseEvent
  | ParamReviseEvent
  | DecisionEvent
  | AnalysisEvent;

export interface CasePack {
  packId: string;
  title: string;
  scenario: string;
  bytesBase64: string;
  sourceName: string;
  params: Params;
  events: TimelineEvent[];
  exportedAt: number;
  schemaVersion: 1;
}

export interface PackSummary {
  packId: string;
  title: string;
  scenario: string;
  latestRevision: number;
  headEventSeq: number;
  status: AnalysisStatus;
  isDemo: boolean;
}
