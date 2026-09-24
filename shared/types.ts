// 领域类型：所有领域量携带单位或坐标基准；原始表示保留在 raw 字段。
export type ByteOrder = 'be' | 'le';

export interface Quantity {
  value: number;
  unit: 'byte' | 'pageshift' | 'count';
  basis: 'file' | 'slice' | 'blob' | 'none';
}

export interface RawField {
  hex: string;
  offset: number; // 文件坐标（byte）
  length: number; // byte
}

export interface FatHeaderView {
  id: string;
  magic: RawField;
  byteOrder: ByteOrder;
  nfatArch: Quantity;
}

export interface SliceView {
  id: string;
  index: number;
  cputype: RawField & { value: number };
  cpusubtype: RawField & { value: number };
  archName: string;
  offset: Quantity; // basis: file
  size: Quantity;
  alignExponent: number; // 2^align，绝不四舍五入修正
  alignBytes: number | null; // null 表示 2^align 溢出
  rawEntry: RawField;
}

export interface LoadCommandView {
  id: string;
  sliceId: string;
  index: number;
  cmd: number;
  cmdName: string;
  cmdsize: Quantity;
  fileOffset: Quantity; // basis: file
  sliceOffset: Quantity; // basis: slice
  raw: RawField;
}

export interface CoverageRegion {
  id: string;
  kind: 'code-slot' | 'signature' | 'gap';
  start: Quantity; // basis: slice
  length: Quantity;
  pageIndex?: number;
  hashOk?: boolean;
}

export interface BlobView {
  id: string;
  type: number;
  magic: number;
  magicName: string;
  known: boolean;
  offset: Quantity; // basis: slice
  length: Quantity;
}

export interface SignatureView {
  id: string;
  sliceId: string;
  dataoff: Quantity;
  datasize: Quantity;
  superblobMagic: string;
  blobs: BlobView[];
  codeDirectory?: {
    hashType: number;
    hashTypeName: string;
    hashSize: number;
    pageSizeExponent: number;
    nCodeSlots: number;
    nSpecialSlots: number;
    codeLimit: Quantity;
    slotDigests: { index: number; expected: string; actual: string; match: boolean }[];
  };
  coverage: CoverageRegion[];
}

export type VerdictStatus =
  | 'ok'
  | 'violation'
  | 'coverage_gap'
  | 'hash_mismatch'
  | 'unsupported_format'
  | 'format_corrupt'
  | 'semantic_unsolvable'
  | 'budget_exhausted';

export interface Verdict {
  id: string; // 稳定身份：内容派生
  check: string;
  status: VerdictStatus;
  subject: string; // 受影响对象 id
  message: string;
  evidence?: { offset: Quantity; bytes: string };
  candidates?: string[]; // 无法唯一决定时保留全部合法候选
}

export interface BinaryView {
  materialId: string;
  name: string;
  digest: string;
  importEventId: string;
  ruleVersion: string;
  fatHeader: FatHeaderView | null;
  slices: SliceView[];
  commands: LoadCommandView[];
  signatures: SignatureView[];
  verdicts: Verdict[];
  result: 'ok' | 'violation' | 'budget_exhausted' | 'format_corrupt' | 'semantic_unsolvable';
}
