/**
 * 领域类型：Mach-O / 通用二进制 / 代码签名覆盖审阅。
 * 所有领域量都携带单位或坐标基准；导入层保留原始表示（raw），
 * 派生层才做规范化（value）；无法转换时 value=null 并附 diagnostic。
 */

/** 带单位与坐标基准的量。raw 为导入时的原始表示，永不丢失。 */
export interface Qty {
  raw: string;
  value: number | null;
  unit: 'byte' | 'byte-exponent' | 'count' | 'enum' | 'hex';
  /** 坐标基准，例如 'fat-file'、'slice:0'、'code-page(4096)' */
  basis: string;
  /** 无法规范化或需注意时的诊断；存在即说明该量未被静默修正 */
  diagnostic?: string;
}

export type Endianness = 'big' | 'little';

export interface FatArchEntry {
  id: string;
  index: number;
  cputype: Qty;
  cpusubtype: Qty;
  archName: string;
  offset: Qty;
  size: Qty;
  align: Qty; // unit = 'byte-exponent'，即 2^n 中的 n
}

export interface FatHeaderFacts {
  magic: Qty;
  endianness: Endianness;
  is64Bit: boolean;
  nfatArch: Qty;
}

export interface MachHeaderFacts {
  magic: Qty;
  endianness: Endianness;
  is64Bit: boolean;
  cputype: Qty;
  cpusubtype: Qty;
  filetype: Qty;
  ncmds: Qty;
  sizeofcmds: Qty;
  flags: Qty;
}

export interface LoadCommandFacts {
  id: string;
  index: number;
  cmd: Qty;
  cmdName: string;
  cmdsize: Qty;
  /** 相对 slice 起点的字节范围 */
  range: { start: number; end: number };
  /** 命令特有字段（如 LC_CODE_SIGNATURE 的 dataoff/datasize） */
  detail: Record<string, Qty>;
}

export interface CodeSlotResult {
  slotIndex: number;
  pageRange: { start: number; end: number }; // slice 坐标
  expectedHash: string; // hex
  actualHash: string; // hex
  ok: boolean;
  firstDiffOffset: number | null; // slice 坐标
}

export interface SignatureFacts {
  blobRange: { start: number; end: number }; // slice 坐标
  superBlobMagic: Qty;
  blobs: BlobFacts[];
  codeDirectory?: {
    hashType: Qty;
    hashAlgorithm: string; // 'sha1' | 'sha256' | 'unknown'
    pageSize: Qty; // byte-exponent
    codeLimit: Qty;
    nCodeSlots: Qty;
    nSpecialSlots: Qty;
    slots: CodeSlotResult[];
  };
}

export interface BlobFacts {
  index: number;
  type: Qty;
  offset: Qty;
  magic: Qty;
  length: Qty;
  supported: boolean;
  /** 无法唯一决定时保留的全部合法候选解释 */
  candidates: string[];
}

/** 覆盖带分段：slice 坐标系 */
export interface CoverageSegment {
  start: number;
  end: number;
  kind: 'code-slots' | 'signature-blob' | 'gap';
}

export interface SliceFacts {
  id: string;
  index: number;
  arch: FatArchEntry;
  digest: string; // slice 字节摘要（派生层）
  endianness: Endianness | null;
  header: MachHeaderFacts | null;
  commands: LoadCommandFacts[];
  signature: SignatureFacts | null;
  coverage: CoverageSegment[];
  outcome: SliceOutcome;
}

/** 三种必须区分的失败结果 + 正常 */
export type SliceOutcome =
  | { kind: 'ok' }
  | { kind: 'budget-exhausted'; reason: string; at: number }
  | { kind: 'malformed'; reason: string; at: number }
  | { kind: 'unsatisfiable'; reason: string; candidates: string[] };

export interface ContainerFacts {
  materialId: string;
  fileSize: number;
  fat: FatHeaderFacts | null; // null 表示 thin Mach-O（单 slice 容器）
  slices: SliceFacts[];
  outcome: SliceOutcome;
}

export interface RuleParams {
  version: string;
  maxCommands: number;
  maxSlices: number;
  minAlignExponent: number;
  maxAlignExponent: number;
  requireTailCoverage: boolean;
  hashAlgorithms: string[];
}

export interface EvidenceBytes {
  /** 坐标基准，例如 'slice:0' 或 'fat-file' */
  basis: string;
  start: number;
  hex: string; // 最多 64 字节
}

export interface Finding {
  id: string;
  ruleId: string;
  ruleVersion: string;
  severity: 'error' | 'warning' | 'info';
  computationId: string;
  objectIds: string[];
  message: string;
  evidence: {
    ranges: { basis: string; start: number; end: number }[];
    expected?: string;
    actual?: string;
    bytes?: EvidenceBytes;
  };
  outcome?: 'malformed' | 'budget-exhausted' | 'unsatisfiable';
  candidates?: { id: string; label: string }[];
}

export type FindingStatus = 'open' | 'accepted' | 'rejected' | 'adjusted' | 'conflicted';

export interface Decision {
  id: string;
  seq: number;
  findingId: string;
  action: 'accept' | 'reject' | 'adjust';
  actor: string;
  rationale: string;
  params?: Record<string, unknown>;
}

export interface ReviewEvent {
  seq: number;
  id: string;
  kind:
    | 'import-material'
    | 'derive'
    | 'revise-params'
    | 'revise-source'
    | 'decide'
    | 'note';
  summary: string;
  payload: Record<string, unknown>;
  parents: string[];
  createdAt: string;
}

export interface Material {
  id: string;
  kind: 'fat-binary' | 'arch-policy' | 'casepack';
  name: string;
  digest: string;
  size: number;
  meta: Record<string, unknown>;
  source: { type: string; ref?: string };
}

export interface Computation {
  id: string;
  materialId: string;
  scope: 'container' | 'slice';
  scopeIndex: number | null;
  ruleVersion: string;
  paramsVersion: string;
  inputDigest: string;
  parentIds: string[];
  createdSeq: number;
}

export interface Conflict {
  findingId: string;
  decisions: Decision[];
}

export interface ReviewState {
  seq: number;
  headSeq: number;
  viewingHistory: boolean;
  params: RuleParams;
  paramsHistory: { version: string; seq: number; params: RuleParams }[];
  materials: Material[];
  containers: ContainerFacts[];
  findings: (Finding & { status: FindingStatus })[];
  decisions: Decision[];
  conflicts: Conflict[];
  computations: Computation[];
  timeline: { seq: number; id: string; kind: string; summary: string }[];
  replay: { cursor: number; total: number; steps: string[] };
}
