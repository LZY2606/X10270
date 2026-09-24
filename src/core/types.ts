/**
 * 领域类型定义。
 * 设计原则：
 * - 所有导入材料保留原始表示（raw 字段），派生值放在 normalized 字段并携带单位/坐标基准。
 * - 无法转换的值留在原位置并附诊断（diagnostics），绝不用空值或默认值伪装成功。
 * - 所有显示值带稳定身份（sid = stable id），等价输入产生相同身份与稳定顺序。
 */

export type Endianness = 'big' | 'little';

/** 坐标基准：fat 容器内偏移用 container；切片内部用 slice-local；Mach-O 文件内用 file。 */
export type CoordinateSpace = 'container' | 'slice-local' | 'file';

export interface Unit {
  /** 领域量单位，例如 byte / count / hex / arch-tag / hash-type */
  kind: 'byte' | 'count' | 'hex' | 'enum' | 'bool' | 'text';
  space?: CoordinateSpace;
}

export type DiagnosticCode =
  | 'TRUNCATED_FAT_HEADER'
  | 'TRUNCATED_FAT_ARCH'
  | 'UNKNOWN_MAGIC'
  | 'CONFLICTING_ENCODING'
  | 'TRUNCATED_MACHO_HEADER'
  | 'TRUNCATED_LOAD_COMMAND'
  | 'LC_OUT_OF_BOUNDS'
  | 'LINKEDIT_INCONSISTENT'
  | 'SIG_OOB'
  | 'TRUNCATED_SUPERBLOB'
  | 'TRUNCATED_BLOB_INDEX'
  | 'BLOB_INDEX_OOB'
  | 'UNKNOWN_BLOB_MAGIC'
  | 'TRUNCATED_CODEDIRECTORY'
  | 'UNSUPPORTED_HASH_TYPE'
  | 'CODESLOT_MISSING'
  | 'CODESLOT_TRUNCATED'
  | 'UNPARSEABLE_VALUE'
  | 'BUDGET_EXHAUSTED'
  | 'OVERLAPPING_SLICES'
  | 'ALIGN_OVERFLOW'
  | 'DUPLICATE_ARCH_TAG'
  | 'SIG_TAIL_UNCOVERED'
  | 'HASH_MISMATCH'
  | 'SEMANTIC_AMBIGUOUS';

/** 三种互不等价的终止结果类别。 */
export type OutcomeClass =
  | 'ok'
  | 'format-corrupt'
  | 'resource-exhausted'
  | 'semantically-unsolvable';

export interface Diagnostic {
  code: DiagnosticCode;
  message: string;
  /** 带坐标基准的位置证据：[start,end) 与所在坐标空间。 */
  range?: { start: number; end: number; space: CoordinateSpace };
  sliceId?: string;
  /** 指向原始输入片段的稳定引用。 */
  sourceRef?: string;
}

/** 带原始表示与单位的领域量。raw 永不被规范化覆盖。 */
export interface DomainValue<T> {
  raw: T;
  /** 派生层规范化结果；无法转换时为 null 且 diagnostic 必填。 */
  normalized: T | null;
  unit: Unit;
  diagnostic?: Diagnostic;
}

export interface EvidenceByte {
  offset: number;
  space: CoordinateSpace;
  expected?: string;
  actual?: string;
}

/** 规则判定结论的细分类型，签名校验严格区分三类。 */
export type FindingType =
  | 'endian-conflict'
  | 'slice-overlap'
  | 'alignment-overflow'
  | 'lc-out-of-bounds'
  | 'signature-coverage-gap'
  | 'hash-mismatch'
  | 'unsupported-signature-format'
  | 'unknown-blob'
  | 'duplicate-arch-tag'
  | 'ok';

export type Severity = 'info' | 'warning' | 'error';

/**
 * 结构化判定状态（不是纯日志）：可重放、可定位、可复核。
 * candidates 保留“无法唯一决定时”的全部合法候选。
 */
export interface Finding {
  fid: string;
  ruleId: string;
  ruleVersion: string;
  type: FindingType;
  severity: Severity;
  accepted: boolean;
  subjectSid: string;
  message: string;
  range?: { start: number; end: number; space: CoordinateSpace };
  evidence: EvidenceByte[];
  candidates?: string[];
  diagnostics: Diagnostic[];
  inputDigest: string;
  parents: string[];
}

export interface FatArchRaw {
  cputype: DomainValue<number>;
  cpusubtype: DomainValue<number>;
  offset: DomainValue<number>;
  size: DomainValue<number>;
  alignShift: DomainValue<number>;
}

export interface FatSlice {
  sid: string;
  archTag: string;
  archTagStable: string;
  index: number;
  offset: number;
  size: number;
  alignShift: number;
  /** 声明对齐 2^alignShift（byte），不做四舍五入修正。 */
  declaredAlignmentBytes: number;
  range: { start: number; end: number };
  raw: FatArchRaw;
}

export interface FatHeader {
  sid: string;
  magic: string;
  isFat: boolean;
  is64: boolean;
  endianness: Endianness | null;
  nfatArch: number;
  declaredEndianness: string;
  slices: FatSlice[];
  rawBytes: number[];
  diagnostics: Diagnostic[];
}

export interface LoadCommandSummary {
  sid: string;
  index: number;
  cmd: number;
  cmdName: string;
  /** slice-local 坐标。 */
  range: { start: number; end: number };
  cmdsize: number;
  segments?: SegmentSummary[];
  signatureDataoff?: number;
  signatureDatasize?: number;
  rawBytes: number[];
}

export interface SegmentSummary {
  segname: string;
  vmaddr: number;
  vmsize: number;
  fileoff: number;
  filesize: number;
  nsects: number;
}

export interface CodeSlot {
  index: number;
  /** slot 类型（含未知 slot 的原始数值，不丢弃）。 */
  type: number;
  typeName: string;
  offsetInBlob: number;
  length: number;
  rawDigest: string;
  normalizedDigest: string | null;
  hashType: number | null;
  unsupported?: boolean;
}

export interface SignatureBlobSummary {
  sid: string;
  magic: string;
  length: number;
  count: number;
  range: { start: number; end: number };
  blobs: EmbeddedBlob[];
  diagnostics: Diagnostic[];
}

export interface EmbeddedBlob {
  sid: string;
  index: number;
  slotType: number;
  slotName: string;
  offset: number;
  magic: string;
  length: number;
  range: { start: number; end: number };
  known: boolean;
  codeSlots?: CodeSlot[];
  codeDirectory?: CodeDirectorySummary;
  diagnostics: Diagnostic[];
}

export interface CodeDirectorySummary {
  version: number;
  hashType: number;
  hashSize: number;
  pageSize: number;
  codeSlotsRaw: string[];
  specialSlotsRaw: string[];
  codeLimit: number;
  identifiedTeamOffset?: number;
}

export interface SliceReport {
  slice: FatSlice;
  machMagic: string;
  machEndianness: Endianness | null;
  is64: boolean;
  headerRange: { start: number; end: number };
  loadCommands: LoadCommandSummary[];
  linkedit?: SegmentSummary;
  signature?: SignatureBlobSummary;
  /** __LINKEDIT 中 code signature 声明的 file 坐标范围。 */
  sigFileRange?: { start: number; end: number };
  /** 切片内 code signature 应覆盖的尾区间（Macho 视角：codeLimit..sliceEnd）。 */
  tailRange?: { start: number; end: number };
  diagnostics: Diagnostic[];
}

export interface ParseReport {
  reportId: string;
  inputDigest: string;
  totalBytes: number;
  outcome: OutcomeClass;
  fat: FatHeader | null;
  /** thin（非 fat）输入时的单切片视角。 */
  thin: SliceReport | null;
  slices: SliceReport[];
  findings: Finding[];
  diagnostics: Diagnostic[];
  budget: BudgetUsage;
}

export interface BudgetUsage {
  limit: number;
  used: number;
  unit: 'byte-work';
  exhausted: boolean;
}

export interface ArchitectureStrategy {
  strategyId: string;
  /** 目标架构标签，多架构同名时用于消歧。 */
  preferredArchTags: string[];
  /** 规则参数版本。 */
  rulesVersion: string;
  maxByteWork: number;
  maxSlices: number;
  maxLoadCommands: number;
}

export interface ScenarioResult {
  scenarioId: string;
  label: string;
  mutation: string;
  directSource: string;
  adopted: boolean;
  outcome: OutcomeClass;
  findings: Finding[];
  reportDigest: string;
}
