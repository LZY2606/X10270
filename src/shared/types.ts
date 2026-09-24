// ---------------------------------------------------------------------------
// 共享类型：Mach-O 领域模型、事件模型、分析结果。
// 所有领域量都携带单位或坐标基准；原始表示在导入层保留，派生层才规范化。
// ---------------------------------------------------------------------------

export type ByteOrder = 'big' | 'little';

/** 带坐标基准的字节区间（单位恒为 byte，offset 相对所属 slice/文件起点）。 */
export interface ByteRange {
  offset: number; // byte
  size: number;   // byte
}

export interface Quantity {
  value: number;
  unit: 'byte' | 'page' | 'bit' | 'count' | 'exponent';
  /** 坐标基准，例如 file/slice/superblob/codedirectory */
  basis: string;
}

export interface FatArchEntry {
  index: number;
  cputype: number;
  cpusubtype: number;
  cpuName: string;
  offset: Quantity;   // unit byte, basis file
  size: Quantity;     // unit byte, basis file
  align: Quantity;    // unit exponent (2^n), basis file
  alignBytes: number; // 派生：2^align，溢出时保持 undefined 语义由 finding 表达
  alignOverflow: boolean;
  rawHex: string;     // 原始 20 字节表示，导入时保留
}

export interface FatHeader {
  magic: number;
  magicHex: string;
  byteOrder: ByteOrder;      // 解析使用的字节序
  declaredOrder: ByteOrder;  // magic 声明的字节序
  swappedMagic: boolean;     // magic 为 FAT_CIGAM（0xbebafeca）
  nfatArch: number;
  archs: FatArchEntry[];
}

export interface LoadCommandInfo {
  index: number;
  cmd: number;
  cmdHex: string;
  cmdName: string;
  cmdsize: Quantity; // byte, basis slice
  offset: Quantity;  // byte, basis slice
  endOffset: number; // 派生
  withinHeader: boolean;
  withinSlice: boolean;
  rawHex: string; // 前 8 字节原始表示
}

export interface LinkEditInfo {
  dataoff: Quantity; // byte, basis slice
  datasize: Quantity;
  endOffset: number;
  withinSlice: boolean;
}

export interface SliceInfo {
  sliceId: string;       // 稳定身份：arch 索引 + cpu 名
  archIndex: number;
  cpuName: string;
  range: ByteRange;      // 相对文件
  align: Quantity;
  alignBytes: number;
  alignOverflow: boolean;
  byteOrder: ByteOrder;  // thin Mach-O 自身字节序
  magicHex: string;
  is64: boolean;
  ncmds: number;
  sizeofcmds: Quantity; // byte, basis slice
  commands: LoadCommandInfo[];
  linkedit: LinkEditInfo | null;
  signature: SignatureInfo | null;
}

export interface BlobIndex {
  type: number;
  typeName: string;
  offset: Quantity; // byte, basis superblob
  magic: number | null;
  magicHex: string;
  recognized: boolean; // magic 是否为已知 blob
}

export interface CodeSlot {
  slotIndex: number; // -1 => CodeDirectory 槽
  label: string;
  expectedHashHex: string; // 原始摘要，保留
  actualHashHex: string | null;
  match: boolean | null;   // null => 无法计算（覆盖缺口等）
}

export interface SignatureInfo {
  range: ByteRange;       // 相对 slice
  fileRange: ByteRange;   // 相对文件
  length: Quantity;
  magicHex: string;
  count: number;
  blobs: BlobIndex[];
  codeDirectory: {
    hashType: number;
    hashTypeName: string;
    hashSize: number;
    pageSize: Quantity; // exponent
    pageSizeBytes: number;
    codeLimit: Quantity; // byte, basis slice
    nCodeSlots: number;
    nSpecialSlots: number;
    slots: CodeSlot[];
  } | null;
  /** 覆盖带：signed 段（[0, codeLimit)）与 signature blob 段 */
  coverage: {
    signedRange: ByteRange;   // 相对 slice
    signatureRange: ByteRange;
    uncoveredGaps: ByteRange[]; // 相对 slice 的未覆盖缺口
  };
}

export interface MachoDocument {
  fat: FatHeader;
  slices: SliceInfo[];
  fileSize: Quantity;
}

// ---------------------------------------------------------------------------
// Findings：结构化判定结果（机器可读），每条都有稳定身份。
// ---------------------------------------------------------------------------

export type FindingCategory =
  | 'format'
  | 'endian'
  | 'slice-overlap'
  | 'alignment'
  | 'load-command'
  | 'signature-coverage'
  | 'signature-hash'
  | 'signature-format'
  | 'multi-arch'
  | 'budget'
  | 'semantic';

export type FindingSeverity = 'violation' | 'warning' | 'info';

export interface Finding {
  findingId: string; // 稳定身份：runId + ruleId + subject
  ruleId: string;    // 例如 SLICE-OVERLAP-01
  category: FindingCategory;
  severity: FindingSeverity;
  status: 'open' | 'accepted' | 'rejected' | 'adjusted';
  message: string;
  /** 受影响对象（sliceId / command index / blob type 等） */
  subjects: string[];
  /** 证据：失败字节读回，含坐标基准 */
  evidence: {
    basis: string;
    offset: number;
    length: number;
    hex: string;
    note?: string;
  }[];
  /** 语义冲突时保留的全部合法候选 */
  candidates?: { label: string; detail: string }[];
  params: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// 分析运行：记录输入摘要、参数版本、父级依赖。
// ---------------------------------------------------------------------------

export type RunOutcome =
  | 'ok'
  | 'violations'
  | 'budget_exhausted'   // 资源预算耗尽
  | 'format_corrupt'     // 格式损坏
  | 'semantic_unsatisfiable'; // 语义无解

export interface AnalysisRun {
  runId: string;
  materialId: string;
  paramVersionId: string;
  parentRunIds: string[];
  inputDigest: string; // sha256 of material bytes
  outcome: RunOutcome;
  findings: Finding[];
  document: MachoDocument | null; // 解析成功时的派生文档
  diagnostics: Diagnostic[];
  startedSeq: number;
}

export interface Diagnostic {
  code: string;
  message: string;
  /** 带位置的诊断：坐标基准 + 偏移 */
  position?: { basis: string; offset: number };
}

// ---------------------------------------------------------------------------
// 材料 / 参数 / 决定 / 事件
// ---------------------------------------------------------------------------

export type MaterialKind = 'universal-binary' | 'arch-policy' | 'case-note';

export interface Material {
  materialId: string;
  kind: MaterialKind;
  name: string;
  byteSize: number;
  sha256: string;
  importedAtSeq: number;
  /** 原始表示保留：base64 字节（二进制）或原文（文本） */
  rawBase64?: string;
  rawText?: string;
  /** 反例档案：来源与单一改动描述 */
  provenance?: {
    baselineOf?: string;
    derivedFrom?: string;
    mutation?: string;
    adopted: boolean; // 被采纳 / 未采纳的结果均保留
  };
}

export interface ParamVersion {
  paramVersionId: string;
  version: number;
  rules: {
    endianPolicy: 'strict' | 'allow-swapped';
    maxCommandsPerSlice: number;
    maxSlices: number;
    maxFileBytes: number;
    alignmentMaxExponent: number;
    hashAlgorithm: 'sha256';
    pageSizeBytes: number;
  };
  createdAtSeq: number;
  note: string;
}

export interface Decision {
  decisionId: string;
  findingId: string;
  action: 'accept' | 'reject' | 'adjust';
  rationale: string;
  params?: Record<string, unknown>;
  atSeq: number;
  revertedBy?: string;
}

export type EventType =
  | 'PROJECT_CREATED'
  | 'MATERIAL_IMPORTED'
  | 'PARAMS_SET'
  | 'ANALYSIS_RUN_RECORDED'
  | 'FINDING_RAISED'
  | 'DECISION_MADE'
  | 'DECISION_REVERTED'
  | 'BRANCH_CREATED'
  | 'TIMELINE_CHECKOUT';

export interface DomainEvent {
  eventId: string;   // 稳定身份：内容哈希
  seq: number;       // 项目内单调序号
  branch: string;
  type: EventType;
  at: string;        // ISO 时间基准
  payload: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// 导出包：含框架头、manifest 与校验，支持半写恢复。
// ---------------------------------------------------------------------------

export interface ExportBundle {
  frame: 'MTRB';
  frameVersion: 1;
  manifest: {
    projectId: string;
    exportedAt: string;
    eventCount: number;
    headSeq: number;
    contentSha256: string; // 对 canonical(payload) 的摘要
  };
  payload: {
    project: { projectId: string; name: string; createdAt: string };
    events: DomainEvent[];
    materials: Material[];
  };
}
