/**
 * 领域模型：Mach-O 切片证言
 * 所有坐标单位均为容器字节（container bytes），切片内部坐标单独标注 slice-local。
 * 原始层（raw/imported）保留原始表示；本层结构仅做只读描述，规范化在派生层进行。
 */

export type Endian = "big" | "little";

/** 稳定身份：所有可显示对象都携带 id，供 UI 键控与导出往返保持引用。 */
export interface Identified {
  id: string;
}

/** 坐标基准（单位/基准声明），不允许无单位的裸数字进入显示层。 */
export interface CoordinateBasis {
  unit: "byte";
  basis: "container-offset" | "slice-offset" | "blob-offset" | "page-index";
}

export interface ByteRange {
  /** 包含起点，容器字节偏移 */
  start: number;
  /** 不含终点，容器字节偏移；end === start 表示空区间 */
  end: number;
}

export type Severity = "error" | "warning" | "info";

/**
 * 结果三分类：
 * - budget-exhausted 资源预算耗尽（已安全中止，非损坏、非语义矛盾）
 * - corrupt 格式损坏（字节级无法解析）
 * - semantically-unsolvable 语义无解（可解析但无合法唯一/候选决定）
 * - ok / partial 为成功侧结果
 */
export type ResultClass =
  | "ok"
  | "partial"
  | "budget-exhausted"
  | "corrupt"
  | "semantically-unsolvable";

export type FindingCode =
  | "ENDIAN_SWAPPED"
  | "ENDIAN_UNKNOWN"
  | "SLICE_OVERLAP"
  | "ALIGNMENT_OVERFLOW"
  | "ALIGNMENT_ROUNDING_REFUSED"
  | "COMMAND_OUT_OF_BOUNDS"
  | "SIGNATURE_TAIL_GAP"
  | "SIGNATURE_COVERAGE_GAP"
  | "SIGNATURE_HASH_MISMATCH"
  | "UNSUPPORTED_SIGNATURE_FORMAT"
  | "UNKNOWN_BLOB"
  | "ARCH_DUPLICATE"
  | "ARCH_POLICY_AMBIGUOUS"
  | "BUDGET_EXHAUSTED"
  | "RAW_PARSE_CORRUPT";

/** 带位置的诊断：输入不完整/不可转换时返回位置，禁止空值伪装成功。 */
export interface Diagnostic {
  code: FindingCode;
  severity: Severity;
  message: string;
  /** 字节坐标（容器偏移），可附带 slice/blob 基准 */
  location?: {
    offset: number;
    basis: CoordinateBasis["basis"];
    sliceId?: string;
  };
  /** 失败字节证据：最多保留 16 个原始字节（hex）与期望 */
  evidence?: FailureBytes;
}

export interface FailureBytes {
  actual: number[];
  expected?: number[];
  /** 证据取自的区间（容器坐标） */
  range: ByteRange;
}

export interface Finding extends Diagnostic {
  id: string;
  affected: string[];
}

export interface FatHeader {
  id: string;
  magic: number;
  magicHex: string;
  declaredEndian: Endian;
  nfatArch: number;
  /** 原始 4 字节（hex，原始表示保留） */
  rawMagic: string;
  /** 32 位 fat_arch 或 64 位 fat_arch_64 */
  flavor: "fat32" | "fat64";
  rawBytes: string;
  range: ByteRange;
}

export interface SliceDescriptor extends Identified {
  index: number;
  cputype: number;
  cpusubtype: number;
  archName: string;
  offset: number;
  size: number;
  align: number;
  /** align 的 2^align 计算结果（byte），不做四舍五入修正 */
  alignmentBytes: number;
  /** align 字段原始 32 位大端值（原始表示） */
  rawAlign: number;
  endian: Endian;
  range: ByteRange;
  /** 描述符表项在 fat 容器中的字节范围 */
  descriptorRange: ByteRange;
  /** slice magic 原始 4 字节（hex） */
  rawMagic: string;
}

export interface LoadCommandView extends Identified {
  index: number;
  cmd: number;
  cmdHex: string;
  cmdsize: number;
  name: string;
  range: ByteRange;
  /** 越界命令仍保留：outOfBounds=true 时 range 为其声明想要的区间 */
  outOfBounds: boolean;
  segmentName?: string;
  isCodeSignature: boolean;
}

export interface CodeSignatureRef extends Identified {
  /** LC_CODE_SIGNATURE 的 dataoff / datasize（slice-local，原始表示） */
  dataoff: number;
  datasize: number;
  /** 容器坐标 */
  range: ByteRange;
  /** 顶层 SuperBlob 声明 */
  magic: number;
  magicHex: string;
  length: number;
  blobCount: number;
  rawMagic: string;
}

export interface CodeSlotView extends Identified {
  /** 特殊槽位为负数：0 => Info, -1 => Requirements, -2 => Resources, -3 => Application, -4 => Entitlement */
  slot: number;
  kind: "code" | "special";
  hashHex: string;
  expectedHex?: string;
  match: boolean | null;
  pageIndex?: number;
  pageRange?: ByteRange;
}

export interface BlobIndexEntry extends Identified {
  type: number;
  typeName: string;
  offset: number;
  length: number;
  range: ByteRange;
  known: boolean;
}

export interface SignatureView extends Identified {
  sliceId: string;
  ref: CodeSignatureRef;
  blobs: BlobIndexEntry[];
  slots: CodeSlotView[];
  /** 覆盖带：按容器字节区间标注 covered / uncovered / tail-gap */
  coverage: CoverageBand[];
  /** SuperBlob 长度未覆盖 slice 尾部等问题的结构化标记 */
}

export type CoverageKind =
  | "code-covered"
  | "signature-blob"
  | "uncovered"
  | "tail-gap";

export interface CoverageBand {
  id: string;
  kind: CoverageKind;
  range: ByteRange;
  label: string;
  slotId?: string;
}

export interface ParsedSlice extends Identified {
  descriptor: SliceDescriptor;
  machMagic: number;
  machMagicHex: string;
  commands: LoadCommandView[];
  signature: SignatureView | null;
  /** slice 内 ncmds / sizeofcmds（原始表示） */
  ncmds: number;
  sizeofcmds: number;
}

export interface ParseResult {
  resultClass: ResultClass;
  containerSize: number;
  fat: FatHeader | null;
  slices: ParsedSlice[];
  findings: Finding[];
  /** 预算耗尽时记录已消耗预算 */
  budget?: { bytesScanned: number; limit: number };
}

/** 目标架构策略（可修改决定层），按 (cputype,cpusubtype) 匹配 slice。 */
export interface ArchPolicy {
  id: string;
  version: number;
  preferredCpuType: number;
  preferredCpuSubtype: number;
  /** 未知 blob 是否按错误处理（v1=false，参数修订后可为 true） */
  unknownBlobIsError: boolean;
  /** 扫描预算（字节），触发 budget-exhausted */
  scanBudgetBytes: number;
}

/** 派生结果记录输入摘要、参数版本、父级依赖（事件溯源中持久化）。 */
export interface DerivationResult {
  id: string;
  parentEventId: string | null;
  inputDigest: string;
  policyVersion: number;
  computedAt: string;
  parse: ParseResult;
  /** 策略选择结论：合法候选全部保留，无法唯一决定时不自动选择 */
  selection: {
    matchedSliceId: string | null;
    candidates: string[];
    decided: boolean;
    reason: string;
  };
  findings: Finding[];
  resultClass: ResultClass;
}

export interface MaterialRef {
  /** 来源材料身份 */
  materialId: string;
  /** 材料内片段身份（如 slice-id / command-id / blob-index） */
  fragmentId?: string;
  /** 原始字节区间（容器坐标） */
  range: ByteRange;
}

export type EventType =
  | "session-created"
  | "material-imported"
  | "derivation-computed"
  | "parameter-revised"
  | "source-amended"
  | "decision"
  | "branch-created"
  | "snapshot-restored";

export type DecisionValue = "accept" | "reject" | "adjust";

export interface SessionEvent {
  id: string;
  sessionId: string;
  branchId: string;
  seq: number;
  type: EventType;
  at: string;
  /** 机器可读判断依据（规则代码、输入摘要、受影响对象） */
  payload: Record<string, unknown>;
  /** 输入摘要 / 参数版本 / 父依赖 */
  inputDigest?: string;
  policyVersion?: number;
  parentEventId?: string | null;
}
