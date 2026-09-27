// 核心领域类型：Universal Mach-O / fat 容器 / load command / 代码签名覆盖
// 所有领域量都携带单位或坐标基准（offset/byte 坐标，align 以 2^n 字节计）。

export type ByteOrder = 'big-endian' | 'little-endian';

/** 三种语义上严格区分的结果 */
export type OutcomeClass =
  | 'ok'
  | 'budget-exhausted' // 资源预算耗尽
  | 'format-corrupt' // 格式损坏
  | 'semantic-unresolvable'; // 语义无解（存在多个合法候选，无法唯一决定）

/** 规则标识（7 个边界情形 + 基础完整性） */
export type RuleId =
  | 'fat-magic-endianness'
  | 'slice-range-no-overlap'
  | 'slice-alignment-no-rounding'
  | 'load-command-in-bounds'
  | 'signature-covers-tail'
  | 'multi-arch-unique-name'
  | 'known-signature-blob'
  | 'resource-budget';

export type Severity = 'info' | 'warning' | 'error';

/** 带位置的诊断；输入不完整时不得用空值/默认值伪装成功 */
export interface Diagnostic {
  code: string;
  message: string;
  severity: Severity;
  /** 字节坐标基准（slice 内或 fat 文件内） */
  at?: { base: 'fat' | `slice:${string}`; offset: number; length?: number };
  /** 原始表示（未规范化），无法转换时留在原位置 */
  raw?: string;
  rule?: RuleId;
}

/** 原始标量：保留导入时的原始表示，派生层才做规范化 */
export interface RawScalar {
  raw: string; // 原文，例如 "0xCAFEBABE" / "0x1000" / "14"
  /** 解释成的数值；无法转换时为 null 并附诊断 */
  value: number | null;
  unit: string; // 例如 "bytes" / "2^n bytes" / "count" / "enum"
  note?: string;
}

export interface FatHeader {
  identity: string; // 稳定身份
  magic: RawScalar; // 0xCAFEBABE(fat32) / 0xCAFEBABF(fat64)
  byteOrder: ByteOrder;
  isFat64: boolean;
  nfatArch: RawScalar;
  /** fat header 自身字节坐标范围 */
  range: { start: number; end: number; unit: 'bytes'; base: 'fat' };
}

export interface Slice {
  identity: string; // 稳定身份：slice:<cputype>:<cpusubtype>:<index>
  index: number;
  cputype: RawScalar;
  cpusubtype: RawScalar;
  archName: string; // 派生显示名，例如 arm64 / x86_64
  offset: RawScalar; // slice 在 fat 文件中的字节偏移
  size: RawScalar; // slice 字节长度
  align: RawScalar; // 2^align 字节对齐
  /** 期望对齐边界（2^align），用于重叠/对齐判定，不做四舍五入修正 */
  expectedAlignmentBytes: number | null;
  range: { start: number; end: number; unit: 'bytes'; base: 'fat' } | null;
  endiannessOfMachHeader: ByteOrder | null;
}

export interface LoadCommand {
  identity: string; // 稳定身份：lc:<sliceIndex>:<ordinal>
  ordinal: number;
  cmd: RawScalar;
  cmdName: string;
  cmdsize: RawScalar;
  range:
    | { start: number; end: number; unit: 'bytes'; base: `slice:${number}` }
    | null;
}

export interface CodeSlot {
  identity: string; // codeslot:<sliceIndex>:<index>
  index: number;
  offset: number; // 在 slice 内的字节坐标
  length: number;
  /** 原始摘要（导入即保留，不重算覆盖） */
  digest: string;
  algo: string;
  /** 该 code slot 覆盖的 slice 字节区间（页/chunk 坐标基准） */
  covers: { start: number; end: number; base: `slice:${number}`; unit: 'bytes' };
  /** 实测摘要（派生层重算），与原始摘要比对 */
  measuredDigest?: string;
}

export type BlobKind =
  | 'CodeDirectory'
  | 'Requirements'
  | 'Entitlements'
  | 'CmsSignature'
  | 'EntitlementsDer'
  | 'Unknown';

export interface SignatureBlob {
  identity: string; // blob:<sliceIndex>:<index>
  index: number;
  type: RawScalar; // magic/type，例如 CSMAGIC_CODEDIRECTORY
  kind: BlobKind;
  offset: number; // slice 内字节坐标
  length: number;
  range: { start: number; end: number; unit: 'bytes'; base: `slice:${number}` };
  supported: boolean;
}

export interface SliceSignatures {
  /** LC_CODE_SIGNATURE 指向的 super blob 区间（slice 坐标） */
  superBlobRange: { start: number; end: number; base: `slice:${number}`; unit: 'bytes' };
  blobs: SignatureBlob[];
  codeSlots: CodeSlot[];
}

/** 一条判定结果（结构化状态，而非仅日志） */
export interface Finding {
  identity: string; // finding:<eventSeq> 稳定
  rule: RuleId;
  severity: Severity;
  outcome: OutcomeClass;
  status: 'accepted' | 'rejected' | 'candidate';
  subject: string; // 受影响对象身份
  message: string;
  /** 失败字节证据（坐标 + 字节 hex + 期望/实际） */
  evidence?: FailureByteEvidence;
  candidates?: string[]; // 无法唯一决定时保留全部合法候选
  diagnostics: Diagnostic[];
}

export interface FailureByteEvidence {
  base: 'fat' | `slice:${number}`;
  start: number;
  end: number;
  unit: 'bytes';
  actualHex: string;
  expectedHex?: string;
  label: string;
}

/** 不可变材料版本 */
export interface MaterialVersion {
  identity: string;
  kind:
    | 'fat-header'
    | 'slice-table'
    | 'mach-header'
    | 'load-commands'
    | 'signature-superblob'
    | 'code-slots'
    | 'raw-digests';
  sourceDigest: string; // 输入摘要
  createdAtEventSeq: number;
}

/** 参数集（目标架构策略等，可修订） */
export interface ParameterSet {
  version: number;
  identity: string;
  /** 目标架构策略：允许的架构名顺序（等价输入得到稳定顺序） */
  targetArchPolicy: string[];
  maxSliceCount: number; // 资源预算
  maxFileBytes: number;
  pageSizeBytes: number; // code slot 分页基准
  note: string;
}

export type DecisionKind = 'accept' | 'reject' | 'parameter-revision';

export interface Decision {
  identity: string;
  kind: DecisionKind;
  atEventSeq: number;
  subject?: string;
  rationale: string;
  /** 互相冲突的人工决定：记录被覆盖的前序决定身份 */
  supersedes?: string;
  parameterVersion?: number;
}

/** 机器可读取事件：判断依据写成事件 */
export interface ReviewEvent {
  seq: number;
  identity: string; // evt:<session>:<seq> 稳定
  type:
    | 'import'
    | 'derive'
    | 'rule-evaluation'
    | 'decision'
    | 'parameter-revision'
    | 'source-mutation'
    | 'export'
    | 'replay-checkpoint';
  rule?: RuleId;
  title: string;
  timestamp: string;
  inputDigest: string; // 输入摘要
  parameterVersion: number;
  parentDeps: string[]; // 父级依赖（事件身份 / 材料版本身份）
  materialVersions: string[];
  finding?: Finding;
  decision?: Decision;
  payload?: Record<string, unknown>;
}

/** 反例档案：被采纳与未采纳的结果都保留 */
export interface CounterexampleArchive {
  mutationId: MutationId;
  baselineInputDigest: string;
  mutatedSource: string; // 被改动的那一个直接来源
  expectedRule: RuleId;
  findings: Finding[];
  adopted: Finding['identity'][];
  notAdopted: Finding['identity'][];
  containedScope: string[]; // 影响被限制在正确范围内的对象身份
}

export type MutationId =
  | 'endianness-flip'
  | 'slice-overlap'
  | 'alignment-overflow'
  | 'command-out-of-bounds'
  | 'signature-tail-gap'
  | 'multi-arch-same-name'
  | 'unknown-blob';

export interface ReviewSession {
  identity: string;
  name: string;
  createdAt: string;
  /** 不可变材料：原始字节（导出往返保留） */
  rawBytesBase64: string;
  byteLength: number;
  fatHeader: FatHeader | null;
  slices: Slice[];
  loadCommands: LoadCommand[];
  signatures: SliceSignatures[];
  materials: MaterialVersion[];
  parameters: ParameterSet[];
  events: ReviewEvent[];
  decisions: Decision[];
  findings: Finding[];
  archives: CounterexampleArchive[];
  diagnostics: Diagnostic[];
  outcome: OutcomeClass;
}
