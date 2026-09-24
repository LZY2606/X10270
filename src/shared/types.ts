/**
 * 领域模型：Mach-O universal（fat）容器切片证言。
 *
 * 分层原则：
 *  - Raw*  = 不可变材料：直接来自字节的原始表示（含字节序、字段宽度、原始摘要）。
 *  - Qty   = 带单位/坐标基准的领域量；派生层才做规范化。
 *  - Derived = 可重算结果：记录输入摘要、参数版本与父级依赖。
 * 所有身份（sid）在导入时即确定，导出再导入保持不变。
 */

export type Unit =
  | 'byte'          // 文件/切片文件坐标，基数 0
  | 'slice-byte'    // 切片内坐标，基数 0（slice offset 处 = 0）
  | 'pow2-unit'     // align 字段：2^align 字节
  | 'page'          // code slot 坐标：页大小 2^pageSize 字节
  | 'hex16'         // 十六进制原始词
  | 'sha256-hex';   // 摘要表示

export interface Qty {
  /** 规范化后的数值（无法转换时为 null，保留 raw） */
  value: number | null;
  unit: Unit;
  /** 坐标基准描述，例如 'file-base0' / 'slice-base0:<sid>' */
  basis: string;
  /** 原始表示，逐字节保留 */
  raw: { repr: string; widthBytes: number; endian: Endian };
}

export type Endian = 'be' | 'le';
export type ByteWidth = 32 | 64;

export interface Positioned {
  /** 带位置的诊断坐标：文件绝对偏移（base 0） */
  at: number;
  /** 所在材料路径，便于回溯输入片段 */
  path: string;
}

export type Severity = 'info' | 'warning' | 'error' | 'fatal';

/** 三种必须可区分的终局，加上 ok 与被规则拒绝 */
export type Verdict =
  | 'ok'
  | 'rejected'           // 规则确定性拒绝（可直接复核）
  | 'budget_exhausted'   // 资源预算耗尽（对齐溢出/计数越界）
  | 'corrupt'            // 格式损坏（无法解析/不支持格式）
  | 'unsolvable';        // 语义无解：存在多个合法候选，必须人工决定

/** 机器可读判定事件 code（判定依据，不只是日志） */
export type FindingCode =
  // fat / 字节序
  | 'FAT_MAGIC_SWAPPED'        // 仅整体交换：可识别但来源字节序与声明相反
  | 'FAT_MAGIC_UNKNOWN'        // 魔数未知
  | 'FAT_NFAT_OVERFLOW'        // nfat_arch 超出容器/预算
  | 'FAT_ARCH_ENTRY_OOB'       // fat_arch 条目超出文件
  // slice
  | 'SLICE_OUT_OF_FILE'        // 切片数据越出容器
  | 'SLICE_OVERLAP'            // slice 范围重叠（禁止四舍五入/吸附修正）
  | 'SLICE_ALIGN_OVERFLOW'     // 对齐溢出：2^align 超过预算/文件
  | 'SLICE_MISALIGNED'         // offset 未满足 align（禁止四舍五入修正）
  | 'SLICE_DUP_ARCH'           // 多架构同名
  // mach / load commands
  | 'MACHO_MAGIC_UNKNOWN'
  | 'LC_RANGE_TRUNCATED'       // load command 头部声明超出切片
  | 'CMD_OUT_OF_BOUNDS'        // 单条 command 越界
  | 'CMD_ZERO_SIZE'
  | 'LINKEDIT_NOT_COVERING_SIG'
  // code signature
  | 'LC_CODE_SIGNATURE_MISSING'
  | 'SIG_BLOB_UNKNOWN_MAGIC'   // 未知 blob（不支持格式的子类，仍保留候选）
  | 'SIG_BLOB_UNSUPPORTED_TYPE'
  | 'SIG_BLOB_TRUNCATED'
  | 'SIG_COVERAGE_GAP'         // 覆盖缺口（未覆盖尾部，区别于 hash 不匹配）
  | 'SIG_CODELIMIT_BEYOND_SLICE'
  | 'SIG_HASH_MISMATCH'        // 原始摘要保留，与重算摘要并列
  | 'SIG_SLOT_ABSENT'
  | 'STRATEGY_ARCH_MISSING'
  | 'STRATEGY_DUPLICATE_TARGET';

export interface Finding {
  code: FindingCode;
  severity: Severity;
  verdict: Exclude<Verdict, 'ok'>;
  message: string;
  /** 受影响对象的稳定身份 */
  subjects: string[];
  /** 输入片段证据（文件坐标区间） */
  evidence?: { start: number; end: number; basis: 'file-base0'; hex: string }[];
  position?: Positioned;
  /** 无法唯一决定时保留的全部合法候选 */
  candidates?: { sid: string; label: string }[];
  /** 机器可读判定依据：触发该结论的规则表达式 */
  rationale: string;
}

/** 稳定身份的原始字段 */
export interface RawField {
  sid: string;
  name: string;
  qty: Qty;
  /** 原始字节在文件中的区间（base 0），用于失败字节证据 */
  fileRange: { start: number; end: number };
}

export interface FatHeader {
  sid: string;
  magic: RawField;          // 0xCAFEBABE 等，原始字节序保留
  nfatArch: RawField;
  declaredEndian: Endian;
  sourceEndian: Endian;
  fields: RawField[];
  range: { start: number; end: number };
}

export interface FatArchEntry {
  sid: string;
  /** fat_arch 表中的原始下标（0 起） */
  index: number;
  cputype: RawField;
  cpusubtype: RawField;
  offset: RawField;
  size: RawField;
  align: RawField;         // 2^align
  reserved: RawField;
  range: { start: number; end: number };
}

export interface LoadCommand {
  sid: string;
  index: number;
  cmd: RawField;
  cmdsize: RawField;
  /** 解析出的语义（可能为 null：未知 command 仍保留） */
  kind:
    | 'LC_SEGMENT_64'
    | 'LC_SEGMENT'
    | 'LC_CODE_SIGNATURE'
    | 'LC_SYMTAB'
    | 'LC_DYSYMTAB'
    | 'LC_UUID'
    | 'LC_UNKNOWN'
    | null;
  segmentName?: string;
  /** command 在切片内的区间（slice-base0）与文件区间 */
  sliceRange: { start: number; end: number };
  fileRange: { start: number; end: number };
  /** LC_CODE_SIGNATURE 的 dataoff/datasize（slice-base0） */
  signature?: { dataoff: RawField; datasize: RawField };
  /** LC_SEGMENT_64 的 fileoff/filesize（slice-base0） */
  segment?: { fileoff: RawField; filesize: RawField; vmaddr: RawField; vmsize: RawField };
}

export interface CodeSlot {
  sid: string;
  index: number;
  pageStart: number;   // slice-base0
  pageEnd: number;
  /** blob 中保存的原始摘要（原始表示保留） */
  storedDigest: RawField;
  /** 重算摘要（派生层）；null 表示尚未计算或无法计算 */
  computedDigestHex: string | null;
  match: boolean | null;
}

export interface SignatureBlob {
  sid: string;
  magic: RawField;             // 0xfade0cc0 = EMBEDDED_SIGNATURE
  length: RawField;
  count: RawField;
  blobType: RawField;         // 0 => CodeDirectory
  sliceRange: { start: number; end: number };
  fileRange: { start: number; end: number };
  codeDirectory: {
    sid: string;
    magic: RawField;
    length: RawField;
    hashType: RawField;       // 1 = SHA-256
    pageSize: RawField;       // 2^pageSize
    hashOffset: RawField;
    identOffset: RawField;
    codeLimit: RawField;      // 被签名字节覆盖长度（slice-base0）
    rawFields: RawField[];
    sliceRange: { start: number; end: number };
  } | null;
  slots: CodeSlot[];
  known: boolean;
}

export interface MachSlice {
  sid: string;
  fatIndex: number;
  arch: { cputype: number; cpusubtype: number; label: string };
  machMagic: RawField;
  declaredEndian: Endian;
  sourceEndian: Endian;
  width: ByteWidth;
  ncmds: RawField;
  sizeofcmds: RawField;
  /** load commands 表整体区间（slice-base0） */
  lcTableRange: { start: number; end: number };
  commands: LoadCommand[];
  signature: SignatureBlob | null;
  sliceRange: { start: number; end: number }; // 文件坐标
  fields: RawField[];
}

export interface ParsedContainer {
  sid: string;
  byteLength: number;
  fat: FatHeader;
  archEntries: FatArchEntry[];
  slices: MachSlice[];
  /** 解析期发现（格式/边界），判定依据见 rationale */
  findings: Finding[];
  /** 所有 RawField 的扁平索引，UI“每个显示值带稳定身份” */
  fields: RawField[];
}

/** 规则参数版本（参数修订即新版本，不覆盖旧值） */
export interface RuleParamsV1 {
  version: number;
  targetArchitectures: { cputype: number; cpusubtype: number; label: string; policy: 'exactly-one' | 'at-most-one' }[];
  maxSlices: number;
  maxFatArchBytes: number;      // 预算：fat 表最大字节
  maxAlignExponent: number;     // 预算：2^align 不得超过文件/预算
  requireCodeSignature: boolean;
  supportedHashTypes: number[];
  supportedBlobMagics: number[];
  hashAlgorithm: 'sha256';
  pageSizeFallback: number;     // 仅当字段无法读取时诊断使用，不用于静默修正
  /** 等价输入的稳定排序键 */
  canonicalOrder: 'offset-then-cpu';
}

export type RuleParams = RuleParamsV1;

export interface InputDigest {
  sha256: string;
  byteLength: number;
}

/** 派生结果：记录输入摘要、参数版本、父级依赖 */
export interface Derivation {
  sid: string;
  kind:
    | 'container-review'
    | 'slice-review'
    | 'lc-table-review'
    | 'signature-review'
    | 'slot-review'
    | 'strategy-review'
    | 'counterexample';
  parentSids: string[];
  inputDigest: InputDigest;
  paramsVersion: number;
  ruleVersion: string;
  findings: Finding[];
  verdict: Verdict;
  /** 规范化派生量（与原始 RawField 并列展示，不替换） */
  normalized: Record<string, { value: number; unit: Unit; basis: string }>;
  /** 被采纳/未采纳标记（反例档案两者都保留） */
  adopted: boolean;
  supersededBy: string | null;
  /** 无法转换/无法唯一决定时的候选（不丢弃） */
  unresolved: Finding[];
  computedAtRevision: number;
}

export interface Decision {
  sid: string;
  revision: number;
  action: 'accept' | 'reject' | 'param-adjust' | 'choose-candidate';
  subjectSids: string[];
  note: string;
  /** 冲突决定：选择了哪个候选；未选择时全部候选保留 */
  chosenCandidateSid: string | null;
}

export type EventType =
  | 'material/import'
  | 'params/set'
  | 'derivation/recorded'
  | 'decision/made'
  | 'branch/created';

export interface TimelineEvent {
  sid: string;
  seq: number;
  revision: number;
  branch: string;
  type: EventType;
  atIsoUtc: string;
  payload: unknown;
  /** 该事件之后的可见结论快照摘要（不覆盖历史，仅冗余便于时间旅行） */
  verdictAfter: Verdict | null;
  parentEventSids: string[];
}

export interface Project {
  sid: string;
  name: string;
  createdAtIsoUtc: string;
  branches: string[];
}

/** 导出包：身份、顺序、来源关系自描述 */
export interface ExportBundle {
  format: 'macho-slice-testimony/v1';
  exportedAtIsoUtc: string;
  project: Project;
  events: TimelineEvent[];
  materials: Record<string, {
    sid: string;
    name: string;
    inputDigest: InputDigest;
    /** base64 原始字节：不可变材料完整保留 */
    bytesBase64: string;
    importedAs: string;
  }>;
  /** 反例档案：采纳与未采纳结果都在事件流中，这里提供目录 */
  counterexamples: { mutation: string; derivationSid: string; adopted: boolean }[];
  casepackVersion: string;
}
