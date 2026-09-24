/**
 * 领域类型：Mach-O 切片证言。
 *
 * 约定：
 * - 所有坐标/长度都显式携带单位与基准（文件坐标、切片坐标、superblob 坐标）。
 * - 导入层保留原始表示（hex、原始字节序、无法映射的原始数值），派生层才做规范化。
 * - 无法转换的值留在原位置，并附 diagnostic，而不是用空值/默认值伪装成功。
 */

export type Endian = "big" | "little";
export type ByteUnit = "byte";
export type CoordinateBasis = "file" | "slice" | "superblob" | "codedirectory";

export interface Coord {
  value: number;
  unit: ByteUnit;
  basis: CoordinateBasis;
  /** 原始表示，例如十六进制字符串 "0x1000" / 原始大端读取文本 */
  raw: string;
}

export interface Diagnostic {
  code: string;
  message: string;
  /** 出错位置（字节偏移，带基准） */
  offset?: Coord;
}

/** 派生值附带原始表示与可选诊断（无法转换时 value=null，诊断留在原地） */
export interface Derived<T> {
  raw: string;
  value: T | null;
  diagnostic?: Diagnostic;
}

// ---- Mach-O 常量 ---------------------------------------------------------

export const FAT_MAGIC = 0xcafebabe;
export const FAT_MAGIC_64 = 0xcafebabf;
export const FAT_CIGAM = 0xbebafeca;
export const FAT_CIGAM_64 = 0xbfbafeca;

export const MH_MAGIC = 0xfeedface;
export const MH_CIGAM = 0xcefaedfe;
export const MH_MAGIC_64 = 0xfeedfacf;
export const MH_CIGAM_64 = 0xcffaedfe;

export const LC_SEGMENT = 0x00000001;
export const LC_SEGMENT_64 = 0x00000019;
export const LC_CODE_SIGNATURE = 0x0000001d;
export const LC_ENCRYPTION_INFO_64 = 0x0000002c;

export const CSMAGIC_EMBEDDED_SIGNATURE = 0xfade0cc0;
export const CSMAGIC_CODEDIRECTORY = 0xfade0c02;
export const CSMAGIC_REQUIREMENTS = 0xfade0c01;
export const CSMAGIC_BLOBWRAPPER = 0xfade0b01;

export const CSSLOT_CODEDIRECTORY = 0;

export const CPU_TYPE_NAMES: Record<number, string> = {
  0x00000007: "i386",
  0x01000007: "x86_64",
  0x0000000c: "arm",
  0x0100000c: "arm64",
  0x01000013: "arm64-32"
};

export const LOAD_COMMAND_NAMES: Record<number, string> = {
  [LC_SEGMENT]: "LC_SEGMENT",
  [LC_SEGMENT_64]: "LC_SEGMENT_64",
  [LC_CODE_SIGNATURE]: "LC_CODE_SIGNATURE",
  [LC_ENCRYPTION_INFO_64]: "LC_ENCRYPTION_INFO_64",
  0x00000002: "LC_SYMTAB",
  0x0000000b: "LC_DYSYMTAB",
  0x0000000d: "LC_LOAD_DYLIB",
  0x0000001e: "LC_SEGMENT_SPLIT_INFO",
  0x80000022: "LC_UUID",
  0x80000026: "LC_DYLD_INFO_ONLY",
  0x85: "LC_MAIN",
  0x80000028: "LC_FUNCTION_STARTS",
  0x80000029: "LC_DATA_IN_CODE",
  0x8000001a: "LC_DYLD_INFO",
  0x1b: "LC_LOAD_DYLINKER",
  0x00000032: "LC_BUILD_VERSION",
  0x80000005: "LC_RPATH"
};

export const HASH_TYPE_NAMES: Record<number, string> = {
  1: "sha1",
  2: "sha256",
  3: "sha256-truncated",
  4: "sha1-sha256"
};

// ---- 解析结果 ------------------------------------------------------------

export type ParseStatus =
  | { status: "ok" }
  | { status: "corrupt_format"; diagnostic: Diagnostic }
  | { status: "budget_exhausted"; diagnostic: Diagnostic };

export interface FatHeaderView {
  magic: Derived<number>;
  endian: Endian;
  is64: boolean;
  nfatArch: Derived<number>;
  /** 原始字节（fat header 与全部 arch 表项） */
  rawHex: string;
}

export interface FatSliceView {
  index: number;
  cputype: Derived<number>;
  cpusubtype: Derived<number>;
  archName: Derived<string>;
  offset: Coord;
  size: Coord;
  /** align 是 2^alignExponent 的指数；绝不四舍五入修正 */
  alignExponent: Derived<number>;
  alignment: Derived<number>;
  rawHex: string;
}

export interface MachHeaderView {
  magic: Derived<number>;
  endian: Endian;
  is64: boolean;
  filetype: Derived<number>;
  ncmds: Derived<number>;
  sizeofcmds: Derived<number>;
  rawHex: string;
}

export interface LoadCommandView {
  index: number;
  cmd: Derived<number>;
  cmdName: Derived<string>;
  cmdsize: Derived<number>;
  /** 切片坐标下的命令区间 */
  start: Coord;
  end: Coord;
  /** LC_CODE_SIGNATURE 专有：链接编辑数据（切片坐标） */
  codeSignature?: { dataoff: Coord; datasize: Coord };
  rawHex: string;
}

export interface CodeSlotView {
  index: number;
  /** code directory 内槽位偏移 */
  slotOffset: Coord;
  /** 覆盖的切片字节区间 */
  coveredStart: Coord;
  coveredEnd: Coord;
  expectedDigest: string;
  actualDigest: string | null;
  rawHex: string;
}

export interface CodeDirectoryView {
  magic: Derived<number>;
  hashType: Derived<number>;
  hashName: Derived<string>;
  hashSize: Derived<number>;
  pageSize: Derived<number>;
  nCodeSlots: Derived<number>;
  codeLimit: Coord;
  hashOffset: Coord;
  rawHex: string;
}

export interface SigBlobView {
  superIndex: number;
  slotType: number;
  magic: Derived<number>;
  /** superblob 坐标 */
  offset: Coord;
  length: Coord;
  codeDirectory?: CodeDirectoryView;
  slots?: CodeSlotView[];
  rawHex: string;
}

export interface SignatureView {
  /** LC_CODE_SIGNATURE 指向的切片坐标区间 */
  dataoff: Coord;
  datasize: Coord;
  superMagic: Derived<number>;
  count: Derived<number>;
  blobs: SigBlobView[];
  rawHex: string;
}

export interface SliceView {
  id: string;
  fat: FatSliceView;
  header: MachHeaderView | null;
  commands: LoadCommandView[];
  signature: SignatureView | null;
  parseDiagnostic?: Diagnostic;
}

export interface FatContainer {
  /** 输入材料 sha256，稳定身份 */
  inputDigest: string;
  totalSize: Coord;
  header: FatHeaderView;
  slices: SliceView[];
}

export interface ParseBudget {
  maxSlices: number;
  maxCommandsPerSlice: number;
  maxHashBytes: number;
}

export const DEFAULT_BUDGET: ParseBudget = {
  maxSlices: 64,
  maxCommandsPerSlice: 512,
  maxHashBytes: 64 * 1024 * 1024
};
