// ---------- 领域基础类型：所有坐标均显式标注基准 ----------

export type Endianness = 'big' | 'little';
export type CoordinateBase = 'file' | 'slice';
export type Unit = 'byte' | 'page' | 'power2' | 'dimensionless';

export interface Quant {
  value: number;
  unit: Unit;
  base: CoordinateBase | 'na';
  raw: string; // 原始表示（十六进制/十进制原样保留）
}

export type VerdictStatus =
  | 'ok'
  | 'integrity_failed'
  | 'format_corrupt'
  | 'semantically_unsolvable'
  | 'budget_exhausted';

export interface Diagnostic {
  code: string;
  message: string;
  path: string; // 字段路径，例如 fat_arch[1].offset
  offset?: number; // 字节坐标
  base?: CoordinateBase;
  length?: number;
  expected?: string;
  actual?: string;
}

export interface EvidenceRange {
  id: string;
  coord: CoordinateBase;
  offset: number; // 字节
  length: number; // 字节
  hex: string;
  note: string;
}

export type CheckOutcome =
  | 'pass'
  | 'fail'
  | 'coverage_gap'
  | 'hash_mismatch'
  | 'unsupported_format'
  | 'ambiguous'
  | 'skipped_budget';

export interface CheckResult {
  id: string; // 稳定身份：materialDigest:check[:subject]
  check:
    | 'fat_endianness'
    | 'fat_slice_bounds'
    | 'slice_alignment'
    | 'slice_overlap'
    | 'arch_name_resolution'
    | 'mach_header'
    | 'load_command_bounds'
    | 'signature_blob_format'
    | 'signature_code_slots'
    | 'signature_coverage';
  outcome: CheckOutcome;
  subjects: string[];
  message: string;
  diagnostic?: Diagnostic;
  evidence: EvidenceRange[];
}

export interface Budget {
  maxBytes: number;
  maxCommands: number;
}

export interface BudgetUse {
  consumedBytes: number;
  consumedCommands: number;
}

export interface ArchPolicy {
  targetArch: string;
  strictAlignment: boolean;
  requireSignature: boolean;
  budget: Budget;
  notes?: string;
}

export interface RawLoadCommand {
  id: string;
  index: number;
  cmd: number;
  cmdName: string;
  cmdsize: number;
  relStart: number; // slice 相对字节
  relEnd: number;
  fileStart: number;
  fileEnd: number;
  inBounds: boolean;
  detail: Record<string, string>;
}

export interface CodeSlot {
  id: string;
  index: number;
  relStart: number;
  relEnd: number;
  fileStart: number;
  fileEnd: number;
  expectedDigest: string;
  actualDigest: string;
  digestAlgo: 'sha1' | 'sha256' | 'unknown';
  matches: boolean;
}

export interface SigBlobIndex {
  slotType: number;
  offset: number;
  blobMagic: number;
  magicHex: string;
  supported: boolean;
  length: number;
}

export interface RawSignature {
  dataoff: number;
  datasize: number;
  magic: number;
  count: number;
  blobs: SigBlobIndex[];
  codeDirectory?: {
    version: number;
    flags: number;
    hashType: number;
    hashSize: number;
    pageSize: number;
    nCodeSlots: number;
    nSpecialSlots: number;
    codeLimit: number;
    ident: string;
  };
  slots: CodeSlot[];
}

export interface RawSlice {
  id: string;
  index: number;
  cputype: number;
  cpusubtype: number;
  archName: string;
  offset: number;
  size: number;
  alignExp: number;
  alignBytes: number;
  reserved: number;
  headerEndian: Endianness | null;
  ncmds: number | null;
  sizeofcmds: number | null;
  filetype: number | null;
  commands: RawLoadCommand[];
  signature: RawSignature | null;
  parseError?: string;
}

export interface RawFatHeader {
  magicHex: string;
  kind: 'fat' | 'fat64';
  endian: Endianness;
  nfatArch: number;
  headerBytesHex: string;
  headerLength: number;
}

export interface ArchCandidate {
  archName: string;
  sliceIds: string[];
  resolvable: boolean;
  reason: string;
}

export interface Evaluation {
  materialDigest: string;
  paramVersion: number;
  status: VerdictStatus;
  fatHeader: RawFatHeader | null;
  slices: RawSlice[];
  checks: CheckResult[];
  candidates: ArchCandidate[];
  diagnostics: Diagnostic[];
  budgetUse: BudgetUse;
  budget: Budget;
  stoppedAt?: number; // budget 中止时的字节坐标
}
