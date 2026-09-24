export type Endianness = 'le' | 'be';
export type CoordBasis = 'file' | 'slice' | 'blob';
export type Severity = 'error' | 'warning' | 'info';

/** 诊断：永远携带位置（偏移 + 坐标基准），不可用空值伪装成功。 */
export interface Diagnostic {
  code: string;
  message: string;
  severity: Severity;
  offset?: number;
  basis?: CoordBasis;
  raw?: string;
}

/** 领域量：导入时保留原始表示，派生层才规范化；无法转换时 value 为 null 并附诊断。 */
export interface Quantity {
  raw: string;
  value: number | null;
  unit: 'byte' | 'pageshift' | 'count';
  basis: CoordBasis;
  diagnostic?: Diagnostic;
}

export interface Budget {
  maxSlices: number;
  maxCommands: number;
  maxPages: number;
}

export const DEFAULT_BUDGET: Budget = { maxSlices: 64, maxCommands: 512, maxPages: 65536 };

export class BudgetExhausted extends Error {
  constructor(public what: string) {
    super(`resource budget exhausted: ${what}`);
    this.name = 'BudgetExhausted';
  }
}

/** 三种必须区分的结果类别 */
export type FailureKind =
  | 'resource_exhausted'
  | 'format_corrupt'
  | 'semantic_unsolvable';

export type VerificationStatus =
  | 'ok'
  | 'coverage_gap'
  | 'hash_mismatch'
  | 'unsupported_format'
  | 'format_corrupt'
  | 'resource_exhausted'
  | 'semantic_unsolvable';

export interface FatArch {
  index: number;
  cputype: number;
  cpusubtype: number;
  archName: string;
  offset: number;
  size: number;
  align: number; // 2 的指数
  reserved?: number;
}

export interface FatParseResult {
  kind: 'fat' | 'thin';
  endian: Endianness;
  fat64: boolean;
  magic: number;
  nfatArch: number;
  arches: FatArch[];
  diagnostics: Diagnostic[];
}

export interface LoadCommand {
  index: number;
  cmd: number;
  cmdName: string;
  cmdsize: number;
  offset: number; // slice 基准
  fields: Record<string, number | string>;
  outOfBounds: boolean;
}

export interface SectionInfo {
  sectname: string;
  segname: string;
  offset: number;
  size: number;
}

export interface ThinParseResult {
  endian: Endianness;
  is64: boolean;
  magic: number;
  cputype: number;
  cpusubtype: number;
  filetype: number;
  ncmds: number;
  sizeofcmds: number;
  flags: number;
  commands: LoadCommand[];
  sections: SectionInfo[];
  codeSignature?: { dataoff: number; datasize: number };
  linkedit?: { fileoff: number; filesize: number };
  diagnostics: Diagnostic[];
}

export interface CodeSlotCheck {
  slot: number;
  pageOffset: number; // slice 基准
  pageLength: number;
  expectedHash: string;
  actualHash: string;
  match: boolean;
}

export interface CoverageBand {
  start: number; // slice 基准
  end: number;
  kind: 'covered' | 'signature' | 'gap';
}

export interface SignatureParseResult {
  present: boolean;
  blobOffset: number;
  blobSize: number;
  superblobMagic?: number;
  entries: { type: number; offset: number; magic: number | null; known: boolean }[];
  codeDirectory?: {
    hashType: number;
    hashName: string;
    pageSize: number; // shift
    nCodeSlots: number;
    nSpecialSlots: number;
    codeLimit: number;
    ident: string;
  };
  slots: CodeSlotCheck[];
  bands: CoverageBand[];
  diagnostics: Diagnostic[];
}

export interface SliceAnalysis {
  index: number;
  arch: FatArch;
  thin: ThinParseResult | null;
  signature: SignatureParseResult | null;
  status: VerificationStatus;
  diagnostics: Diagnostic[];
}

export interface AnalysisResult {
  container: FatParseResult;
  slices: SliceAnalysis[];
  failureKind: FailureKind | null;
  digest: string;
}
