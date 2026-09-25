// Domain types for the Mach-O slice testimony workbench.
// Every domain quantity carries a unit and a coordinate basis; the raw
// representation captured at import time is preserved alongside.

export type Unit = 'byte' | 'page' | 'slot' | 'index' | 'count' | 'exponent';
export type Basis = 'file-offset' | 'slice-offset' | 'blob-offset' | 'ordinal';

export interface Quantity {
  id: string;            // stable identity, e.g. "qty:slice0.offset"
  value: number | null;  // normalized value; null when not convertible
  unit: Unit;
  basis: Basis;
  raw: string;           // original representation as imported
  diagnostic?: string;   // present when the value could not be normalized
}

export type ResultKind = 'ok' | 'format_corrupt' | 'budget_exhausted' | 'semantic_unresolved';

export interface Diagnostic {
  pos: Quantity | null;  // position of the problem, when known
  code: string;          // machine readable, e.g. "slice.overlap"
  message: string;
}

export interface Budget {
  maxFileBytes: number;
  maxSlices: number;
  maxCommands: number;
  maxBlobs: number;
}

export const DEFAULT_BUDGET: Budget = {
  maxFileBytes: 1 << 20,
  maxSlices: 16,
  maxCommands: 256,
  maxBlobs: 32,
};

// ---- analysis events (machine readable judgements) ----
export type AnalysisEventKind =
  | 'endianness.unknown'
  | 'endianness.mixed'
  | 'slice.overlap'
  | 'slice.misaligned'
  | 'slice.align_overflow'
  | 'slice.duplicate_arch'
  | 'command.out_of_bounds'
  | 'signature.coverage_gap'
  | 'signature.hash_mismatch'
  | 'signature.unsupported_blob'
  | 'signature.unsupported_hash'
  | 'signature.ok';

export interface AnalysisEvent {
  id: string;            // stable within a derivation: "ae:<derivedId>:<n>"
  kind: AnalysisEventKind;
  slice: number | null;
  detail: Record<string, unknown>;
}

export interface LoadCommandInfo {
  id: string;            // "cmd:<sliceId>:<index>"
  index: number;
  cmd: number;
  cmdName: string;
  cmdsize: Quantity;
  offset: Quantity;      // slice-offset basis
  inBounds: boolean;
  fields: Record<string, number>;
}

export interface BlobInfo {
  id: string;
  magic: number;
  magicName: string;     // "CodeDirectory" | "Requirements" | "CMS" | "unknown"
  offset: Quantity;      // blob-offset basis within signature superblob
  length: Quantity;
  supported: boolean;
}

export interface SlotCheck {
  slot: number;
  expected: string;      // hex digest stored in CodeDirectory
  actual: string;        // hex digest computed from bytes
  match: boolean;
}

export interface SignatureInfo {
  id: string;            // "sig:<sliceId>"
  dataoff: Quantity;
  datasize: Quantity;
  superblobMagic: number | null;
  blobs: BlobInfo[];
  hashType: number | null;
  hashName: string | null;
  nCodeSlots: number | null;
  nSpecialSlots: number | null;
  codeLimit: Quantity | null;
  slotChecks: SlotCheck[];
  coverage: { start: number; end: number }[];  // covered ranges, slice-offset basis
  tailGap: { start: number; end: number } | null;
}

export interface SliceInfo {
  id: string;            // "slice:<materialShort>:<index>"
  index: number;
  archName: string;      // e.g. "arm64", "x86_64", "cputype:0x??" when unknown
  cputype: number;
  cpusubtype: number;
  offset: Quantity;      // file-offset basis
  size: Quantity;
  align: Quantity;       // exponent, unit "exponent"
  endian: 'little' | 'big' | 'unknown';
  ncmds: number | null;
  sizeofcmds: Quantity | null;
  commands: LoadCommandInfo[];
  signature: SignatureInfo | null;
}

export interface FatHeaderInfo {
  magic: number;
  magicName: string;
  endian: 'big' | 'little';
  nfatArch: Quantity;
  headerSize: Quantity;  // bytes consumed by fat header + arch table
}

export interface AnalysisResult {
  kind: ResultKind;
  fatHeader: FatHeaderInfo | null;
  slices: SliceInfo[];
  events: AnalysisEvent[];
  diagnostics: Diagnostic[];
  fileSize: Quantity;
  digest: string;        // sha256 of the analysed bytes
}

// ---- store / provenance ----
export interface MaterialRecord {
  id: string;            // "mat:<sha256>"
  kind: 'fat-binary' | 'arch-policy' | 'case-pack' | 'archive';
  sha256: string;
  size: number;
  meta: Record<string, unknown>;
  createdSeq: number;
}

export interface EventRecord {
  id: string;            // "evt:000001"
  seq: number;
  kind: string;
  branch: string;
  parents: string[];     // event ids
  payload: Record<string, unknown>;
  createdAt: string;     // ISO time basis
}

export interface DerivedRecord {
  id: string;            // "drv:<hash>"
  kind: string;          // "analysis" | "coverage" | ...
  inputDigest: string;   // sha256 of input material
  paramsVersion: number;
  parents: string[];     // event ids that were visible when computed
  result: AnalysisResult;
  seq: number;           // event seq that introduced it
}

export interface DecisionRecord {
  eventId: string;
  target: string;        // stable id of the reviewed object
  action: 'accept' | 'reject' | 'adjust';
  rationale: string;
  branch: string;
}
