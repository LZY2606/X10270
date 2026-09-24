/**
 * Domain types for Mach-O slice testimony.
 *
 * Layering:
 *  - Raw / source representations always carry their original form
 *    (byte order, radix strings, units/coordinate basis).
 *  - Normalized values exist only on the derived layer.
 *  - Values that cannot be converted stay in place with diagnostics;
 *    they are never silently dropped or replaced with defaults.
 */

export type ByteOrder = 'BE' | 'BE64' | 'LE' | 'unknown';

/** Stable coordinate basis every offset/length references. */
export type CoordinateBasis = 'fat.container' | 'slice.local' | 'code.page';

export interface UnitTag {
  /** Logical unit, e.g. "byte", "2^align bytes", "page(4096 bytes)". */
  unit: string;
  basis: CoordinateBasis;
}

/** Original representation preserved at import time. */
export interface OrigRepr {
  /** How the value was written in the source, e.g. "0x1000", "4096", "0b100". */
  text: string;
  /** Source byte order observed for this field, when relevant. */
  byteOrder?: ByteOrder;
  /** Field offset inside the source blob, for position-carrying diagnostics. */
  at?: number;
}

export interface LocatedValue {
  value: number | bigint;
  orig: OrigRepr;
}

/** Three distinct terminal classes the requirements call out. */
export type Outcome = 'OK' | 'CORRUPT' | 'BUDGET_EXHAUSTED' | 'SEMANTIC';

/** Signature-specific distinctions required by the business rules. */
export type SigVerdict =
  | 'SIG_OK'
  | 'COVERAGE_GAP'
  | 'HASH_MISMATCH'
  | 'UNSUPPORTED_FORMAT';

export type FindingCode =
  | 'ENDIAN_SWAPPED'
  | 'ENDIAN_UNRECOGNIZED'
  | 'SLICE_OVERLAP'
  | 'ALIGNMENT_OVERFLOW'
  | 'COMMAND_OUT_OF_BOUNDS'
  | 'SIG_TAIL_UNCOVERED'
  | 'SIG_HASH_MISMATCH'
  | 'SIG_UNKNOWN_BLOB'
  | 'MULTI_ARCH_DUPLICATE'
  | 'BUDGET_EXHAUSTED'
  | 'MALFORMED_CONTAINER'
  | 'SEMANTIC_AMBIGUOUS';

export type Severity = 'info' | 'warning' | 'error';

export interface Diagnostic {
  code: FindingCode;
  severity: Severity;
  /** Human-readable message. */
  message: string;
  /** Byte position (basis-relative) the complaint refers to. */
  at?: number;
  basis?: CoordinateBasis;
  /** Range, half-open [start,end), in bytes, when a span is implicated. */
  range?: [number, number];
}

export interface RawEvidenceWindow {
  basis: CoordinateBasis;
  /** Absolute start of the window in that basis. */
  offset: number;
  /** Base64 bytes actually present at the window. */
  actualBase64: string;
  /** Base64 bytes expected (e.g. recomputed hash slot), when applicable. */
  expectedBase64?: string;
  /** Index of the first differing byte within the window, when applicable. */
  firstDiffIndex?: number;
}

export interface FatHeaderView {
  /** Magic as observed (0xcafebabe / 0xcafebabf / little-endian variants). */
  magicObserved: LocatedValue;
  byteOrder: ByteOrder;
  nFatArch: LocatedValue;
  is64: boolean;
  /** Total byte length of the input container this header came from. */
  containerBytes: number;
}

export interface SliceSpec {
  /** Stable identity assigned at material import; survives export/import. */
  sliceId: string;
  index: number;
  cputype: LocatedValue;
  cpusubtype: LocatedValue;
  /** Offset of slice within the fat container (basis: fat.container). */
  offset: LocatedValue;
  size: LocatedValue;
  align: LocatedValue;
  /** Effective alignment boundary = 2^align bytes. */
  alignBoundary: number;
  reserved?: LocatedValue;
}

export interface LoadCommandView {
  commandId: string;
  index: number;
  cmd: LocatedValue;
  cmdsize: LocatedValue;
  /** Half-open [start,end) within the slice (basis: slice.local). */
  range: [number, number];
  name: string;
  linkedit?: {
    dataoff: number;
    datasize: number;
    kind: 'LC_CODE_SIGNATURE' | 'LC_SEGMENT_LINKEDIT' | 'other';
  };
}

export interface CodeSlotView {
  slotId: string;
  index: number;
  /** Page coordinate this slot hashes, basis code.page. */
  page: number;
  observedDigestBase64: string;
  recomputedDigestBase64?: string;
  match: boolean | null;
}

export interface SigBlobView {
  blobId: string;
  slot: number;
  type: number;
  typeName: string;
  offset: number;
  length: number;
  supported: boolean;
}

export interface SignatureView {
  present: boolean;
  /** Half-open [start,end) of the signature blob within the slice. */
  range: [number, number] | null;
  codeLimit: number | null;
  codePageSize: number | null;
  hashType: string | null;
  verdict: SigVerdict;
  blobs: SigBlobView[];
  codeSlots: CodeSlotView[];
  coverageBand: Array<{ start: number; end: number; covered: boolean; label: string }>;
  failureEvidence?: RawEvidenceWindow;
  diagnostics: Diagnostic[];
}

export interface SliceView {
  spec: SliceSpec;
  archName: string;
  sliceByteOrder: ByteOrder;
  /** Half-open container range [offset,offset+size). */
  containerRange: [number, number];
  commands: LoadCommandView[];
  signature: SignatureView;
  diagnostics: Diagnostic[];
  outcome: Outcome;
}

export interface ReviewView {
  materialId: string;
  sourceLabel: string;
  header: FatHeaderView | null;
  slices: SliceView[];
  diagnostics: Diagnostic[];
  outcome: Outcome;
  /** Every legal candidate kept when identity cannot be decided uniquely. */
  ambiguityCandidates: AmbiguityCandidate[];
  budgets: BudgetReport;
  generatedAtEventId: string;
  paramsVersion: number;
  parentEventIds: string[];
}

export interface AmbiguityCandidate {
  candidateId: string;
  reason: FindingCode;
  sliceIds: string[];
  archName: string;
  detail: string;
}

export interface BudgetReport {
  maxSlices: number;
  maxCommandsPerSlice: number;
  maxContainerBytes: number;
  maxTotalCommands: number;
  usedSlices: number;
  usedContainerBytes: number;
  usedTotalCommands: number;
  exhausted: boolean;
}

/** Materials are immutable source artifacts. */
export interface MaterialRecord {
  materialId: string;
  kind: 'fat-bytes' | 'case-recipe' | 'mutated-bytes';
  label: string;
  /** Raw imported bytes preserved verbatim (base64). */
  bytesBase64: string;
  sha256: string;
  byteLength: number;
  importedAt: string;
  /** Original representation metadata (radix/order) retained at import. */
  sourceMeta: Record<string, unknown>;
}

export type EventKind =
  | 'material.imported'
  | 'params.revised'
  | 'source.patch_applied'
  | 'decision.accepted'
  | 'decision.rejected'
  | 'decision.parameter_adjusted'
  | 'derivation.computed'
  | 'archive.verdict_recorded'
  | 'case.replay_step';

export interface EventRecord {
  eventId: string;
  projectId: string;
  seq: number;
  branch: string;
  kind: EventKind;
  occurredAt: string;
  /** Digest(s) of the exact inputs this event/result was computed from. */
  inputDigests: string[];
  paramsVersion: number;
  parentEventIds: string[];
  payload: Record<string, unknown>;
}

export interface DecisionRecord {
  decisionId: string;
  projectId: string;
  branch: string;
  eventId: string;
  targetFindingId: string | null;
  action: 'accept' | 'reject' | 'adjust';
  rationale: string;
  paramsVersion: number;
  createdAt: string;
}

export interface ProjectRecord {
  projectId: string;
  name: string;
  createdAt: string;
  headEventId: string | null;
}
