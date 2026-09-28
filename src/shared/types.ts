// ---------- Domain quantities: every derived/raw value carries unit or coordinate basis ----------

export type ByteOrder = 'be' | 'le';

/** Coordinate basis tells the reviewer whether an offset is global (fat container)
 *  or local (inside a slice). */
export type CoordinateBasis = 'fat-container' | 'slice-local';

export interface DomainValue {
  /** Raw representation exactly as imported (hex / decimal / symbol). Never normalized away. */
  raw: string;
  /** Normalized numeric value when a lossless conversion exists; null otherwise. */
  value: number | null;
  /** Unit of measurement, e.g. 'byte', 'power-of-2 boundary byte', 'count'. */
  unit: string;
  basis: CoordinateBasis;
  /** Set when the raw representation cannot be converted. */
  diagnostic?: string;
}

export type RuleKind =
  | 'pass'
  | 'coverage-gap'
  | 'hash-mismatch'
  | 'unsupported-format'
  | 'slice-overlap'
  | 'alignment-overflow'
  | 'command-out-of-bounds'
  | 'endian-mismatch'
  | 'duplicate-architecture'
  | 'unknown-blob'
  | 'budget-exhausted'
  | 'format-corrupt'
  | 'semantic-ambiguous';

/** Three structurally distinct terminal outcomes required by the spec. */
export type TerminalOutcome =
  | 'adopted'        // judgment kept as binding
  | 'rejected'       // judgment reviewed and discarded
  | 'undecidable';   // multiple legal candidates remain, no unique decision

export type Severity = 'info' | 'warning' | 'error' | 'fatal';

export interface EvidenceByte {
  offset: number;          // coordinate relative to `basis`
  basis: CoordinateBasis;
  expected: number | null; // byte expected (hash mismatch) or null for structural gaps
  actual: number | null;
}

export interface EvidenceSpan {
  start: number;
  end: number;             // exclusive
  basis: CoordinateBasis;
  label: string;
  /** Hex preview of the first bytes actually present (empty when the span is a gap). */
  hexPreview?: string;
}

export interface FindingLocation {
  /** Stable object path, e.g. fat/slice[0]/loadCommands[3]/signature/band */
  path: string;
  spans: EvidenceSpan[];
  bytes?: EvidenceByte[];
}

export interface FindingInputDigest {
  /** sha256 over the exact input bytes that produced this finding */
  inputSha256: string;
  /** content id of the rule parameter version */
  paramsId: string;
  paramsVersion: string;
  /** event ids / content ids of direct parents */
  parents: string[];
}

export interface FindingCandidate {
  sliceId: string;
  archName: string;
  reason: string;
}

export interface Finding {
  id: string;               // stable content identity, survives export/import
  code: RuleKind;
  title: string;
  severity: Severity;
  status: TerminalOutcome;
  location: FindingLocation;
  message: string;
  detail: Record<string, DomainValue | string | number | boolean | string[]>;
  /** hash-mismatch: digest that was expected; coverage-gap: none */
  expectedDigest?: DomainValue;
  actualDigest?: DomainValue;
  candidates?: FindingCandidate[]; // semantic-ambiguous: every legal candidate retained
  input: FindingInputDigest;
  /** id of the analyze event that emitted it */
  emittedBy: string;
}

// ---------- Parsed artifacts (all offsets carry coordinate basis) ----------

export interface FatArchEntry {
  id: string;
  index: number;
  cpuType: DomainValue;
  cpuSubtype: DomainValue;
  archName: string;
  offset: DomainValue;       // fat-container bytes
  size: DomainValue;         // bytes
  align: DomainValue;        // 2^align bytes
  alignBoundary: DomainValue;
  effectiveOffset: DomainValue | null;
}

export interface FatContainer {
  kind: 'fat32' | 'fat64' | 'thin';
  magic: DomainValue;
  byteOrder: ByteOrder;
  declaredByteOrder: ByteOrder; // order actually used by the on-disk header
  nfatArch: DomainValue;
  headerSize: DomainValue;
  archTable: FatArchEntry[];
  totalSize: DomainValue;
}

export interface MachHeaderView {
  magic: DomainValue;
  is64: boolean;
  byteOrder: ByteOrder;
  cpuType: DomainValue;
  cpuSubtype: DomainValue;
  fileType: DomainValue;
  ncmds: DomainValue;
  sizeofcmds: DomainValue;
  flags: DomainValue;
  reserved?: DomainValue;
  headerSize: DomainValue;
}

export interface LoadCommandView {
  id: string;
  index: number;
  cmd: DomainValue;
  cmdName: string;
  cmdsize: DomainValue;
  /** [start,end) slice-local range occupied by the command */
  range: { start: DomainValue; end: DomainValue };
  recognized: boolean;
  payload: Record<string, DomainValue>;
}

export interface CodeSlotView {
  index: number;
  kind: 'code' | 'special';
  slotName?: string;
  /** page-aligned [start,end) slice-local range this slot hashes */
  pageRange: { start: DomainValue; end: DomainValue };
  expectedDigest: DomainValue;
  actualDigest: DomainValue;
  matches: boolean;
}

export interface SignatureBlobView {
  id: string;
  indexInSuper: number;
  type: DomainValue;
  typeName: string;
  known: boolean;
  offset: DomainValue;       // slice-local start of the blob wrapper
  length: DomainValue;
  range: { start: DomainValue; end: DomainValue };
  magic: DomainValue;
}

export interface CodeDirectoryView {
  blobIndex: number;
  version: DomainValue;
  flags: DomainValue;
  hashType: DomainValue;
  hashTypeName: string;
  pageSize: DomainValue;    // bytes
  codeLimit: DomainValue;   // slice-local
  ident: string;
  codeSlots: CodeSlotView[];
}

export interface CoverageBand {
  id: string;
  start: DomainValue;       // slice-local
  end: DomainValue;
  label: string;            // hashed | signed-blob | uncovered-tail | pre-signature-gap
  covered: boolean;
}

export interface LinkEditInfo {
  linkeditSegment?: LoadCommandView;
  codeSignatureCommand?: LoadCommandView;
  dataOffset: DomainValue | null; // LC_CODE_SIGNATURE dataoff, slice-local
  dataSize: DomainValue | null;
}

export interface SliceView {
  id: string;
  index: number;
  archName: string;
  cpuType: DomainValue;
  cpuSubtype: DomainValue;
  /** [start,end) in fat-container coordinates (or [0,size) for thin) */
  containerRange: { start: DomainValue; end: DomainValue };
  size: DomainValue;
  alignmentOk: boolean;
  alignmentDiagnostic?: string;
  byteOrder: ByteOrder;
  header: MachHeaderView;
  loadCommands: LoadCommandView[];
  commandRegion: { start: DomainValue; end: DomainValue };
  linkedit: LinkEditInfo;
  signatureBlobs: SignatureBlobView[];
  codeDirectory?: CodeDirectoryView;
  coverageBands: CoverageBand[];
  rawHeadSha256: string; // digest of the original slice bytes (original summary retained)
}

export interface ParseReport {
  container: FatContainer;
  slices: SliceView[];
  /** sha256 of the full original file bytes */
  sourceSha256: string;
  byteLength: number;
  findings: Finding[]; // structural findings emitted during parse (pre-decision)
  fatal?: { code: RuleKind; message: string };
}

// ---------- Target architecture strategy ----------

export interface ArchStrategy {
  id: string;
  version: string;
  preferredCpuTypes: number[]; // order of preference
  rejectUnknownArch: boolean;
}

// ---------- Event sourcing ----------

export type EventKind =
  | 'project-created'
  | 'material-imported'
  | 'params-revised'
  | 'analyze-requested'
  | 'rule-judged'
  | 'decision-made'
  | 'case-seeded';

export interface EventBase {
  id: string;                 // content-addressed, stable across export/import
  seq: number;                // local order within project (deterministic)
  projectId: string;
  branch: string;
  kind: EventKind;
  parents: string[];          // explicit parent dependency (DAG, not only chain)
  at: string;                 // ISO timestamp, retained as recorded
  ruleVersion: string;
  payload: unknown;
}

export interface MaterialPayload {
  materialId: string;
  filename: string;
  byteLength: number;
  sha256: string;
  /** original bytes kept, base64 (immutable material layer) */
  bytesBase64: string;
  role: 'universal-binary' | 'strategy' | 'counterexample';
  note?: string;
}

export interface ParamsPayload {
  paramsId: string;
  version: string;
  changes: Record<string, number | boolean | string>;
  basedOnParamsId: string;
}

export interface AnalyzeRequestPayload {
  requestId: string;
  materialId: string;
  paramsId: string;
  strategyId: string;
  inputSha256: string;
}

export interface RuleJudgedPayload {
  requestId: string;
  report: ParseReport;
  findings: Finding[];
}

export interface DecisionPayload {
  decisionId: string;
  requestId: string;
  findingIds: string[];
  action: 'accept' | 'reject' | 'adjust-params';
  rationale: string;
  /** when action = adjust-params, a new params version is referenced */
  newParamsId?: string;
  /** conflict marker: decision disagrees with an earlier decision on same finding */
  conflictsWith?: string;
  supersededBy?: string;
}

export type ProjectEvent = EventBase;

export interface ProjectState {
  projectId: string;
  head: string[];                 // DAG tips
  events: ProjectEvent[];
  materials: Record<string, MaterialPayload>;
  paramsById: Record<string, RuleParams & { id: string; version: string }>;
  findings: Record<string, Finding>;
  decisions: Record<string, DecisionPayload>;
  reports: Record<string, ParseReport>;
}

export interface RuleParams {
  maxSlices: number;
  maxLoadCommands: number;
  maxBytes: number;
  requireSliceAlignment: boolean;
  requireSignatureCoversTail: boolean;
  rejectUnknownBlob: boolean;
  pageSize: number;
}

// ---------- Counterexample archive ----------

export type MutationKind =
  | 'endianness'
  | 'slice-overlap'
  | 'alignment-overflow'
  | 'command-out-of-bounds'
  | 'signature-tail-gap'
  | 'duplicate-architecture'
  | 'unknown-blob';

export interface CounterexampleRecord {
  id: string;
  mutation: MutationKind;
  title: string;
  directSource: string;      // the single direct source changed
  baselineSha256: string;
  mutatedSha256: string;
  /** findings with the verdict the reviewer ultimately gave */
  verdictByFinding: Record<string, TerminalOutcome>;
  events: ProjectEvent[];    // machine-readable judgment basis events
  note: string;
}
