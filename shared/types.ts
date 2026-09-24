// Domain model for universal Mach-O / fat container / code signature review.
// Everything that came from a file keeps its original representation plus a
// coordinate/unit anchor; normalized values live only in derived snapshots.

export type Endianness = 'big' | 'little';

export type CoordinateSpace = 'container' | 'slice' | 'signature';

export interface ByteRange {
  offset: number; // absolute within coordinateSpace, unit: byte
  length: number; // unit: byte
}

export interface Coordinate {
  space: CoordinateSpace;
  range: ByteRange;
  sliceId?: string;
  unit: 'byte';
}

export interface ByteEvidence {
  coordinate: Coordinate;
  expectedHex?: string;
  actualHex?: string;
  contextBeforeHex?: string;
  contextAfterHex?: string;
}

export type FailureClass = 'coverage-gap' | 'hash-mismatch' | 'unsupported-format';

export type FindingKind =
  | 'endian-fat-swapped'
  | 'endian-slice-swapped'
  | 'slice-overlap'
  | 'slice-misaligned'
  | 'alignment-overflow'
  | 'slice-out-of-bounds'
  | 'duplicate-arch'
  | 'command-out-of-bounds'
  | 'truncated-input'
  | 'sig-tail-uncovered'
  | 'sig-hash-mismatch'
  | 'sig-unsupported-format'
  | 'sig-unknown-blob'
  | 'budget-exhausted'
  | 'format-corrupt'
  | 'semantic-undecidable';

export type Severity = 'info' | 'warning' | 'blocking';

export interface Candidate {
  sliceId: string;
  archKey: string;
  reason: string;
}

export interface Finding {
  id: string;
  kind: FindingKind;
  severity: Severity;
  failureClass?: FailureClass;
  ruleId: string;
  message: string;
  coordinate: Coordinate;
  evidence?: ByteEvidence;
  candidates?: Candidate[];
  diagnosedValue?: string;
  validRange?: string;
}

export interface FatHeaderView {
  id: string;
  magicHex: string;
  magicName: string;
  endianness: Endianness;
  nfatArch: number;
  headerRange: ByteRange; // container bytes, unit byte
  archEntryRange: ByteRange;
  byteLength: number; // container byte count
}

export interface SliceView {
  id: string;
  archKey: string;
  cputype: number;
  cpusubtype: number;
  archName: string;
  endianness: Endianness;
  offset: number; // container offset, byte
  declaredSize: number; // byte, from fat entry
  actualSize: number; // byte, bytes consumed/available
  alignmentShift: number;
  alignmentBytes: number | null; // null when the shift cannot be converted
  alignmentOverflow?: boolean;
  misaligned?: boolean;
  unconvertible?: { field: string; rawValue: string; reason: string };
  magicHex: string;
  machHeaderRange: ByteRange; // slice-relative, byte
}

export interface LoadCommandView {
  id: string;
  sliceId: string;
  index: number;
  cmd: number;
  cmdName: string;
  cmdsize: number;
  offset: number; // slice-relative byte offset
  range: ByteRange; // slice-relative
  details?: Record<string, string>;
}

export interface CodeSlotView {
  id: string;
  sliceId: string;
  index: number;
  offset: number; // slice-relative byte offset
  length: number; // bytes (last slot truncated at codeLimit)
  recordedDigestHex: string;
  actualDigestHex: string;
  digestAlgorithm: string;
  matches: boolean;
}

export interface SignatureBlobView {
  id: string;
  sliceId: string;
  magicHex: string;
  magicName: string;
  slotType: number;
  blobOffset: number; // signature-relative byte offset
  length: number; // bytes
  range: ByteRange; // signature-relative
  supported: boolean;
  codeLimit?: number;
  pageSize?: number; // bytes
  nCodeSlots?: number;
  hashSize?: number;
  hashType?: number;
}

export type CoverageKind =
  | 'hashed-code'
  | 'uncovered-tail'
  | 'signature'
  | 'non-signature-gap';

export interface CoverageBand {
  id: string;
  sliceId: string;
  kind: CoverageKind;
  offset: number; // slice-relative byte
  length: number; // byte
  label: string;
}

export type ParseStatus =
  | 'ok'
  | 'budget-exhausted'
  | 'format-corrupt'
  | 'semantic-undecidable';

export interface DerivedSnapshot {
  id: string;
  eventId: string;
  materialId: string;
  paramsVersion: string;
  inputDigest: string;
  status: ParseStatus;
  adopted: boolean;
  fat?: FatHeaderView;
  slices: SliceView[];
  commands: LoadCommandView[];
  signatures: SignatureBlobView[];
  codeSlots: CodeSlotView[];
  coverage: CoverageBand[];
  findings: Finding[];
}

export type MaterialKind = 'universal-binary' | 'arch-policy' | 'thin-binary';
export type MaterialRole =
  | 'baseline'
  | 'counterexample'
  | 'parameter-revision'
  | 'source-change'
  | 'user-import';

export interface Material {
  id: string;
  kind: MaterialKind;
  role: MaterialRole;
  name: string;
  description: string;
  // Original representation is never normalized away: binary inputs keep their
  // verbatim hex bytes, policies keep their original JSON text.
  hexBytes?: string;
  originalJson?: unknown;
  byteLength: number;
  sourceDigest: string;
  mutatesFrom?: string; // baseline material id when this is a single-source variant
  mutationDirectSource?: string; // human-readable direct source coordinate
}

export interface PolicyParams {
  version: string;
  label: string;
  targetArchitectures: { cputype: number; cpusubtype: number; name: string }[];
  maxContainerBytes: number; // byte budget
  maxFatArchs: number;
  maxLoadCommandsPerSlice: number;
  tailGap: 'allow-as-warning' | 'block';
  hashMismatch: 'allow-as-warning' | 'block';
  unknownBlob: 'allow-as-warning' | 'block';
}

export type EventType =
  | 'project-created'
  | 'material-imported'
  | 'params-revised'
  | 'derived'
  | 'decision'
  | 'branch-opened';

export interface EventBase {
  id: string;
  projectId: string;
  branch: string;
  seq: number;
  at: string; // ISO-8601 timestamp
  actor: string;
  type: EventType;
  parentEventId: string | null;
  inputDigest: string;
  paramsVersion: string | null;
}

export interface ProjectCreatedPayload {
  name: string;
  narrative: string;
}
export interface MaterialImportedPayload {
  materialId: string;
  sourceDigest: string;
  note: string;
}
export interface ParamsRevisedPayload {
  paramsVersion: string;
  fromVersion: string | null;
  policy: PolicyParams;
  note: string;
}
export interface DerivedPayload {
  materialId: string;
  paramsVersion: string;
  snapshotId: string;
  status: ParseStatus;
  adopted: boolean;
  findingCount: number;
  blockingCount: number;
}
export interface DecisionPayload {
  decision: 'accepted' | 'rejected' | 'parameter-adjusted';
  targetEventId: string;
  targetMaterialId?: string;
  rationale: string;
  conflictWithEventId?: string;
  paramsVersion?: string;
}
export interface BranchOpenedPayload {
  branch: string;
  parentBranch: string;
  fromEventId: string;
  reason: string;
}

export type EventPayload =
  | ProjectCreatedPayload
  | MaterialImportedPayload
  | ParamsRevisedPayload
  | DerivedPayload
  | DecisionPayload
  | BranchOpenedPayload;

export interface Event extends EventBase {
  payload: EventPayload;
}

export interface BranchInfo {
  name: string;
  parentBranch: string | null;
  forkFromEventId: string | null;
  reason: string;
  createdAt: string;
}

export interface Project {
  id: string;
  name: string;
  narrative: string;
  createdAt: string;
  mainBranch: string;
}

export interface ExportBundle {
  format: 'macho-gsb-review-bundle';
  bundleVersion: 1;
  project: Project;
  branches: BranchInfo[];
  materials: Material[];
  events: Event[];
  snapshots: DerivedSnapshot[];
  exportedAt: string;
  checksum: string;
}

export interface ScenarioStep {
  at: string;
  actor: string;
  type: EventType;
  branch?: string;
  note?: string;
  // for material-imported
  materialRef?: string; // key into scenario materials
  // params
  policyRef?: string;
  // derived
  fromEvent?: number; // seq on same branch to (re)derive from its material
  // decision
  decision?: 'accepted' | 'rejected' | 'parameter-adjusted';
  targetSeq?: number;
  targetBranch?: string;
  rationale?: string;
  conflictWith?: { branch: string; seq: number };
  // branch
  parentBranch?: string;
  fromSeq?: number;
  reason?: string;
}

export interface ScenarioMaterial {
  ref: string;
  name: string;
  description: string;
  role: MaterialRole;
  variantKind?: FindingKind;
  directSource?: string;
  mutatesRef?: string;
  policy?: PolicyParams;
}

export interface CasePack {
  format: 'macho-gsb-review-casepack';
  casepackVersion: 1;
  title: string;
  domain: string;
  story: string;
  materials: ScenarioMaterial[];
  baselineRef: string;
  policies: { ref: string; policy: PolicyParams }[];
  steps: ScenarioStep[];
  generatedAt: string;
  checksum: string;
}
