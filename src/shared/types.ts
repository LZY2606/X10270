// ---------------------------------------------------------------------------
// Core domain types for the Mach-O slice testimony platform.
//
// Coordinate / unit rule (domain invariant):
//  * Every offset/length material value is an unsigned byte offset or count
//    measured from the start of the enclosing coordinate basis:
//      - FAT_BYTE : offset within the universal (fat) file image
//      - SLICE_BYTE : offset within a thin slice image
//      - FILE_BYTES : generic byte length in the enclosing file
//  * Alignment shift values are measured in bits (2^align bytes).
//  * Raw representations imported from bytes are preserved verbatim on the
//    `raw` fields; normalization happens only in the derivation layer.
// ---------------------------------------------------------------------------

export type ByteOrder = 'be' | 'le';

export type EndianState = 'fixed-be' | 'fixed-le' | 'swap-detected';

export const UNITS = {
  FAT_BYTE: 'FAT_BYTE',
  SLICE_BYTE: 'SLICE_BYTE',
  FILE_BYTES: 'FILE_BYTES',
  ALIGN_BITS: 'ALIGN_BITS',
  SHA256_HEX: 'SHA256_HEX',
} as const;

export type UnitName = (typeof UNITS)[keyof typeof UNITS];

export interface Coordinate {
  basis: 'FAT_BYTE' | 'SLICE_BYTE' | 'FILE_BYTES';
  sliceKey?: string;
}

/** A raw field exactly as it was read from an imported byte source. */
export interface RawField {
  field: string;
  value: number | string;
  unit: UnitName | 'ORDINAL' | 'ENUM' | 'HEX32' | 'MAGIC' | 'UNSUPPORTED_HASHTYPE';
  rawHex: string;
  byteOrder: ByteOrder;
  at: number;
  width: 8 | 16 | 32 | 64;
}

// ---------------------------------------------------------------------------
// Immutable materials (layer 0). These rows are never rewritten.
// ---------------------------------------------------------------------------

export interface FatHeaderMaterial {
  id: string;
  kind: 'fat_header';
  magic: number;
  declaredByteOrder: ByteOrder;
  nfatArch: number;
  headerBytes: number;
  coordinates: { basis: 'FAT_BYTE' };
  raw: RawField[];
}

export interface SliceMaterial {
  id: string;
  kind: 'slice';
  index: number;
  cpuType: number;
  cpuSubtype: number;
  archKey: string;
  offset: number;
  size: number;
  alignShift: number;
  coordinates: { basis: 'FAT_BYTE' };
  thinMagic: number | null;
  thinByteOrder: ByteOrder | null;
  thinFileType: number | null;
  raw: RawField[];
}

export interface LoadCommandMaterial {
  id: string;
  kind: 'load_command';
  sliceKey: string;
  commandIndex: number;
  cmd: number;
  cmdName: string;
  cmdsize: number;
  offsetInSlice: number;
  payloadHex: string;
  coordinates: { basis: 'SLICE_BYTE'; sliceKey: string };
  raw: RawField[];
}

export interface LinkeditMaterial {
  id: string;
  kind: 'linkedit';
  sliceKey: string;
  fileOffset: number;
  fileSize: number;
  vmAddr: number;
  vmSize: number;
  coordinates: { basis: 'SLICE_BYTE'; sliceKey: string };
  raw: RawField[];
}

export interface SignatureBlobMaterial {
  id: string;
  kind: 'signature_blob';
  sliceKey: string;
  fileOffset: number;
  blobSize: number;
  magic: number;
  length: number;
  count: number;
  indexes: { type: number; typeName: string; offset: number; supported: boolean }[];
  coordinates: { basis: 'SLICE_BYTE'; sliceKey: string };
  raw: RawField[];
}

export interface CodeSlotMaterial {
  id: string;
  kind: 'code_slot';
  sliceKey: string;
  slotIndex: number;
  special: boolean;
  codeOffset: number;
  codeLength: number;
  expectedDigest: string | null;
  observedDigest: string | null;
  digestUnit: 'SHA256_HEX';
  coordinates: { basis: 'SLICE_BYTE'; sliceKey: string };
  raw: RawField[];
}

export interface ImageDigestMaterial {
  id: string;
  kind: 'image_digest';
  imageId: string;
  sha256: string;
  byteLength: number;
  unit: 'SHA256_HEX';
  raw: RawField[];
}

export type Material =
  | FatHeaderMaterial
  | SliceMaterial
  | LoadCommandMaterial
  | LinkeditMaterial
  | SignatureBlobMaterial
  | CodeSlotMaterial
  | ImageDigestMaterial;

export type MaterialKind = Material['kind'];

/** Fat (universal) file image material pack extracted from a single byte blob. */
export interface FatImageMaterial {
  imageId: string;
  sourceLabel: string;
  byteLength: number;
  sha256: string;
  fatHeader: FatHeaderMaterial | null;
  slices: SliceMaterial[];
  loadCommands: LoadCommandMaterial[];
  linkedit: LinkeditMaterial[];
  signatureBlobs: SignatureBlobMaterial[];
  codeSlots: CodeSlotMaterial[];
}

// ---------------------------------------------------------------------------
// Target architecture policy (versioned, human-editable decision input).
// ---------------------------------------------------------------------------

export interface TargetPolicy {
  version: number;
  name: string;
  requiredArchKeys: string[];
  forbidDuplicateArch: boolean;
  enforceFatEntryAlignment: boolean;
  tailCoverageGraceBytes: number;
  signatureHashAlgorithm: 'sha256';
}

// ---------------------------------------------------------------------------
// Findings / evaluations (layer 1, derived).
// ---------------------------------------------------------------------------

export type FindingCode =
  | 'FAT_BAD_MAGIC'
  | 'FAT_BYTE_ORDER_SWAP'
  | 'SLICE_OVERLAP'
  | 'SLICE_ALIGN_SHIFT_OVERFLOW'
  | 'SLICE_MISALIGNED'
  | 'SLICE_OUT_OF_BOUNDS'
  | 'THIN_MAGIC_BYTE_ORDER_SWAP'
  | 'LC_OUT_OF_BOUNDS'
  | 'SIGNATURE_TAIL_UNCOVERED'
  | 'SIGNATURE_CODE_SLOT_HASH_MISMATCH'
  | 'SIGNATURE_UNKNOWN_BLOB_TYPE'
  | 'SIGNATURE_BLOB_OUT_OF_BOUNDS'
  | 'MULTI_ARCH_SAME_NAME'
  | 'POLICY_REQUIRED_ARCH_MISSING'
  | 'BUDGET_EXHAUSTED';

export type FindingClass =
  | 'byte_order'
  | 'range'
  | 'alignment'
  | 'load_command'
  | 'signature_coverage'
  | 'signature_hash'
  | 'unsupported_format'
  | 'identity'
  | 'policy'
  | 'budget';

export interface FailedByteEvidence {
  basis: 'FAT_BYTE' | 'SLICE_BYTE';
  sliceKey?: string;
  start: number;
  length: number;
  expectedHex: string;
  observedHex: string;
}

export interface Finding {
  id: string;
  code: FindingCode;
  class: FindingClass;
  severity: 'error' | 'warning';
  message: string;
  subject: { kind: MaterialKind | 'image' | 'policy'; id: string };
  coordinates: Coordinate[];
  evidence: FailedByteEvidence[];
  /** Blast radius: ids of materials/derivations whose conclusion depends on it. */
  affectedObjectIds: string[];
}

export type EvaluationStatus =
  | 'accepted_clean'
  | 'rejected_format_corrupt'
  | 'rejected_semantic_no_solution'
  | 'rejected_budget_exhausted'
  | 'signature_coverage_gap'
  | 'signature_hash_mismatch'
  | 'unsupported_format'
  | 'indeterminate';

export interface Evaluation {
  id: string;
  imageId: string;
  policyVersion: number;
  ruleVersion: string;
  inputDigest: string;
  parentDepIds: string[];
  status: EvaluationStatus;
  findings: Finding[];
  candidates: Candidate[];
  computedAt: string;
  engine: { name: 'macho-testimony-engine'; version: string };
  budget: { maxObjects: number; used: number; exhausted: boolean };
}

export interface Candidate {
  id: string;
  resolution: string;
  selectedSliceKeys: string[];
  rationale: string;
  legal: boolean;
  chosen: boolean;
}

// ---------------------------------------------------------------------------
// Derived view rows (every displayed value carries a stable identity).
// ---------------------------------------------------------------------------

export interface SliceMapRow {
  id: string;
  sliceKey: string;
  archLabel: string;
  start: number;
  end: number;
  size: number;
  alignShift: number;
  validRange: boolean;
  overlapsWith: string[];
  coordinates: { basis: 'FAT_BYTE' };
}

export interface CoverageBand {
  id: string;
  sliceKey: string;
  kind: 'code_hashed' | 'tail_gap' | 'signature_blob' | 'out_of_bounds';
  start: number;
  end: number;
  length: number;
  coordinates: { basis: 'SLICE_BYTE'; sliceKey: string };
  valid: boolean;
  note: string;
}

export interface CommandListRow {
  id: string;
  sliceKey: string;
  commandIndex: number;
  cmdName: string;
  cmd: number;
  cmdsize: number;
  offsetInSlice: number;
  inBounds: boolean;
  coordinates: { basis: 'SLICE_BYTE'; sliceKey: string };
}

// ---------------------------------------------------------------------------
// Event log (layer 2, append-only).
// ---------------------------------------------------------------------------

export type EventType =
  | 'session_created'
  | 'material_imported'
  | 'policy_revised'
  | 'evaluation_recorded'
  | 'decision_recorded'
  | 'branch_created';

export type Disposition = 'accept' | 'reject' | 'parameter_adjustment' | 'conflict';

export interface Decision {
  id: string;
  disposition: Disposition;
  targetEvaluationId: string | null;
  rationale: string;
  candidateId: string | null;
  conflictsWithDecisionId: string | null;
  policyVersion: number;
}

export interface BaseEvent {
  id: string;
  seq: number;
  sessionId: string;
  branch: string;
  at: string;
  actor: 'importer' | 'engine' | 'reviewer';
}

export interface SessionCreatedEvent extends BaseEvent {
  type: 'session_created';
  payload: { title: string; narrative: string };
}

export interface MaterialImportedEvent extends BaseEvent {
  type: 'material_imported';
  payload: {
    imageId: string;
    variantKey: string;
    sourceLabel: string;
    hexAsset?: string;
    image: FatImageMaterial;
    inputFragmentRefs: string[];
  };
}

export interface PolicyRevisedEvent extends BaseEvent {
  type: 'policy_revised';
  payload: { policy: TargetPolicy; previousVersion: number; reason: string };
}

export interface EvaluationRecordedEvent extends BaseEvent {
  type: 'evaluation_recorded';
  payload: { evaluation: Evaluation };
}

export interface DecisionRecordedEvent extends BaseEvent {
  type: 'decision_recorded';
  payload: { decision: Decision };
}

export interface BranchCreatedEvent extends BaseEvent {
  type: 'branch_created';
  payload: { branch: string; parentBranch: string; parentSeq: number; reason: string };
}

export type Event =
  | SessionCreatedEvent
  | MaterialImportedEvent
  | PolicyRevisedEvent
  | EvaluationRecordedEvent
  | DecisionRecordedEvent
  | BranchCreatedEvent;

export type StatusKind = 'ok' | 'format_corrupt' | 'semantic_no_solution' | 'budget_exhausted';
