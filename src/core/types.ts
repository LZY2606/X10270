/**
 * Domain model for universal Mach-O / code-signature coverage review.
 *
 * Layering rule:
 *  - Raw* / "raw" fields preserve the original on-disk representation
 *    (hex strings, log2 alignment, detected byte order) with byte coordinates.
 *  - Derived/normalized values live only in derived structures and always
 *    carry a unit or coordinate basis.
 */

export type ByteOrder = "big" | "little";

export type Unit =
  | "byte"
  | "log2(byte)"
  | "page"
  | "enum"
  | "hex32"
  | "utf8"
  | "sha256"
  | "count";

export interface RawRepr {
  /** Original textual/hex representation as imported. */
  raw: string;
  unit: Unit;
  /** Absolute byte coordinate inside the imported file, when applicable. */
  byteOffset?: number;
  byteLength?: number;
  endian?: ByteOrder;
}

export interface Located<T> extends RawRepr {
  path: string;
  value: T;
}

// ---------------------------------------------------------------------------
// Imported, immutable materials
// ---------------------------------------------------------------------------

export type MaterialKind = "macho-fat-bytes" | "arch-policy" | "rule-pack";

export interface MaterialOrigin {
  source: "case-pack" | "upload" | "reimport" | "mutation";
  sourceId: string;
}

export interface RawMaterial {
  id: string;
  kind: MaterialKind;
  fileName: string;
  importedAt: string;
  /** Original bytes, preserved (base64 so JSON round-trip is exact). */
  bytesBase64: string;
  bytesSha256: string;
  byteLength: number;
  byteOrderHint: ByteOrder | "auto";
  /** For mutation materials: the single direct source they derive from. */
  derivedFrom?: { materialId: string; note: string };
  origin: MaterialOrigin;
}

export interface ArchPolicyTarget {
  cputype: number;
  /** Exact subtype, or mask semantics via cpusubtypeMask. */
  cpusubtype?: number;
  cpusubtypeMask?: number;
  label: string;
}

export interface ArchPolicy {
  id: string;
  version: number;
  rawJson: string;
  targets: ArchPolicyTarget[];
  /** "require-canonical": fat BE, Mach-O per-arch. "accept": accept swapped. */
  endianPolicy: "require-canonical" | "accept";
}

export interface RuleParameter {
  name: string;
  defaultValue: number | string | boolean;
  unit: Unit | "flag";
}

export interface RuleDef {
  id: string;
  version: string;
  code: FindingCode;
  title: string;
  rationale: string;
  appliesTo: "fat" | "slice" | "load-commands" | "code-signature";
  parameters: RuleParameter[];
}

export interface RulePack {
  id: string;
  version: string;
  rawJson: string;
  rules: RuleDef[];
}

export interface ParamChange {
  name: keyof ReviewParams;
  from: number | string | boolean;
  to: number | string | boolean;
  unit: Unit | "flag";
  reason: string;
}

export interface ReviewParams {
  version: number;
  /** Code-hash page size in bytes. */
  pageSize: number;
  /** Reject fat containers whose magic byte order is swapped. */
  requireFatCanonicalEndian: boolean;
  /** Resource budget: maximum code slots hashed per derivation. */
  maxCodeSlots: number;
  maxSlices: number;
  maxLoadCommands: number;
  maxBlobBytes: number;
  /** When target architecture is ambiguous, retain all legal candidates. */
  conflictPolicy: "retain-candidates" | "auto-first";
}

// ---------------------------------------------------------------------------
// Parsed structures (normalized view; raw originals kept alongside)
// ---------------------------------------------------------------------------

export interface FatHeader {
  byteOffset: number;
  magic: Located<number>;
  byteOrder: ByteOrder;
  canonical: boolean;
  nfatArch: Located<number>;
}

export interface FatSlice {
  index: number;
  /** Coordinate of the fat_arch/fat_arch_64 entry itself. */
  entryByteOffset: number;
  cputype: Located<number>;
  cpusubtype: Located<number>;
  offset: Located<number>;
  size: Located<number>;
  /** Alignment as encoded: power of two exponent (log2). Never rounded. */
  align: Located<number>;
  is64Entry: boolean;
  reserved?: Located<number>;
}

export interface MachSection {
  index: number;
  sectname: string;
  segname: string;
  addr: number;
  size: number;
  offset: number;
  alignLog2: number;
  byteOffset: number;
}

export interface MachSegment {
  segname: string;
  vmaddr: number;
  vmsize: number;
  fileoff: number;
  filesize: number;
  maxprot: number;
  initprot: number;
  nsects: number;
  sections: MachSection[];
  cmdByteOffset: number;
}

export interface LinkEditPayload {
  kind: "symtab" | "dysymtab";
  symoff?: number;
  nsyms?: number;
  stroff?: number;
  strsize?: number;
  tocoff?: number;
  ntoc?: number;
  modtaboff?: number;
  nmodtab?: number;
  extrefsymoff?: number;
  nextrefsyms?: number;
  indirectsymoff?: number;
  nindirectsyms?: number;
  extreloff?: number;
  nextrel?: number;
  locreloff?: number;
  nlocrel?: number;
}

export interface CodeSigPayload {
  dataoff: number;
  datasize: number;
}

export interface LoadCommand {
  index: number;
  byteOffset: number;
  endOffset: number;
  cmd: number;
  cmdName: string;
  cmdsize: number;
  segment?: MachSegment;
  linkedit?: LinkEditPayload;
  codesig?: CodeSigPayload;
  uuid?: string;
  /** Raw 32-bit words for commands we do not model structurally. */
  rawWords: number[];
}

export interface MachHeaderInfo {
  byteOffset: number;
  magic: Located<number>;
  byteOrder: ByteOrder;
  is64: boolean;
  cputype: Located<number>;
  cpusubtype: Located<number>;
  filetype: Located<number>;
  ncmds: Located<number>;
  sizeofcmds: Located<number>;
  flags: Located<number>;
  reserved?: Located<number>;
}

export interface CodeSlotHash {
  slot: number;
  /** Absolute file offset of the hashed page start. */
  rangeStart: number;
  /** Absolute file offset, exclusive. Final slot may be shorter than page. */
  rangeEnd: number;
  length: number;
  expectedSha256: string;
  /** Offset of the stored hash inside the CodeDirectory. */
  storedAt: number;
}

export interface CodeDirectoryInfo {
  version: string;
  flags: number;
  hashOffset: number;
  identOffset: number;
  nSpecialSlots: number;
  nCodeSlots: number;
  codeLimit: number;
  hashSize: number;
  hashType: number;
  pageSizeLog2: number;
  identifier: string;
  codeSlots: CodeSlotHash[];
  specialSlots: { slot: number; value: string }[];
  byteLength: number;
}

export interface BlobSlot {
  index: number;
  type: number;
  typeName: string;
  /** Offset relative to superblob start. */
  offset: number;
  size: number;
  magic: number;
  magicHex: string;
  known: boolean;
  codeDirectory?: CodeDirectoryInfo;
}

export interface SuperBlobInfo {
  byteOffset: number;
  byteOrder: ByteOrder;
  length: number;
  count: number;
  slots: BlobSlot[];
  /** Coverage band: [byteOffset, byteOffset+length) in file coordinates. */
  bandEnd: number;
}

export interface ParsedSlice {
  fat: FatSlice;
  header: MachHeaderInfo;
  commands: LoadCommand[];
  commandsEnd: number;
  signature?: SuperBlobInfo;
  linkEditCommands: LoadCommand[];
}

export interface ParsedContainer {
  kind: "fat" | "thin";
  fatHeader?: FatHeader;
  slices: ParsedSlice[];
  /** Bytes after the final slice end, if any (coordinate of uncovered tail). */
  containerEnd: number;
}

// ---------------------------------------------------------------------------
// Diagnostics, findings, derivation results
// ---------------------------------------------------------------------------

export type OutcomeKind =
  | "OK"
  | "FORMAT_CORRUPT"
  | "SEMANTIC_UNRESOLVABLE"
  | "BUDGET_EXHAUSTED";

export interface Diagnostic {
  code: string;
  severity: "error" | "warning" | "info";
  message: string;
  path?: string;
  byteOffset?: number;
  byteLength?: number;
  actualHex?: string;
}

export interface EvidenceByte {
  id: string;
  label: string;
  coordinate: "file" | "slice";
  sliceIndex?: number;
  start: number;
  end: number;
  length: number;
  unit: "byte";
  actualHex: string;
  expectedHex?: string;
}

export interface CoverageBand {
  id: string;
  label: string;
  coordinate: "file" | "slice";
  sliceIndex?: number;
  start: number;
  end: number;
  kind: "code-hashed" | "signature" | "gap" | "load-commands" | "linkedit";
}

export type FindingCode =
  | "ENDIAN_SWAPPED"
  | "SLICE_OVERLAP"
  | "SLICE_ALIGNMENT"
  | "ALIGN_OVERFLOW"
  | "CMD_OUT_OF_BOUNDS"
  | "SIG_COVERAGE_GAP"
  | "SIG_HASH_MISMATCH"
  | "SIG_UNSUPPORTED_BLOB"
  | "MULTI_ARCH_AMBIGUOUS"
  | "FORMAT_CORRUPT"
  | "BUDGET_EXHAUSTED"
  | "OK";

export interface AmbiguousCandidate {
  sliceIndex: number;
  cputype: number;
  cpusubtype: number;
  label: string;
  reason: string;
}

export interface RuleFinding {
  id: string;
  ruleId: string;
  ruleVersion: string;
  code: FindingCode;
  severity: "violation" | "gap" | "mismatch" | "unsupported" | "ambiguous" | "info";
  subject: string;
  subjectLabel: string;
  message: string;
  verdict: "fail" | "warn" | "pass" | "candidate";
  evidence: EvidenceByte[];
  bands?: CoverageBand[];
  candidates?: AmbiguousCandidate[];
}

export interface ConsumedRange {
  ruleId: string;
  coordinate: "file" | "slice";
  sliceIndex?: number;
  start: number;
  end: number;
  purpose: string;
}

export interface DerivationResult {
  id: string;
  materialId: string;
  materialSha256: string;
  rulePackId: string;
  rulePackVersion: string;
  paramsId: string;
  paramsVersion: number;
  parentDerivationId?: string;
  derivedAt: string;
  outcome: OutcomeKind;
  parsed: ParsedContainer;
  findings: RuleFinding[];
  inputDigest: string;
  consumedRanges: ConsumedRange[];
  diagnostics: Diagnostic[];
  budget?: { limit: number; used: number; remaining: number; unit: Unit };
  /** Set on ambiguous policy resolution: all legal candidates retained. */
  candidates?: AmbiguousCandidate[];
}

// ---------------------------------------------------------------------------
// Event sourcing
// ---------------------------------------------------------------------------

export type DecisionKind = "accept" | "reject";

export type EventBody =
  | { t: "MaterialImported"; material: RawMaterial }
  | { t: "PolicyImported"; policy: ArchPolicy }
  | { t: "RulePackRegistered"; pack: RulePack }
  | { t: "ParamsRevised"; fromVersion: number; changes: ParamChange[]; params: ReviewParams }
  | {
      t: "SourceMutated";
      fromMaterialId: string;
      material: RawMaterial;
      note: string;
    }
  | { t: "Derived"; derivation: DerivationResult; label: string }
  | {
      t: "Decision";
      derivationId: string;
      decision: DecisionKind;
      rationale: string;
      conflictsWith?: string;
    }
  | { t: "BranchTag"; branch: string; atEventId: string | null };

export interface ReviewEvent {
  id: string;
  seq: number;
  caseId: string;
  branch: string;
  parentEventId: string | null;
  timestamp: string;
  actor: "system" | "reviewer";
  body: EventBody;
}

// ---------------------------------------------------------------------------
// Offline case pack
// ---------------------------------------------------------------------------

export type CaseAction =
  | { kind: "import-material"; materialId: string }
  | { kind: "mutate-source"; fromMaterialId: string; materialId: string; note: string }
  | { kind: "revise-params"; changes: ParamChange[]; note: string }
  | { kind: "derive"; materialId: string; label: string }
  | {
      kind: "decide";
      derivationLabel: string;
      decision: DecisionKind;
      rationale: string;
      branch?: string;
      conflictsWith?: string;
    };

export interface CasePack {
  format: "macho-review-case-pack/1";
  caseId: string;
  title: string;
  narrative: string;
  createdAt: string;
  rulePack: RulePack;
  policy: ArchPolicy;
  initialParams: ReviewParams;
  materials: RawMaterial[];
  actions: CaseAction[];
}

export interface CaseExport {
  format: "macho-review-export/1";
  caseId: string;
  exportedAt: string;
  events: ReviewEvent[];
}
