/**
 * Offline case recipes: a structured, domain-specific source format for
 * universal Mach-O material. Recipes are the *immutable material*; the
 * builder derives concrete bytes. Original numeric representations
 * (radix strings + observed byte order) are preserved alongside values.
 */

export interface OrigField {
  /** Canonical numeric value written into bytes. */
  value: number;
  /** Original textual representation from the domain source. */
  text: string;
}

export type SigCorruption =
  | { kind: 'none' }
  | { kind: 'hash-mismatch'; containerCodeOffset: number; xorByte: number }
  | { kind: 'unknown-blob' }
  | { kind: 'short-tail'; trailingUncovered: number };

export interface SliceRecipe {
  key: string;
  cputype: OrigField;
  cpusubtype: OrigField;
  /** Alignment exponent; boundary = 2^align bytes. */
  align: OrigField;
  filetype: number;
  /** true => little-endian Mach-O slice (normal); false => big-endian. */
  littleEndian: boolean;
  pageSize: number;
  /** Number of hashed code pages; codeLimit = codePages * pageSize. */
  codePages: number;
  /** Content seed for deterministic page bytes. */
  contentSeed: number;
  signature: {
    present: boolean;
    hashType: number;
    corruption: SigCorruption;
  };
}

export interface FatRecipe {
  recipeId: string;
  label: string;
  /** Fat container byte order: standard universal binaries are big-endian. */
  fatLittleEndian: boolean;
  is64: boolean;
  slices: SliceRecipe[];
}

/** A mutation touches exactly one direct source (single point of change). */
export type Mutation =
  | { id: string; kind: 'set-arch-field'; sliceKey: string; field: 'offset' | 'size' | 'align' | 'cputype' | 'cpusubtype'; rawText: string; value: number; note: string }
  | { id: string; kind: 'set-fat-field'; field: 'nfat_arch'; value: number; rawText: string; note: string }
  | { id: string; kind: 'set-command-field'; sliceKey: string; command: number; field: 'cmdsize' | 'cmd'; value: number; rawText: string; note: string }
  | { id: string; kind: 'slice-endian'; sliceKey: string; littleEndian: boolean; note: string }
  | { id: string; kind: 'append-tail'; sliceKey: string; bytes: number; note: string }
  | { id: string; kind: 'patch-code-byte'; sliceKey: string; pageLocalOffset: number; xor: number; note: string };

export interface BuiltArtifact {
  bytes: Uint8Array;
  /** Container-relative coordinate map of significant fields. */
  layout: FatLayout;
}

export interface FieldLoc {
  containerOffset: number;
  width: 4 | 8;
  littleEndian: boolean;
}

export interface SliceLayout {
  key: string;
  sliceIndex: number;
  containerOffset: number;
  size: number;
  fields: {
    magic: FieldLoc;
    cputype: FieldLoc;
    cpusubtype: FieldLoc;
    ncmds: FieldLoc;
    sizeofcmds: FieldLoc;
  };
  archFields: {
    cputype: FieldLoc;
    cpusubtype: FieldLoc;
    offset: FieldLoc;
    size: FieldLoc;
    align: FieldLoc;
  };
  commands: Array<{
    index: number;
    containerOffset: number;
    cmd: FieldLoc;
    cmdsize: FieldLoc;
    name: string;
  }>;
  codeSignature?: {
    linkeditDataoffContainer: number;
    linkeditDatasize: number;
    blobContainerOffset: number;
    blobLength: number;
    codeLimit: number;
    codeLimitField: FieldLoc;
    pageSize: number;
    blobMagicField: FieldLoc;
    codeSlots: Array<{ page: number; containerOffset: number; length: number }>;
  };
}

export interface FatLayout {
  is64: boolean;
  littleEndian: boolean;
  headerSize: number;
  archEntrySize: number;
  nfatArchField?: FieldLoc;
  slices: SliceLayout[];
}
