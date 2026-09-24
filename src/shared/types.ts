/** A domain quantity always carries its unit and coordinate basis. */
export type Unit = 'byte' | 'count' | 'exponent2';
export type Basis = 'file' | 'slice' | 'blob';
export interface Qty {
  value: number;
  unit: Unit;
  basis: Basis;
}
export const q = (value: number, unit: Unit, basis: Basis): Qty => ({ value, unit, basis });

/** Raw on-disk representation preserved at import time. */
export interface RawField {
  rawHex: string;
  endian: 'le' | 'be';
  note?: string;
}

export type DiagCode =
  | 'header_truncated'
  | 'bad_magic'
  | 'slice_overlap'
  | 'slice_out_of_bounds'
  | 'align_overflow'
  | 'align_invalid'
  | 'command_out_of_bounds'
  | 'command_malformed'
  | 'signature_out_of_bounds'
  | 'budget_exceeded'
  | 'semantic_unresolvable'
  | 'import_corrupt';

export interface Diag {
  code: DiagCode;
  message: string;
  objectId: string;
  position: Qty | null;
  raw?: RawField;
}

export type Verdict =
  | { kind: 'ok'; slots: number }
  | { kind: 'not_signed' }
  | { kind: 'coverage_gap'; gapStart: Qty; gapEnd: Qty }
  | { kind: 'hash_mismatch'; slot: number; expected: string; actual: string }
  | { kind: 'unsupported_format'; blobMagic: string };

export interface Budget {
  maxSlices: number;
  maxCommands: number;
  maxBytes: number;
}

export interface Policy {
  version: number;
  targetArch: string;
  budget: Budget;
}

export const DEFAULT_BUDGET: Budget = { maxSlices: 8, maxCommands: 64, maxBytes: 1 << 22 };
