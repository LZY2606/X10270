// Domain model: every quantity carries a unit and a coordinate basis.
// Raw representations are preserved at import; normalization happens only
// in the derived layer. Values that cannot be converted stay in place with
// a diagnostic attached — never dropped, never defaulted.

export type Unit = 'byte' | 'page' | 'slot' | 'index';
export type Basis = 'file' | 'slice' | 'blob' | 'codedir';

export interface Quantity {
  value: number;
  unit: Unit;
  basis: Basis;
  raw?: string; // original textual/hex representation as imported
}

export interface ByteRange {
  offset: Quantity;
  length: Quantity;
}

export interface Diagnostic {
  code: string; // machine-readable, e.g. 'slice.overlap'
  severity: 'error' | 'warning' | 'info';
  message: string;
  ranges: ByteRange[]; // positions; empty only when truly positionless
  objectId?: string; // stable identity of the affected object
  detail?: Record<string, unknown>;
}

// Three failure families must stay distinguishable:
//  - 'malformed'         : format is corrupt (structural parse failure)
//  - 'budget-exhausted'  : resource budget ran out before completion
//  - 'unsatisfiable'     : format parsed fine, semantics have no legal solution
export type ResultStatus = 'ok' | 'malformed' | 'budget-exhausted' | 'unsatisfiable';

export type SignatureVerdict =
  | 'ok'
  | 'coverage-gap'
  | 'hash-mismatch'
  | 'unsupported-format'
  | 'absent';

export interface Policy {
  name: string;
  version: string;
  requiredArchs: string[];
  allowedHashTypes: string[]; // e.g. ['sha256']
  pageSize: number; // expected code-signing page size in bytes
  maxSlices: number;
}

export interface Budget {
  maxBytes: number;
  maxSlices: number;
  maxCommands: number;
  maxBlobs: number;
}

export const DEFAULT_BUDGET: Budget = {
  maxBytes: 64 * 1024 * 1024,
  maxSlices: 64,
  maxCommands: 4096,
  maxBlobs: 64,
};

export function q(value: number, unit: Unit, basis: Basis, raw?: string): Quantity {
  return raw === undefined ? { value, unit, basis } : { value, unit, basis, raw };
}

export function byteRange(offset: number, length: number, basis: Basis, rawOffset?: string): ByteRange {
  return { offset: q(offset, 'byte', basis, rawOffset), length: q(length, 'byte', basis) };
}

export function hex(n: number, width = 8): string {
  return '0x' + n.toString(16).padStart(width, '0');
}
