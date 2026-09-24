// Structured, machine-readable diagnostics. Every problem carries a precise
// position (file-absolute + slice-relative coordinates when available), the
// offending byte evidence (hex), and is classified so callers can distinguish
// corruption, semantic ambiguity and budget exhaustion programmatically.

export type FindingCode =
  | 'endian-mismatch'
  | 'fat-header-truncated'
  | 'fat-entry-overflow'
  | 'slice-overlap'
  | 'alignment-overflow'
  | 'slice-out-of-bounds'
  | 'mach-magic-unknown'
  | 'mach-header-truncated'
  | 'command-out-of-bounds'
  | 'linkedit-data-out-of-bounds'
  | 'duplicate-arch'
  | 'signature-truncated'
  | 'signature-unsupported-magic'
  | 'signature-unsupported-format'
  | 'codirectory-unsupported'
  | 'code-slot-unknown-blob'
  | 'signature-not-covering-tail'
  | 'code-slot-hash-mismatch'
  | 'budget-exhausted';

export type Severity = 'error' | 'warning' | 'info';

// Outcome classes required by the specification — three deliberately distinct
// terminal results plus the success path.
export type OutcomeClass =
  | 'ok'
  | 'corrupt-format'      // bytes violate the on-disk grammar
  | 'semantic-ambiguous'  // well-formed but no unique decision (candidates kept)
  | 'budget-exhausted';   // resource limit hit before a verdict was reached

export interface ByteRange {
  offset: number;   // unit: bytes
  length: number;   // unit: bytes
}

export interface Finding {
  code: FindingCode;
  severity: Severity;
  message: string;
  basis: string;                  // coordinate basis label
  positions?: {
    fileAbsolute?: number;        // absolute-file-offset (bytes)
    sliceRelative?: number;       // slice-relative-offset (bytes)
    sliceId?: string;
    page?: number;                // page-index
    endian?: 'big' | 'little';
  }[];
  ranges?: {
    basis: string;
    range: ByteRange;
  }[];
  candidates?: { id: string; label: string }[]; // retained legal candidates
  evidence?: {
    offset: number;
    expected?: string;            // hex
    actual?: string;              // hex
    bytes?: string;               // raw hex excerpt
  }[];
}

export class DiagnosticCollector {
  readonly findings: Finding[] = [];
  private _class: OutcomeClass = 'ok';

  add(f: Finding): void {
    this.findings.push(f);
    this._class = mergeOutcome(this._class, classForFinding(f.code));
  }

  budgetExhausted(message: string, limit: number, used: number): never {
    this.findings.push({
      code: 'budget-exhausted',
      severity: 'error',
      message,
      basis: 'resource-budget',
      evidence: [{ offset: 0, actual: `used=${used}`, expected: `limit=${limit}` }],
    });
    const err = new Error(message) as Error & { diagnostic?: true };
    err.diagnostic = true;
    throw err;
  }

  get outcomeClass(): OutcomeClass {
    return this._class;
  }

  errors(): Finding[] {
    return this.findings.filter((f) => f.severity === 'error');
  }
}

export function classForFinding(code: FindingCode): OutcomeClass {
  switch (code) {
    case 'duplicate-arch':
      return 'semantic-ambiguous';
    case 'budget-exhausted':
      return 'budget-exhausted';
    default:
      return 'corrupt-format';
  }
}

export function mergeOutcome(a: OutcomeClass, b: OutcomeClass): OutcomeClass {
  const rank: Record<OutcomeClass, number> = {
    ok: 0,
    'semantic-ambiguous': 1,
    'corrupt-format': 2,
    'budget-exhausted': 3,
  };
  return rank[b] > rank[a] ? b : a;
}

export function hex(bytes: Uint8Array, max = 32): string {
  return [...bytes.slice(0, max)]
    .map((b) => b.toString(16).padStart(2, '0'))
    .join(' ');
}
