export type Unit = 'byte' | 'page' | 'slot' | 'log2byte' | 'count';
export type Basis = 'file' | 'slice' | 'blob' | 'none';

/** 领域量：始终携带单位与坐标基准；raw 保留导入时的原始表示。 */
export interface Quantity {
  value: number;
  unit: Unit;
  basis: Basis;
  raw?: string;
}

export interface Position {
  offset: Quantity;
  length?: Quantity;
}

export interface Diagnostic {
  code: string;
  message: string;
  position?: Position;
  /** 失败字节证据（hex），用于证据读回。 */
  fragmentHex?: string;
}

/** 资源预算耗尽 / 格式损坏 / 语义无解：三种必须可区分的结果。 */
export type FailureKind = 'budget_exhausted' | 'malformed' | 'unsatisfiable';

export type Result<T> =
  | { ok: true; value: T; diagnostics: Diagnostic[] }
  | { ok: false; kind: FailureKind; diagnostic: Diagnostic };

export function ok<T>(value: T, diagnostics: Diagnostic[] = []): Result<T> {
  return { ok: true, value, diagnostics };
}

export function fail<T>(kind: FailureKind, diagnostic: Diagnostic): Result<T> {
  return { ok: false, kind, diagnostic };
}

export function q(value: number, unit: Unit, basis: Basis, raw?: string): Quantity {
  return raw === undefined ? { value, unit, basis } : { value, unit, basis, raw };
}

export function hexOf(bytes: Uint8Array, start: number, length: number): string {
  const end = Math.min(bytes.length, start + length);
  const out: string[] = [];
  for (let i = Math.max(0, start); i < end; i++) {
    out.push(bytes[i]!.toString(16).padStart(2, '0'));
  }
  return out.join(' ');
}
