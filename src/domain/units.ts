// Domain quantities always carry their unit and coordinate basis.
// The raw representation as imported is preserved; normalization happens
// only in this derived layer. Unconvertible values stay in place with a
// diagnostic and are never silently replaced by defaults.

export type Unit = 'byte' | 'page' | 'slot' | 'count' | 'exponent' | 'none';
export type Basis = 'file' | 'slice' | 'blob' | 'directory';

export interface Quantity {
  raw: string;
  unit: Unit;
  basis: Basis;
  value: number | null;
  diagnostic: string | null;
}

export function quantity(raw: string | number | bigint, unit: Unit, basis: Basis): Quantity {
  const rawStr = typeof raw === 'bigint' ? raw.toString() : String(raw);
  let parsed: number;
  if (typeof raw === 'number') {
    parsed = raw;
  } else {
    const text = rawStr.trim();
    if (/^0x[0-9a-f]+$/i.test(text)) parsed = Number(BigInt(text));
    else if (/^[0-9]+$/.test(text)) parsed = Number(text);
    else parsed = NaN;
  }
  if (!Number.isFinite(parsed)) {
    return { raw: rawStr, unit, basis, value: null, diagnostic: `value.unconvertible: "${rawStr}" 不是可解析的 ${unit} 数值，保留原始表示` };
  }
  if (!Number.isSafeInteger(parsed)) {
    return { raw: rawStr, unit, basis, value: null, diagnostic: `value.unconvertible: "${rawStr}" 超出安全整数范围，保留原始表示` };
  }
  return { raw: rawStr, unit, basis, value: parsed, diagnostic: null };
}

// Alignment exponents are normalized to a byte count only when exactly
// representable. We never round an offset up to satisfy alignment.
export function alignmentBytes(alignExp: Quantity): { value: number | null; diagnostic: string | null } {
  if (alignExp.value === null) return { value: null, diagnostic: alignExp.diagnostic };
  if (alignExp.value < 0 || alignExp.value > 53) {
    return { value: null, diagnostic: `alignment.exponent.unsupported: 2^${alignExp.raw} 超出可精确表示范围 (0..53)，保留原值不做四舍五入` };
  }
  return { value: 2 ** alignExp.value, diagnostic: null };
}
