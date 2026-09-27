/**
 * Domain quantities always carry a unit or coordinate basis.
 * Raw representation is preserved at import; normalization happens only in the derived layer.
 */
export interface Quantity {
  /** raw representation exactly as imported, e.g. "0x1000", "4096", "4KiB" */
  raw: string;
  /** unit or coordinate basis, e.g. "byte", "page", "cpu-type-code", "slot-index" */
  unit: string;
  /** normalized numeric value in the declared unit; null when not convertible */
  value: number | null;
}

export function qty(raw: string | number, unit: string, value?: number | null): Quantity {
  const rawStr = String(raw);
  if (value !== undefined) return { raw: rawStr, unit, value };
  return { raw: rawStr, unit, value: parseQuantity(rawStr) };
}

/** Lenient parser for raw quantity strings; returns null when not convertible. */
export function parseQuantity(raw: string): number | null {
  const t = raw.trim();
  if (/^0x[0-9a-fA-F]+$/.test(t)) return Number.parseInt(t, 16);
  if (/^-?\d+$/.test(t)) return Number.parseInt(t, 10);
  return null;
}

export interface RangeQ {
  offset: Quantity;
  size: Quantity;
}

export function rangeEnd(r: RangeQ): number | null {
  if (r.offset.value === null || r.size.value === null) return null;
  return r.offset.value + r.size.value;
}
