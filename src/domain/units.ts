/** 领域量单位与坐标基准：所有领域量必须携带单位与坐标基准。 */
export type Unit = 'byte' | 'page' | 'slot' | 'count';
export type Basis = 'file-offset' | 'slice-offset' | 'blob-offset' | 'index';

export interface Quantity {
  value: number;
  unit: Unit;
  basis: Basis;
}

export const qty = (value: number, unit: Unit, basis: Basis): Quantity => ({ value, unit, basis });

export interface ByteRange {
  start: Quantity;
  end: Quantity; // 半开区间 [start, end)
}

export const byteRange = (start: number, end: number, basis: Basis): ByteRange => ({
  start: qty(start, 'byte', basis),
  end: qty(end, 'byte', basis),
});

export interface Diagnostic {
  code: string;
  message: string;
  range?: ByteRange;
  /** 原始表示（导入时保留，不做规范化） */
  rawHex?: string;
}

/** 原始标量：保留原始字节表示与字节序，派生层才规范化为 value；无法转换时 value=null 并附诊断。 */
export interface RawScalar {
  rawHex: string;
  rawEndian: 'big' | 'little' | 'unknown';
  value: number | null;
  diagnostic?: string;
}

export type ResultKind = 'ok' | 'budget_exhausted' | 'format_corrupt' | 'semantics_unsolvable';
