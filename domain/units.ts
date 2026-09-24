// 领域量：所有数值都携带单位与坐标基准；原始表示在导入时保留，派生层才规范化。
export type Unit = 'byte' | 'page' | 'slot' | 'count' | 'align-exp' | 'hex' | 'utf8';
export type Basis = 'file' | 'slice' | 'blob' | 'none';

export interface Diagnostic {
  code: string;            // 机器可读诊断码
  pos: string;             // 位置，例如 "slice[1].offset" 或 "file@0x1000"
  message: string;
}

export interface Quantity {
  raw: string;             // 导入时的原始表示（如 "0x00004000"、"16384"）
  unit: Unit;
  basis: Basis;
  value: number | null;    // 规范化后的数值；无法转换时保持 null
  diagnostic?: Diagnostic; // 无法转换时留在原位置并附诊断
}

export function qty(raw: string, unit: Unit, basis: Basis): Quantity {
  const value = parseRaw(raw);
  if (value === null) {
    return { raw, unit, basis, value: null,
      diagnostic: { code: 'QTY_UNPARSEABLE', pos: basis, message: `无法将 "${raw}" 规范化为 ${unit}` } };
  }
  return { raw, unit, basis, value };
}

function parseRaw(raw: string): number | null {
  const t = raw.trim();
  if (/^0x[0-9a-fA-F]+$/.test(t)) return Number.parseInt(t, 16);
  if (/^[0-9]+$/.test(t)) return Number.parseInt(t, 10);
  return null;
}

export function hex(n: number, width = 0): string {
  return '0x' + n.toString(16).padStart(width, '0');
}
