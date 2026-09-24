import { createHash } from 'node:crypto';

export function sha256Hex(data: Uint8Array): string {
  return createHash('sha256').update(data).digest('hex');
}

export function digestOf(value: unknown): string {
  return createHash('sha256').update(canonical(value)).digest('hex');
}

/** 规范化 JSON：键排序，保证等价输入产生稳定摘要与稳定顺序。 */
export function canonical(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value ?? null);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  const keys = Object.keys(value as Record<string, unknown>).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonical((value as Record<string, unknown>)[k])}`).join(',')}}`;
}

export function shortId(prefix: string, data: Uint8Array | string, suffix?: string | number): string {
  const h = typeof data === 'string' ? createHash('sha256').update(data).digest('hex') : sha256Hex(data);
  return `${prefix}_${h.slice(0, 16)}${suffix === undefined ? '' : `_${suffix}`}`;
}
