import { createHash } from 'node:crypto';

/** 规范化 JSON：键排序，保证等价输入得到等价摘要。 */
export function canonical(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonical(obj[k])).join(',') + '}';
}

export function sha256Hex(data: Buffer | string): string {
  return createHash('sha256').update(data).digest('hex');
}

export function contentId(prefix: string, value: unknown): string {
  return `${prefix}_${sha256Hex(canonical(value)).slice(0, 16)}`;
}
