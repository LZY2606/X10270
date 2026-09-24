import { createHash } from 'node:crypto';

export function sha256hex(data: Buffer | string): string {
  return createHash('sha256').update(data).digest('hex');
}

/** Deterministic stringify: object keys sorted recursively. */
export function canonical(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null';
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  const rec = value as Record<string, unknown>;
  const keys = Object.keys(rec).sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonical(rec[k])).join(',') + '}';
}

/** Content-addressed stable identity: `<prefix>_<sha256[:16]>`. */
export function contentId(prefix: string, value: unknown): string {
  return `${prefix}_${sha256hex(canonical(value)).slice(0, 16)}`;
}
