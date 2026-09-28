import { createHash } from 'node:crypto';

export function sha256Hex(data: Uint8Array | string): string {
  const buf = typeof data === 'string' ? Buffer.from(data, 'utf8') : Buffer.from(data);
  return createHash('sha256').update(buf).digest('hex');
}

export function shortHash(data: Uint8Array | string): string {
  return sha256Hex(data).slice(0, 12);
}

export function stableId(...parts: Array<string | number | bigint>): string {
  return parts
    .map((p) => (typeof p === 'bigint' ? `b${p.toString(16)}` : String(p)))
    .join('/');
}
