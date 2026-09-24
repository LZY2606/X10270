import { createHash } from 'node:crypto';

export function sha256Hex(data: Uint8Array | string): string {
  const h = createHash('sha256');
  h.update(typeof data === 'string' ? Buffer.from(data, 'utf8') : data);
  return h.digest('hex');
}

export function shortId(prefix: string, data: string, len = 12): string {
  return `${prefix}-${sha256Hex(data).slice(0, len)}`;
}
