import { createHash } from 'node:crypto';

export function sha256(data: Buffer | string): string {
  const buf = typeof data === 'string' ? Buffer.from(data, 'utf8') : data;
  return createHash('sha256').update(buf).digest('hex');
}

export function shortId(prefix: string, data: Buffer | string): string {
  return `${prefix}-${sha256(data).slice(0, 12)}`;
}
