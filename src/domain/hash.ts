import { createHash } from 'node:crypto';

export function sha256hex(data: Uint8Array): string {
  return createHash('sha256').update(data).digest('hex');
}

export function sha1hex(data: Uint8Array): string {
  return createHash('sha1').update(data).digest('hex');
}

export function hashHex(kind: 'sha256' | 'sha1', data: Uint8Array): string {
  return kind === 'sha1' ? sha1hex(data) : sha256hex(data);
}

// Content-derived stable identity. Equivalent inputs produce equivalent ids.
export function stableId(prefix: string, ...parts: (string | number)[]): string {
  const digest = createHash('sha256').update(parts.join('|')).digest('hex').slice(0, 12);
  return `${prefix}_${digest}`;
}

export function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}
