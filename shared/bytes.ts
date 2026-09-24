import { createHash } from 'node:crypto';

export function sha256Hex(data: Uint8Array): string {
  return createHash('sha256').update(data).digest('hex');
}

export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortValue(value));
}

function sortValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortValue);
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      out[key] = sortValue((value as Record<string, unknown>)[key]);
    }
    return out;
  }
  return value;
}

export function checksumOf(value: unknown): string {
  return sha256Hex(new TextEncoder().encode(canonicalJson(value)));
}

// Deterministic stable identity: id("slice", projectId, "arm64") etc.
export function stableId(kind: string, ...parts: (string | number)[]): string {
  const basis = `${kind}|${parts.map(String).join('|')}`;
  return `${kind}-${createHash('sha256').update(basis).digest('hex').slice(0, 16)}`;
}

export function bytesFromHex(hex: string): Uint8Array {
  const clean = hex.replace(/\s+/g, '');
  if (clean.length % 2 !== 0) throw new Error('odd-length hex input');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i]! = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function hexFromBytes(
  bytes: Uint8Array,
  offset = 0,
  length?: number,
): string {
  const end = length === undefined ? bytes.length : Math.min(bytes.length, offset + length);
  let out = '';
  for (let i = offset; i < end; i++) out += bytes[i]!.toString(16).padStart(2, '0');
  return out;
}

export function asciiHex(text: string): string {
  return hexFromBytes(new TextEncoder().encode(text));
}
