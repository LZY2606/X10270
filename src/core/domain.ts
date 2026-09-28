import { createHash } from 'node:crypto';
import type { CoordinateBasis, DomainValue } from '../shared/types.js';

let hex = (n: number | bigint): string => '0x' + n.toString(16);

export function dv(
  raw: string,
  value: number | null,
  unit: string,
  basis: CoordinateBasis,
  diagnostic?: string,
): DomainValue {
  return { raw, value, unit, basis, diagnostic };
}

export const bytes = (n: number, basis: CoordinateBasis = 'slice-local') =>
  dv(hex(n), n, 'byte', basis);
export const count = (n: number, label = 'count') => dv(`${n}`, n, label, 'slice-local');
export const flagNum = (n: number) => dv(hex(n), n >>> 0, 'bitmask', 'slice-local');

/** content-addressed stable identity; deterministic for equivalent inputs */
export function cid(kind: string, parts: Array<string | number | boolean | null | undefined>): string {
  const h = createHash('sha256');
  h.update(kind);
  h.update('\0');
  for (const p of parts) {
    h.update(String(p));
    h.update('|');
  }
  return `${kind}_${h.digest('hex').slice(0, 16)}`;
}

export function sha256Parts(parts: Array<string | number | boolean | null | undefined>): string {
  return cid('h', parts).slice(2);
}
