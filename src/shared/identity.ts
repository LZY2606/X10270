// Deterministic, content-based stable identities. Equivalent inputs must yield
// equivalent ids and equivalent ordering; ids survive export/delete/reimport.

import { sha256Hex } from './sha256';

export function digestHex(input: Uint8Array): string {
  return sha256Hex(input);
}

export function shortDigest(hex: string, len = 12): string {
  return hex.slice(0, len);
}

/** Deterministic id: `<kind>:<imageTag>:<coordinate path>:<content digest>`. */
export function stableId(kind: string, parts: (string | number)[]): string {
  const path = parts
    .map((p) => String(p))
    .join('/')
    .replace(/[^A-Za-z0-9._:-]+/g, '_');
  return `${kind}:${path}`;
}

export const CPU_NAMES: Record<number, { family: string; arch: string }> = {
  0x01000007: { family: 'x86_64', arch: 'x86_64' },
  0x0100000c: { family: 'arm64', arch: 'arm64' },
  0x0100000d: { family: 'arm64', arch: 'arm64e' },
};

export function archKey(cpuType: number, cpuSubtype: number): string {
  const known = CPU_NAMES[cpuType];
  if (known) {
    // arm64e distinguishes itself via subtype 2 on arm64 in our fixtures.
    if (cpuType === 0x0100000c && cpuSubtype === 2) return 'arm64e';
    return known.arch;
  }
  return `cpu_${cpuType.toString(16).padStart(8, '0')}_sub_${cpuSubtype.toString(16).padStart(8, '0')}`;
}

export function archLabel(cpuType: number, cpuSubtype: number): string {
  return archKey(cpuType, cpuSubtype);
}

export const LC_NAMES: Record<number, string> = {
  0x19: 'LC_SEGMENT_64',
  0x1d: 'LC_CODE_SIGNATURE',
  0x80000022: 'LC_LOAD_DYLIB',
  0x2: 'LC_SYMTAB',
  0xb: 'LC_DYSYMTAB',
  0x80000018: 'LC_LOAD_WEAK_DYLIB',
  0x32: 'LC_MAIN',
};

export function loadCommandName(cmd: number): string {
  return LC_NAMES[cmd] ?? `LC_0x${cmd.toString(16).padStart(8, '0')}`;
}

export const BLOB_TYPE_NAMES: Record<number, string> = {
  0: 'CodeDirectory',
  2: 'Requirements',
  0x7ade7101: 'DRMApplicationSpecific',
};

export function blobTypeName(type: number): string {
  return BLOB_TYPE_NAMES[type] ?? `UnknownBlobType_0x${type.toString(16).padStart(8, '0')}`;
}

/** Equivalent-input ordering: index then coordinate then identity. */
export function compareByIndex<T extends { [k: string]: unknown }>(
  rows: T[],
  keys: (keyof T)[],
): T[] {
  return [...rows].sort((a, b) => {
    for (const key of keys) {
      const av = a[key];
      const bv = b[key];
      if (typeof av === 'number' && typeof bv === 'number') {
        if (av !== bv) return av - bv;
      } else {
        const as = String(av);
        const bs = String(bv);
        if (as !== bs) return as < bs ? -1 : 1;
      }
    }
    return 0;
  });
}
