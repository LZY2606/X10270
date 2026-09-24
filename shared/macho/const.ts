export const FAT_MAGIC = 0xcafebabe;
export const FAT_CIGAM = 0xbebafeca; // byte-swapped fat magic
export const MH_MAGIC_64 = 0xfeedfacf;
export const MH_CIGAM_64 = 0xcffaedfe;

export const LC_SEGMENT_64 = 0x19;
export const LC_SYMTAB = 0x2;
export const LC_UUID = 0x1b;
export const LC_CODE_SIGNATURE = 0x1d;
export const LC_DYLD_CHAINED_FIXUPS = 0x34;

export const CSMAGIC_EMBEDDED_SIGNATURE = 0xfade0cc0;
export const CSMAGIC_CODEDIRECTORY = 0xfade0c02;
export const CSSLOT_CODEDIRECTORY = 0;

export const CPU_TYPES: Record<number, string> = {
  7: 'x86',
  0x01000007: 'x86_64',
  12: 'arm',
  0x0100000c: 'arm64',
};

export function archName(cputype: number, cpusubtype: number): string {
  const base = CPU_TYPES[cputype] ?? `cpu-${cputype}`;
  if (cputype === 0x0100000c && (cpusubtype & 0xffffff) === 2) return 'arm64e';
  return base;
}

export const LC_NAMES: Record<number, string> = {
  [LC_SEGMENT_64]: 'LC_SEGMENT_64',
  [LC_SYMTAB]: 'LC_SYMTAB',
  [LC_UUID]: 'LC_UUID',
  [LC_CODE_SIGNATURE]: 'LC_CODE_SIGNATURE',
  [LC_DYLD_CHAINED_FIXUPS]: 'LC_DYLD_CHAINED_FIXUPS',
};

export const HASH_TYPES: Record<number, { name: string; size: number }> = {
  1: { name: 'sha1', size: 20 },
  2: { name: 'sha256', size: 32 },
  3: { name: 'sha256-truncated', size: 20 },
  4: { name: 'sha384', size: 48 },
  5: { name: 'sha512', size: 64 },
};
