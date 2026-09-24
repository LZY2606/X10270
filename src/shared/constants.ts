/** Mach-O / fat / 嵌入式签名常量（显式保留字节序语义）。 */
export const MAGIC = {
  FAT_MAGIC: 0xcafebabe,
  FAT_CIGAM: 0xbebafeca,
  MH_MAGIC_64: 0xfeedfacf,
  MH_CIGAM_64: 0xcffaedfe,
  MH_MAGIC: 0xfeedface,
  MH_CIGAM: 0xcefaedfe,
} as const;

export const CPU = {
  ARM64: { cputype: 0x0100000c, cpusubtype: 0, label: 'arm64' },
  X86_64: { cputype: 0x01000007, cpusubtype: 3, label: 'x86_64' },
  ARM64E: { cputype: 0x0100000c, cpusubtype: 2, label: 'arm64e' },
} as const;

export const LC = {
  LC_SEGMENT: 0x1,
  LC_SYMTAB: 0x2,
  LC_DYSYMTAB: 0xb,
  LC_UUID: 0x1b,
  LC_SEGMENT_64: 0x19,
  LC_CODE_SIGNATURE: 0x1d,
} as const;

export const CS = {
  CSMAGIC_EMBEDDED_SIGNATURE: 0xfade0cc0,
  CSMAGIC_CODEDIRECTORY: 0xfade0c02,
  CS_HASHTYPE_SHA1: 1,
  CS_HASHTYPE_SHA256: 2,
  CS_HASHTYPE_SHA256_TRUNCATED: 3,
  CSSLOT_CODEDIRECTORY: 0,
} as const;

export const SEG_LINKEDIT = '__LINKEDIT';
export const SEG_TEXT = '__TEXT';

/** 规则引擎版本（规则修订独立于参数版本） */
export const RULE_VERSION = 'rules-2026.1-fat-lc-cs';
