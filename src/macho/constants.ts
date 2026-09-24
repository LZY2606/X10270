// Mach-O / fat / code signature constants (subset used by this workbench).
// All values documented at <mach-o/fat.h>, <mach-o/loader.h>,
// <mach-o/codedirectory.h>.

export const MAGIC = {
  FAT_MAGIC: 0xcafebabe,
  FAT_CIGAM: 0xbebafeca,
  MH_MAGIC: 0xfeedface,
  MH_CIGAM: 0xcefaedfe,
  MH_MAGIC_64: 0xfeedfacf,
  MH_CIGAM_64: 0xcffaedfe,
} as const;

export const CPU_TYPE = {
  X86_64: 0x01000007,
  ARM64: 0x0100000c,
} as const;

export const CPU_SUBTYPE = {
  X86_64_ALL: 0x00000003,
  ARM64_ALL: 0x00000000,
} as const;

export function archName(cputype: number, cpusubtype: number): string {
  if (cputype === CPU_TYPE.X86_64) return 'x86_64';
  if (cputype === CPU_TYPE.ARM64) {
    if ((cpusubtype & 0x00ffffff) === 2) return 'arm64e';
    return 'arm64';
  }
  return `cputype:0x${cputype.toString(16)}/sub:0x${cpusubtype.toString(16)}`;
}

export function archKey(cputype: number, cpusubtype: number): string {
  return `${cputype >>> 0}:${cpusubtype >>> 0}`;
}

export const LC = {
  LC_REQ_DYLD: 0x80000000,
  LC_SEGMENT: 0x00000001,
  LC_SYMTAB: 0x00000002,
  LC_DYSYMTAB: 0x0000000b,
  LC_LOAD_DYLIB: 0x0000000c,
  LC_ID_DYLIB: 0x0000000d,
  LC_LOAD_DYLINKER: 0x0000000e,
  LC_UUID: 0x0000001b,
  LC_SEGMENT_64: 0x00000019,
  LC_CODE_SIGNATURE: 0x0000001d,
  LC_ENCRYPTION_INFO_64: 0x0000002c,
  LC_DYLD_EXPORTS_TRIE: 0x80000033,
  LC_DYLD_CHAINED_FIXUPS: 0x80000023,
} as const;

export function loadCommandName(cmd: number): string {
  const entry = Object.entries(LC).find(([, value]) => value === cmd);
  if (entry) return entry[0]!.toLowerCase();
  return `cmd:0x${cmd.toString(16)}`;
}

export const CS_MAGIC = {
  CSMAGIC_EMBEDDED_SIGNATURE: 0xfade0cc0,
  CSMAGIC_CODEDIRECTORY: 0xfade0c02,
  CSMAGIC_REQUIREMENT: 0xfade0c01,
  CSMAGIC_REQUIREMENTS: 0xfade0c05,
  CSMAGIC_ENTITLEMENTS: 0xfade7171,
  CSMAGIC_EMBEDDED_ENTITLEMENTS_DER: 0xfade7172,
  CSMAGIC_BLOBWRAPPER: 0xfade0b01,
} as const;

export function csMagicName(magic: number): string {
  const entry = Object.entries(CS_MAGIC).find(([, value]) => value === magic);
  return entry ? entry[0] : 'unknown';
}

export const CS_SLOT = {
  CSSLOT_CODEDIRECTORY: 0,
  CSSLOT_REQUIREMENTS: 2,
  CSSLOT_ENTITLEMENTS: 5,
  CSSLOT_DER_ENTITLEMENTS: 7,
  CSSLOT_SIGNATURESLOT: 0x10000,
} as const;

export function slotTypeName(type: number): string {
  switch (type) {
    case CS_SLOT.CSSLOT_CODEDIRECTORY:
      return 'code-directory';
    case CS_SLOT.CSSLOT_REQUIREMENTS:
      return 'requirements';
    case CS_SLOT.CSSLOT_ENTITLEMENTS:
      return 'entitlements';
    case CS_SLOT.CSSLOT_DER_ENTITLEMENTS:
      return 'der-entitlements';
    case CS_SLOT.CSSLOT_SIGNATURESLOT:
      return 'cms-signature';
    default:
      return `reserved-slot-${type}`;
  }
}

export const CS_HASH_TYPE = {
  SHA1: 1,
  SHA256_TRUNCATED: 2,
  SHA256: 3,
  SHA384: 4,
} as const;

export function hashAlgorithmName(hashType: number, hashSize: number): string {
  switch (hashType) {
    case CS_HASH_TYPE.SHA1:
      return 'sha1';
    case CS_HASH_TYPE.SHA256_TRUNCATED:
      return 'sha256-truncated-20';
    case CS_HASH_TYPE.SHA256:
      return hashSize === 32 ? 'sha256' : `sha256?hashSize=${hashSize}`;
    case CS_HASH_TYPE.SHA384:
      return 'sha384';
    default:
      return `unknown-${hashType}`;
  }
}

export function supportedHashType(hashType: number, hashSize: number): boolean {
  if (hashType === CS_HASH_TYPE.SHA1 && hashSize === 20) return true;
  if (hashType === CS_HASH_TYPE.SHA256_TRUNCATED && hashSize === 20) return true;
  if (hashType === CS_HASH_TYPE.SHA256 && hashSize === 32) return true;
  if (hashType === CS_HASH_TYPE.SHA384 && hashSize === 48) return true;
  return false;
}
