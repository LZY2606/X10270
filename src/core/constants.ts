// Mach-O / fat / code-signature constants used by the parser and the synthetic
// fixture builder. Values mirror the on-disk formats described in <mach-o/loader.h>,
// <mach-o/fat.h> and <mach-o/codesign.h> closely enough for offline review.

export const MH_MAGIC = 0xfeedface;
export const MH_CIGAM = 0xcefaedfe;
export const MH_MAGIC_64 = 0xfeedfacf;
export const MH_CIGAM_64 = 0xcffaedfe;

export const FAT_MAGIC = 0xcafebabe;
export const FAT_CIGAM = 0xbebafeca;
export const FAT_MAGIC_64 = 0xcafebabf;
export const FAT_CIGAM_64 = 0xbfbafeca;

export const LC_REQ_DYLD = 0x80000000;
export const LC_SEGMENT = 0x1;
export const LC_SEGMENT_64 = 0x19;
export const LC_UUID = 0x1b;
export const LC_CODE_SIGNATURE = 0x1d;
export const LC_ENCRYPTION_INFO_64 = 0x2c;
export const LC_LINKER_OPTION = 0x2d;
export const LC_MAIN = 0x80000028;

export function loadCommandName(cmd: number): string {
  switch (cmd) {
    case LC_SEGMENT: return 'LC_SEGMENT';
    case LC_SEGMENT_64: return 'LC_SEGMENT_64';
    case LC_UUID: return 'LC_UUID';
    case LC_CODE_SIGNATURE: return 'LC_CODE_SIGNATURE';
    case LC_ENCRYPTION_INFO_64: return 'LC_ENCRYPTION_INFO_64';
    case LC_LINKER_OPTION: return 'LC_LINKER_OPTION';
    case LC_MAIN: return 'LC_MAIN';
    default:
      return (cmd & LC_REQ_DYLD) ? `LC_REQ_DYLD_0x${(cmd ^ LC_REQ_DYLD).toString(16)}` : `LC_UNKNOWN_0x${cmd.toString(16)}`;
  }
}

// cpu_type_t / cpu_subtype_t (subset, enough for universal-binary review)
export const CPU_ARCH_ABI64 = 0x01000000;
export const CPU_TYPE_X86 = 7;
export const CPU_TYPE_X86_64 = CPU_TYPE_X86 | CPU_ARCH_ABI64;
export const CPU_TYPE_ARM = 12;
export const CPU_TYPE_ARM64 = CPU_TYPE_ARM | CPU_ARCH_ABI64;
export const CPU_SUBTYPE_ARM64_ALL = 0;
export const CPU_SUBTYPE_X86_64_ALL = 3;
export const CPU_SUBTYPE_X86_64_H = 8;

export function archName(cpuType: number, cpuSubtype: number): string {
  if (cpuType === CPU_TYPE_ARM64) return 'arm64';
  if (cpuType === CPU_TYPE_X86_64) return cpuSubtype === CPU_SUBTYPE_X86_64_H ? 'x86_64h' : 'x86_64';
  if (cpuType === CPU_TYPE_ARM) return 'arm';
  if (cpuType === CPU_TYPE_X86) return 'i386';
  return `unknown(cputype=0x${cpuType.toString(16)},cpusubtype=0x${cpuSubtype.toString(16)})`;
}

// Embedded code-signature blob magic numbers (CSMAGIC_*).
export const CSMAGIC_REQUIREMENT = 0xfade0c00;
export const CSMAGIC_REQUIREMENTS = 0xfade0c01;
export const CSMAGIC_CODEDIRECTORY = 0xfade0c02;
export const CSMAGIC_EMBEDDED_SIGNATURE = 0xfade0cc0;
export const CSMAGIC_DETACHED_SIGNATURE = 0xfade0cc1;
export const CSMAGIC_ENTITLEMENTS = 0xfade7171;
export const CSMAGIC_EMBEDDED_ENTITLEMENTS = 0xfade7172;
export const CSMAGIC_BLOBWRAPPER = 0xfade0b01;

export const CS_SUPPORTED_BLOB_MAGICS = new Set<number>([
  CSMAGIC_REQUIREMENT,
  CSMAGIC_REQUIREMENTS,
  CSMAGIC_CODEDIRECTORY,
  CSMAGIC_ENTITLEMENTS,
  CSMAGIC_EMBEDDED_ENTITLEMENTS,
  CSMAGIC_BLOBWRAPPER,
]);

export const CSSLOT_CODEDIRECTORY = 0;
export const CSSLOT_REQUIREMENTS = 2;
export const CSSLOT_ENTITLEMENTS = 5;
export const CSSLOT_DER_ENTITLEMENTS = 7;

export function codeSlotName(slot: number): string {
  switch (slot) {
    case 0: return 'CodeDirectory';
    case 1: return 'Info.plist';
    case 2: return 'Requirements';
    case 3: return 'MacResources';
    case 4: return 'MacApplication';
    case 5: return 'Entitlements';
    case 6: return 'DYLIBCodeDirectory';
    case 7: return 'DER-Entitlements';
    case 8: return 'Signature';
    default: return slot < 0 ? `special(${slot})` : `special(${slot})`;
  }
}

export const CS_HASHTYPE_NO_HASH = 0;
export const CS_HASHTYPE_SHA1 = 1;
export const CS_HASHTYPE_SHA256 = 2;
export const CS_HASHTYPE_SHA256_TRUNCATED = 3;
export const CS_HASHTYPE_SHA384 = 4;

export function hashTypeName(t: number): string {
  return ({
    0: 'none', 1: 'sha1', 2: 'sha256', 3: 'sha256-truncated', 4: 'sha384',
  } as Record<number, string>)[t] ?? `unsupported-hashtype-${t}`;
}

export const HASH_ALGO_LENGTH: Record<number, number> = {
  [CS_HASHTYPE_SHA1]: 20,
  [CS_HASHTYPE_SHA256]: 32,
  [CS_HASHTYPE_SHA256_TRUNCATED]: 20,
  [CS_HASHTYPE_SHA384]: 48,
};

// CodeDirectory version floor/ceiling that this reviewer understands.
export const CS_SUPPORTED_CODEDIRECTORY_VERSIONS = new Set([0x20100, 0x20200, 0x20400, 0x20500]);

// Unit / coordinate basis labels travel with every domain value.
export const UNIT_BYTES = 'bytes';
export const BASIS_FILE_ABSOLUTE = 'absolute-file-offset';
export const BASIS_SLICE_RELATIVE = 'slice-relative-offset';
export const BASIS_PAGE = 'page-index';
export const BASIS_POW2 = 'power-of-two-exponent';
