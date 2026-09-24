export const MAGIC_FAT = 0xcafebabe;
export const MAGIC_FAT_BE = 0xcafebabe;
export const MAGIC_FAT_64 = 0xcafebabf;

export const MH_MAGIC = 0xfeedface;
export const MH_CIGAM = 0xcefaedfe;
export const MH_MAGIC_64 = 0xfeedfacf;
export const MH_CIGAM_64 = 0xcffaedfe;

export const CPU_ARCH_ABI64 = 0x01000000;
export const CPU_TYPE_X86 = 0x00000007;
export const CPU_TYPE_X86_64 = 0x01000007;
export const CPU_TYPE_ARM = 0x0000000c;
export const CPU_TYPE_ARM64 = 0x0100000c;

export const CPU_SUBTYPE_X86_64_ALL = 0x00000003;
export const CPU_SUBTYPE_ARM64_ALL = 0x00000000;
export const CPU_SUBTYPE_ARM64_V8 = 0x00000000;

export const MH_EXECUTE = 2;

export const LC_REQ_DYLD = 0x80000000;
export const LC_SEGMENT = 0x00000001;
export const LC_SEGMENT_64 = 0x00000019;
export const LC_CODE_SIGNATURE = 0x0000001d;
export const LC_SYMTAB = 0x00000002;
export const LC_DYSYMTAB = 0x0000000b;
export const LC_UUID = 0x0000001b;
export const LC_BUILD_VERSION = 0x00000032;
export const LC_DYLD_INFO_ONLY = LC_REQ_DYLD | 0x0f;
export const LC_LOAD_DYLINKER = 0x8000000e;

export function cmdName(cmd: number): string {
  switch (cmd) {
    case LC_SEGMENT:
      return 'LC_SEGMENT';
    case LC_SEGMENT_64:
      return 'LC_SEGMENT_64';
    case LC_CODE_SIGNATURE:
      return 'LC_CODE_SIGNATURE';
    case LC_SYMTAB:
      return 'LC_SYMTAB';
    case LC_DYSYMTAB:
      return 'LC_DYSYMTAB';
    case LC_UUID:
      return 'LC_UUID';
    case LC_BUILD_VERSION:
      return 'LC_BUILD_VERSION';
    case LC_DYLD_INFO_ONLY:
      return 'LC_DYLD_INFO_ONLY';
    case LC_LOAD_DYLINKER:
      return 'LC_LOAD_DYLINKER';
    default:
      return cmd >= LC_REQ_DYLD ? `LC_REQ_DYLD_0x${(cmd & ~LC_REQ_DYLD).toString(16)}` : `LC_0x${cmd.toString(16)}`;
  }
}

export function archName(cpuType: number, cpuSubtype: number): string {
  if (cpuType === CPU_TYPE_ARM64) return 'arm64';
  if (cpuType === CPU_TYPE_X86_64) return 'x86_64';
  if (cpuType === CPU_TYPE_ARM) return `arm${cpuSubtype}`;
  if (cpuType === CPU_TYPE_X86) return `x86-${cpuSubtype}`;
  return `cputype-0x${cpuType.toString(16)}:sub-${cpuSubtype}`;
}

export const CSMAGIC_EMBEDDED_SIGNATURE = 0xfade0cc0;
export const CSMAGIC_CODEDIRECTORY = 0xfade0c02;
export const CSMAGIC_REQUIREMENTS = 0xfade0c01;
export const CSMAGIC_ENTITLEMENTS = 0xfade7171;
export const CSMAGIC_BLOBWRAPPER = 0xfade0b01;

export const CSSLOT_CODEDIRECTORY = 0;
export const CSSLOT_REQUIREMENTS = 2;
export const CSSLOT_ENTITLEMENTS = 5;
export const CSSLOT_DER_ENTITLEMENTS = 7;

export function slotName(type: number): string {
  switch (type) {
    case 0:
      return 'CSSLOT_CODEDIRECTORY';
    case 2:
      return 'CSSLOT_REQUIREMENTS';
    case 5:
      return 'CSSLOT_ENTITLEMENTS';
    case 7:
      return 'CSSLOT_DER_ENTITLEMENTS';
    default:
      return `UNKNOWN_SLOT_0x${type.toString(16)}`;
  }
}

export const CS_HASHTYPE_SHA1 = 1;
export const CS_HASHTYPE_SHA256 = 2;
export const CS_HASHTYPE_SHA256_TRUNCATED = 3;

export function hashName(type: number): string {
  switch (type) {
    case CS_HASHTYPE_SHA1:
      return 'sha1';
    case CS_HASHTYPE_SHA256:
      return 'sha256';
    case CS_HASHTYPE_SHA256_TRUNCATED:
      return 'sha256Truncated20';
    default:
      return `unknownHash-0x${type.toString(16)}`;
  }
}

export const MACH_HEADER_SIZE_32 = 28;
export const MACH_HEADER_SIZE_64 = 32;
export const CODE_SIGNATURE_LINKSIZE = 16;
