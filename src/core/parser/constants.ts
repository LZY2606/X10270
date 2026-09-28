// Fat container
export const FAT_MAGIC = 0xcafebabe;
export const FAT_CIGAM = 0xbebafeca; // big-endian on-disk bytes read as little-endian u32
export const FAT_MAGIC_64 = 0xcafebabf;
export const FAT_CIGAM_64 = 0xbfbafeca;

// Mach-O
export const MH_MAGIC = 0xfeedface;
export const MH_CIGAM = 0xcefaedfe;
export const MH_MAGIC_64 = 0xfeedfacf;
export const MH_CIGAM_64 = 0xcffaedfe;

export const LC_REQ_DYLD = 0x80000000;
export const LC_SEGMENT = 0x1;
export const LC_SYMTAB = 0x2;
export const LC_DYSYMTAB = 0xb;
export const LC_SEGMENT_64 = 0x19;
export const LC_CODE_SIGNATURE = 0x1d;
export const LC_ENCRYPTION_INFO = 0x21;
export const LC_DYLD_INFO = 0x22;
export const LC_DYLD_INFO_ONLY = 0x80000022;
export const LC_FUNCTION_STARTS = 0x26;
export const LC_DATA_IN_CODE = 0x29;
export const LC_SOURCE_VERSION = 0x2a;
export const LC_VERSION_MIN_MACOSX = 0x24;
export const LC_DYLD_CHAINED_FIXUPS = 0x80000034;
export const LC_DYLD_EXPORTS_TRIE = 0x80000033;

export function loadCommandName(cmd: number): string {
  switch (cmd >>> 0) {
    case LC_SEGMENT: return 'LC_SEGMENT';
    case LC_SYMTAB: return 'LC_SYMTAB';
    case LC_DYSYMTAB: return 'LC_DYSYMTAB';
    case LC_SEGMENT_64: return 'LC_SEGMENT_64';
    case LC_CODE_SIGNATURE: return 'LC_CODE_SIGNATURE';
    case LC_ENCRYPTION_INFO: return 'LC_ENCRYPTION_INFO';
    case LC_DYLD_INFO: return 'LC_DYLD_INFO';
    case LC_DYLD_INFO_ONLY: return 'LC_DYLD_INFO_ONLY';
    case LC_FUNCTION_STARTS: return 'LC_FUNCTION_STARTS';
    case LC_DATA_IN_CODE: return 'LC_DATA_IN_CODE';
    case LC_SOURCE_VERSION: return 'LC_SOURCE_VERSION';
    case LC_VERSION_MIN_MACOSX: return 'LC_VERSION_MIN_MACOSX';
    case LC_DYLD_CHAINED_FIXUPS: return 'LC_DYLD_CHAINED_FIXUPS';
    case LC_DYLD_EXPORTS_TRIE: return 'LC_DYLD_EXPORTS_TRIE';
    default:
      return (cmd & LC_REQ_DYLD) ? `LC_REQ_DYLD_0x${(cmd ^ LC_REQ_DYLD).toString(16)}`
                                 : `LC_0x${cmd.toString(16)}`;
  }
}

// cpu types (subset)
export const CPU_ARCH_ABI64 = 0x01000000;
export const CPU_TYPE_X86 = 7;
export const CPU_TYPE_X86_64 = CPU_TYPE_X86 | CPU_ARCH_ABI64;
export const CPU_TYPE_ARM = 12;
export const CPU_TYPE_ARM64 = CPU_TYPE_ARM | CPU_ARCH_ABI64;

export function archName(cpuType: number, cpuSubtype: number): string {
  const sub = cpuSubtype >>> 0;
  switch (cpuType >>> 0) {
    case CPU_TYPE_X86_64: return 'x86_64';
    case CPU_TYPE_ARM64:
      if (sub === 2) return 'arm64e';
      return 'arm64';
    case CPU_TYPE_X86: return 'i386';
    case CPU_TYPE_ARM: return 'arm';
    default: return `cpu_${cpuType >>> 0}:${sub}`;
  }
}

// Embedded signature blobs are big-endian.
export const CSMAGIC_EMBEDDED_SIGNATURE = 0xfade0cc0;
export const CSMAGIC_DETACHED_SIGNATURE = 0xfade0cc1;
export const CSMAGIC_CODEDIRECTORY = 0xfade0c02;
export const CSMAGIC_REQUIREMENTS = 0xfade0c01;
export const CSMAGIC_ENTITLEMENTS = 0xfade7171;
export const CSMAGIC_BLOBWRAPPER = 0xfade0b01;

export const CS_HASHTYPE_SHA1 = 1;
export const CS_HASHTYPE_SHA256 = 2;
export function hashTypeName(t: number): string {
  switch (t) {
    case CS_HASHTYPE_SHA1: return 'SHA-1';
    case CS_HASHTYPE_SHA256: return 'SHA-256';
    default: return `unsupported-hashtype-${t}`;
  }
}

// Blob slot types in a CS_SuperBlob
export const CSSLOT_CODEDIRECTORY = 0;
export const CSSLOT_REQUIREMENTS = 2;
export const CSSLOT_ENTITLEMENTS = 5;
export const CSSLOT_DER_ENTITLEMENTS = 7;
export function blobTypeName(type: number): string {
  switch (type) {
    case CSSLOT_CODEDIRECTORY: return 'CodeDirectory';
    case CSSLOT_REQUIREMENTS: return 'Requirements';
    case CSSLOT_ENTITLEMENTS: return 'Entitlements';
    case CSSLOT_DER_ENTITLEMENTS: return 'DER-Entitlements';
    default: return `blob-slot-${type}`;
  }
}
export function isKnownBlobType(type: number): boolean {
  return [0, 2, 5, 7].includes(type);
}

export const MH_EXECUTE = 2;
export const MH_DYLIB = 6;
