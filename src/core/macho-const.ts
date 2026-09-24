// Subset of <mach-o/loader.h> constants used by the parser.

export const MH_MAGIC = 0xfeedface;
export const MH_CIGAM = 0xcefaedfe;
export const MH_MAGIC_64 = 0xfeedfacf;
export const MH_CIGAM_64 = 0xcffaedfe;

export const FAT_MAGIC = 0xcafebabe;
export const FAT_CIGAM = 0xbebafeca;
export const FAT_MAGIC_64 = 0xcafebabf;
export const FAT_CIGAM_64 = 0xbfbafeca;

export const CPU_ARCH_ABI64 = 0x01000000;
export const CPU_TYPE_X86 = 7;
export const CPU_TYPE_X86_64 = CPU_TYPE_X86 | CPU_ARCH_ABI64;
export const CPU_TYPE_ARM = 12;
export const CPU_TYPE_ARM64 = CPU_TYPE_ARM | CPU_ARCH_ABI64;

// cpu subtype mask for ARM64e capabilities.
export const CPU_SUBTYPE_PTRAUTH_ABI = 0x80000000;
export const CPU_SUBTYPE_ARM64_ALL = 0;
export const CPU_SUBTYPE_ARM64E = 2;
export const CPU_SUBTYPE_X86_64_ALL = 3;
export const CPU_SUBTYPE_X86_ALL = 3;

export const LC_REQ_DYLD = 0x80000000;

export const LC_SEGMENT = 0x1;
export const LC_SYMTAB = 0x2;
export const LC_DYSYMTAB = 0xb;
export const LC_UUID = 0x1b;
export const LC_SEGMENT_64 = 0x19;
export const LC_CODE_SIGNATURE = 0x1d;
export const LC_BUILD_VERSION = 0x32;
export const LC_VERSION_MIN_MACOSX = 0x24;

export const LOAD_COMMAND_NAMES: Record<number, string> = {
  [LC_SEGMENT]: "LC_SEGMENT",
  [LC_SYMTAB]: "LC_SYMTAB",
  [LC_DYSYMTAB]: "LC_DYSYMTAB",
  [LC_UUID]: "LC_UUID",
  [LC_SEGMENT_64]: "LC_SEGMENT_64",
  [LC_CODE_SIGNATURE]: "LC_CODE_SIGNATURE",
  [LC_BUILD_VERSION]: "LC_BUILD_VERSION",
  [LC_VERSION_MIN_MACOSX]: "LC_VERSION_MIN_MACOSX",
};

export function cpuName(cputype: number, cpusubtype: number): string {
  const sub = cpusubtype >>> 0;
  switch (cputype >>> 0) {
    case CPU_TYPE_ARM64:
      if ((sub & CPU_SUBTYPE_PTRAUTH_ABI) !== 0 && (sub & 0xff) === CPU_SUBTYPE_ARM64E) {
        return "arm64e";
      }
      return "arm64";
    case CPU_TYPE_X86_64:
      return "x86_64";
    case CPU_TYPE_X86:
      return "i386";
    case CPU_TYPE_ARM:
      return "arm";
    default:
      return `cputype:0x${(cputype >>> 0).toString(16)}:0x${sub.toString(16)}`;
  }
}

// Code signature blobs
export const CSMAGIC_EMBEDDED_SIGNATURE = 0xfade0cc0;
export const CSMAGIC_CODEDIRECTORY = 0xfade0c02;
export const CSMAGIC_REQUIREMENTS = 0xfade0c01;
export const CSMAGIC_EMBEDDED_ENTITLEMENTS = 0xfade7171;
export const CSMAGIC_BLOBWRAPPER = 0xfade0b01;

export const CSSLOT_CODEDIRECTORY = 0;
export const CSSLOT_REQUIREMENTS = 2;
export const CSSLOT_ENTITLEMENTS = 5;

export const BLOB_TYPE_NAMES: Record<number, string> = {
  0: "CodeDirectory",
  2: "Requirements",
  5: "Entitlements",
  0x10000: "Wrapper",
};

export const CS_HASHTYPE_SHA256 = 2;
