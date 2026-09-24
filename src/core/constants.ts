/** Mach-O / fat / embedded-signature constants (observed magic values). */

export const FAT_MAGIC = 0xcafebabe;
export const FAT_CIGAM = 0xbebafeca;
export const FAT_MAGIC_64 = 0xcafebabf;
export const FAT_CIGAM_64 = 0xbfbafeca;

export const MH_MAGIC = 0xfeedface;
export const MH_CIGAM = 0xcefaedfe;
export const MH_MAGIC_64 = 0xfeedfacf;
export const MH_CIGAM_64 = 0xcffaedfe;

export const LC_REQ_DYLD = 0x80000000;
export const LC_SEGMENT = 0x1;
export const LC_SYMTAB = 0x2;
export const LC_DYSYMTAB = 0xb;
export const LC_LOAD_DYLIB = 0xc;
export const LC_ID_DYLIB = 0xd;
export const LC_SEGMENT_64 = 0x19;
export const LC_UUID = 0x1b;
export const LC_CODE_SIGNATURE = 0x1d;
export const LC_ENCRYPTION_INFO_64 = 0x2c;
export const LC_DYLD_EXPORTS_TRIE = 0x80000033;
export const LC_DYLD_CHAINED_FIXUPS = 0x80000034;

export const CPU_ARCH_ABI64 = 0x01000000;
export const CPU_TYPE_X86 = 0x7;
export const CPU_TYPE_X86_64 = 0x01000007;
export const CPU_TYPE_ARM = 12;
export const CPU_TYPE_ARM64 = 0x0100000c;

export const CPU_SUBTYPE_MASK = 0x00ffffff;

export function cpuTypeName(t: number): string {
  switch (t) {
    case CPU_TYPE_X86:
      return 'i386';
    case CPU_TYPE_X86_64:
      return 'x86_64';
    case CPU_TYPE_ARM:
      return 'arm';
    case CPU_TYPE_ARM64:
      return 'arm64';
    default:
      return `unknown-cpu(0x${t >>> 0 ? (t >>> 0).toString(16) : t.toString(16)})`;
  }
}

export function loadCommandName(cmd: number): string {
  switch (cmd) {
    case LC_SEGMENT:
      return 'LC_SEGMENT';
    case LC_SYMTAB:
      return 'LC_SYMTAB';
    case LC_DYSYMTAB:
      return 'LC_DYSYMTAB';
    case LC_LOAD_DYLIB:
      return 'LC_LOAD_DYLIB';
    case LC_ID_DYLIB:
      return 'LC_ID_DYLIB';
    case LC_SEGMENT_64:
      return 'LC_SEGMENT_64';
    case LC_UUID:
      return 'LC_UUID';
    case LC_CODE_SIGNATURE:
      return 'LC_CODE_SIGNATURE';
    case LC_ENCRYPTION_INFO_64:
      return 'LC_ENCRYPTION_INFO_64';
    case LC_DYLD_EXPORTS_TRIE:
      return 'LC_DYLD_EXPORTS_TRIE';
    case LC_DYLD_CHAINED_FIXUPS:
      return 'LC_DYLD_CHAINED_FIXUPS';
    default:
      return cmd & LC_REQ_DYLD
        ? `LC_REQ_DYLD(0x${cmd.toString(16)})`
        : `LC_UNKNOWN(0x${cmd.toString(16)})`;
  }
}

/** Embedded signature blobs (CSMAGIC_*). */
export const CSMAGIC_EMBEDDED_SIGNATURE = 0xfade0cc0;
export const CSMAGIC_CODEDIRECTORY = 0xfade0c02;
export const CSMAGIC_REQUIREMENTS = 0xfade0c01;
export const CSMAGIC_ENTITLEMENTS = 0xfade7171;
export const CSMAGIC_BLOBWRAPPER = 0xfade0b01;
export const CSMAGIC_UNKNOWN_FOR_CASE = 0xfadebabe;

export const CSSLOT_CODEDIRECTORY = 0;
export const CSSLOT_REQUIREMENTS = 2;
export const CSSLOT_ENTITLEMENTS = 5;
export const CSSLOT_ALTERNATE = 0x1000;

export function sigBlobTypeName(type: number): string {
  switch (type) {
    case CSSLOT_CODEDIRECTORY:
      return 'CodeDirectory';
    case CSSLOT_REQUIREMENTS:
      return 'Requirements';
    case CSSLOT_ENTITLEMENTS:
      return 'Entitlements';
    case CSSLOT_ALTERNATE:
      return 'AlternateCodeDirectory';
    default:
      return `slot-${type}`;
  }
}

export const CS_HASHTYPE_SHA1 = 1;
export const CS_HASHTYPE_SHA256 = 2;
export const CS_HASHTYPE_SHA256_TRUNCATED = 3;

export function hashTypeName(t: number): string {
  switch (t) {
    case CS_HASHTYPE_SHA1:
      return 'sha1';
    case CS_HASHTYPE_SHA256:
      return 'sha256';
    case CS_HASHTYPE_SHA256_TRUNCATED:
      return 'sha256-truncated';
    default:
      return `unsupported-hashtype-${t}`;
  }
}

export function hashDigestBytes(t: number): number | null {
  switch (t) {
    case CS_HASHTYPE_SHA1:
      return 20;
    case CS_HASHTYPE_SHA256:
      return 32;
    case CS_HASHTYPE_SHA256_TRUNCATED:
      return 20;
    default:
      return null;
  }
}
