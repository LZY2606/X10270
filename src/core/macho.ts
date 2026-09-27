// Mach-O / fat / LC_CODE_SIGNATURE 公开常量（离线自带）。
export const MAGIC = {
  MH_MAGIC: 0xfeedface,
  MH_CIGAM: 0xcefaedfe,
  MH_MAGIC_64: 0xfeedfacf,
  MH_CIGAM_64: 0xcffaedfe,
  FAT_MAGIC: 0xcafebabe,
  FAT_CIGAM: 0xbebafeca,
  FAT_MAGIC_64: 0xcafebabf,
  FAT_CIGAM_64: 0xbfbafeca,
} as const;

export const LC = {
  LC_REQ_DYLD: 0x80000000,
  LC_SEGMENT: 0x1,
  LC_SYMTAB: 0x2,
  LC_UNIXTHREAD: 0x5,
  LC_DYSYMTAB: 0xb,
  LC_LOAD_DYLIB: 0xc,
  LC_ID_DYLIB: 0xd,
  LC_SEGMENT_64: 0x19,
  LC_UUID: 0x1b,
  LC_CODE_SIGNATURE: 0x1d,
  LC_ENCRYPTION_INFO: 0x21,
  LC_DYLD_INFO: 0x22,
  LC_DYLD_INFO_ONLY: 0x22 | 0x80000000,
  LC_VERSION_MIN_MACOSX: 0x24,
  LC_MAIN: 0x80000028,
  LC_DYLD_EXPORTS_TRIE: 0x80000033,
} as const;

const LC_NAMES = new Map<number, string>(
  Object.entries(LC).map(([k, v]) => [v as number, k]),
);
export function lcName(cmd: number): string {
  return LC_NAMES.get(cmd) ?? `LC_UNKNOWN(0x${cmd.toString(16)})`;
}

// Code Signing blobs（<Security/SecCode> 公开 magic）
export const CS = {
  CSMAGIC_EMBEDDED_SIGNATURE: 0xfade0cc0,
  CSMAGIC_REQUIREMENT: 0xfade0c00,
  CSMAGIC_REQUIREMENTS: 0xfade0c01,
  CSMAGIC_CODEDIRECTORY: 0xfade0c02,
  CSMAGIC_EMBEDDED_ENTITLEMENTS: 0xfade7171,
  CSMAGIC_EMBEDDED_DER_ENTITLEMENTS: 0xfade7172,
  CSMAGIC_BLOBWRAPPER: 0xfade0b01,
} as const;

export interface BlobTypeInfo {
  kind:
    | 'CodeDirectory'
    | 'Requirements'
    | 'Entitlements'
    | 'CmsSignature'
    | 'EntitlementsDer'
    | 'Unknown';
  supported: boolean;
}

export function blobInfo(magic: number): BlobTypeInfo {
  switch (magic) {
    case CS.CSMAGIC_CODEDIRECTORY:
      return { kind: 'CodeDirectory', supported: true };
    case CS.CSMAGIC_REQUIREMENTS:
    case CS.CSMAGIC_REQUIREMENT:
      return { kind: 'Requirements', supported: true };
    case CS.CSMAGIC_EMBEDDED_ENTITLEMENTS:
      return { kind: 'Entitlements', supported: true };
    case CS.CSMAGIC_EMBEDDED_DER_ENTITLEMENTS:
      return { kind: 'EntitlementsDer', supported: true };
    case CS.CSMAGIC_BLOBWRAPPER:
      return { kind: 'CmsSignature', supported: true };
    default:
      return { kind: 'Unknown', supported: false };
  }
}

export const BLOB_INDEX_TYPES = new Map<number, string>([
  [0, 'CodeDirectory'],
  [2, 'Requirements'],
  [5, 'Entitlements'],
  [0x10000, 'CmsSignature'],
  [7, 'EntitlementsDer'],
]);
