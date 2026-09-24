/** Mach-O / fat / embedded signature 常量（只包含本核验用到的子集）。 */

export const MH_MAGIC = 0xfeedface;
export const MH_CIGAM = 0xcefaedfe;
export const MH_MAGIC_64 = 0xfeedfacf;
export const MH_CIGAM_64 = 0xcffaedfe;

export const FAT_MAGIC = 0xcafebabe;
export const FAT_CIGAM = 0xbebafeca;
export const FAT_MAGIC_64 = 0xcafebabf;
export const FAT_CIGAM_64 = 0xbfbafeca;

export const LC_SEGMENT = 0x1;
export const LC_SEGMENT_64 = 0x19;
export const LC_CODE_SIGNATURE = 0x1d;

/** 嵌入签名 SuperBlob */
export const CSMAGIC_EMBEDDED_SIGNATURE = 0xfade0cc0;
export const CSMAGIC_REQUIREMENT = 0xfade0c00;
export const CSMAGIC_REQUIREMENTS = 0xfade0c01;
export const CSMAGIC_CODEDIRECTORY = 0xfade0c02;
export const CSMAGIC_EMBEDDED_ENTITLEMENTS = 0xfade7171;
export const CSMAGIC_DETACHED_SIGNATURE = 0xfade0cc1;

export const CSSLOT_CODEDIRECTORY = 0;
export const CSSLOT_INFOSLOT = -1;
export const CSSLOT_REQUIREMENTS = -2;
export const CSSLOT_RESOURCEDIR = -3;
export const CSSLOT_APPLICATION = -4;
export const CSSLOT_ENTITLEMENTS = -5;

export const BLOB_TYPE_NAMES: Record<number, string> = {
  0: "CodeDirectory",
  0x00000002: "Requirements",
  0x00000007: "Entitlements DER",
  0x00000005: "Entitlements",
  0x00001000: "Alternate CodeDirectory",
};

export const CPU_TYPE_NAMES: Record<number, string> = {
  0x01000007: "x86_64",
  0x00000007: "i386",
  0x0100000c: "arm64",
  0x0000000c: "arm",
  0x01000012: "arm64e",
};

export function cpuTypeName(cputype: number, cpusubtype: number): string {
  const base = CPU_TYPE_NAMES[cputype];
  if (base) {
    if (cputype === 0x0100000c && cpusubtype === 2) return "arm64e";
    return base;
  }
  return `unknown(cputype=0x${cputype.toString(16)})`;
}

/** 加载命令友好名（仅核验子集）。 */
export function loadCommandName(cmd: number): string {
  switch (cmd) {
    case LC_SEGMENT:
      return "LC_SEGMENT";
    case LC_SEGMENT_64:
      return "LC_SEGMENT_64";
    case LC_CODE_SIGNATURE:
      return "LC_CODE_SIGNATURE";
    default:
      return `LC_0x${cmd.toString(16).padStart(8, "0")}`;
  }
}
