// Shared Mach-O layout constants and small helpers.
export const PAGE_SIZE = 0x4000;
export const MACH64_HEADER_SIZE = 32;
export const MAX_ALIGN_SHIFT = 30;
export const LC_SEGMENT_64 = 0x19;
export const LC_CODE_SIGNATURE = 0x1d;
export const SHA256_SIZE = 32;

export const CPU_X86_64 = 0x01000007;
export const CPU_ARM64 = 0x0100000c;
export const CPU_ARM64E = 0x0100000d;

export function roundUp(value: number, alignment: number): number {
  return Math.ceil(value / alignment) * alignment;
}
