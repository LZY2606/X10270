/** Byte layout layout constants of the synthetic fixture, shared by builder and mutations. */
export const LAYOUT = {
  fatArchEntry: (i: number) => 8 + i * 20,
  slice0: 0x1000,
  slice1: 0x4000,
  sliceSize: 0x2000,
  fileSize: 0x6000,
  dataoff: 0x1800,
  datasize: 0x800,
  page: 0x400,
  pageSizeExp: 10,
  // inside a slice
  machHeader: 0,
  cmd0: 32, // LC_SEGMENT_64
  cmd1: 32 + 72, // LC_CODE_SIGNATURE
  // inside the signature blob (slice-basis dataoff + offset)
  superBlob: 0,
  codeDirectory: 20,
  cdNCodeSlots: 28, // field offset inside CodeDirectory
} as const;

export const CPU_X86_64 = 0x01000007;
export const CPU_ARM64 = 0x0100000c;
