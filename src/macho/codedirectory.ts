// Standard CS_CodeDirectory header layout (big-endian integers), per
// <mach-o/codedirectory.h>. Parser and builder share these offsets.
export const CD = {
  magic: 0,
  length: 4,
  version: 8,
  flags: 12,
  hashOffset: 16,
  identOffset: 20,
  nSpecialSlots: 24,
  nCodeSlots: 28,
  codeLimit: 32,
  hashSize: 36, // u8
  hashType: 37, // u8
  platform: 38, // u8
  pageSize: 39, // u8 (log2)
  spare2: 40,
  scatterOffset: 44,
} as const;

export const SUPERBLOB = {
  magic: 0,
  length: 4,
  count: 8,
  entriesStart: 12,
  entrySize: 8, // uint32 slotType + uint32 offset
} as const;
