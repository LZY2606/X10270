/**
 * Deterministic builder for universal Mach-O containers whose slice bodies
 * carry a real Embedded Signature (SuperBlob) with a CodeDirectory containing
 * SHA-256 code slots. Everything produced here is parseable by parser.ts and
 * re-hashable by the signature rules.
 */
import { createHash } from "node:crypto";
import {
  CSMAGIC_CODEDIRECTORY,
  CSMAGIC_EMBEDDED_SIGNATURE,
  CSMAGIC_REQUIREMENTS,
  CSSLOT_CODEDIRECTORY,
  CSSLOT_REQUIREMENTS,
  CS_HASHTYPE_SHA256,
  CPU_SUBTYPE_ARM64_ALL,
  CPU_SUBTYPE_ARM64E,
  CPU_SUBTYPE_PTRAUTH_ABI,
  CPU_SUBTYPE_X86_64_ALL,
  CPU_TYPE_ARM64,
  CPU_TYPE_X86_64,
  FAT_CIGAM,
  FAT_CIGAM_64,
  FAT_MAGIC,
  FAT_MAGIC_64,
  LC_BUILD_VERSION,
  LC_CODE_SIGNATURE,
  LC_DYSYMTAB,
  LC_SEGMENT_64,
  LC_SYMTAB,
  LC_UUID,
  MH_MAGIC_64,
} from "./macho-const.ts";
import { bytesToBase64 } from "./binary.ts";

export type SliceArch = "arm64" | "x86_64" | "arm64e";

export interface BuildOptions {
  arch: SliceArch;
  textSize?: number;
  /** Extra bytes appended after the linkedit segment (still before signature). */
  tailGap?: number;
  /** Corrupt the hash of page 1 by flipping a byte in the hashed region. */
  flipTextByte?: number;
  /** Put an unknown blob in the Requirements slot instead of requirements. */
  unknownBlob?: boolean;
  /** Page size exponent inside the CodeDirectory (default 12 = 4096). */
  pageSizeLog2?: number;
  /** Endian of the Mach-O slice itself (default little). */
  endian?: "little" | "big";
}

function cputypeOf(arch: SliceArch): number {
  return arch === "x86_64" ? CPU_TYPE_X86_64 : CPU_TYPE_ARM64;
}

function cpusubtypeOf(arch: SliceArch): number {
  if (arch === "x86_64") return CPU_SUBTYPE_X86_64_ALL;
  if (arch === "arm64e") return CPU_SUBTYPE_ARM64E | CPU_SUBTYPE_PTRAUTH_ABI;
  return CPU_SUBTYPE_ARM64_ALL;
}

class Writer {
  private chunks: number[] = [];

  get length(): number {
    return this.chunks.length;
  }

  byte(v: number): void {
    this.chunks.push(v & 0xff);
  }

  bytes(b: ArrayLike<number> | Uint8Array): void {
    for (let i = 0; i < b.length; i++) this.chunks.push(b[i]! & 0xff);
  }

  fill(count: number, value: number): void {
    for (let i = 0; i < count; i++) this.chunks.push(value & 0xff);
  }

  u32(v: number, endian: "little" | "big" = "little"): void {
    const b = [v & 0xff, (v >>> 8) & 0xff, (v >>> 16) & 0xff, (v >>> 24) & 0xff];
    if (endian === "big") b.reverse();
    this.bytes(b);
  }

  u64(v: bigint, endian: "little" | "big" = "little"): void {
    const b: number[] = [];
    for (let i = 0; i < 8; i++) b.push(Number((v >> BigInt(i * 8)) & 0xffn));
    if (endian === "big") b.reverse();
    this.bytes(b);
  }

  cstr(s: string, fixed: number): void {
    const raw = new TextEncoder().encode(s);
    this.bytes(raw.subarray(0, fixed - 1));
    this.fill(fixed - Math.min(raw.length, fixed - 1), 0);
  }

  patchU32(off: number, v: number, endian: "little" | "big" = "little"): void {
    const b = [v & 0xff, (v >>> 8) & 0xff, (v >>> 16) & 0xff, (v >>> 24) & 0xff];
    if (endian === "big") b.reverse();
    for (let i = 0; i < 4; i++) this.chunks[off + i] = b[i]!;
  }

  patchByte(off: number, v: number): void {
    this.chunks[off] = v & 0xff;
  }

  toBytes(): Uint8Array {
    return Uint8Array.from(this.chunks);
  }
}

function pageHash(page: Uint8Array): string {
  return createHash("sha256").update(page).digest("hex");
}

const PAGE = 4096;
const HEADER_END = 0x80;
const LINKEDIT_OFF = 0x4000;

/**
 * Build one Mach-O 64 slice.
 * Layout:
 *   0x0000  mach_header_64 + load commands (ends <= 0x80)
 *   0x0800..0x4000  __TEXT.__text content
 *   0x4000..0x5000  __LINKEDIT (symbol/string tables)
 *   0x5000..        __LINKEDIT tail / signature superblob
 */
export function buildSlice(opts: BuildOptions): Uint8Array {
  const endian = opts.endian ?? "little";
  const magicBE = (m: number) => m; // magic is written per endian below
  const w = new Writer();
  const textSize = opts.textSize ?? 0x1000;
  const linkeditSize = 0x1000;
  const cputype = cputypeOf(opts.arch);
  const cpusubtype = cpusubtypeOf(opts.arch);
  const pageExp = opts.pageSizeLog2 ?? 12;
  const sigPage = 1 << pageExp;

  // --- Load commands -------------------------------------------------------
  const lc: Array<{ write: (at: number) => void; size: number }> = [];

  // LC_SEGMENT_64 __TEXT
  lc.push({
    size: 72,
    write(at) {
      w.u32(LC_SEGMENT_64, endian);
      w.u32(72, endian);
      w.cstr("__TEXT", 16);
      w.u64(0n, endian); // vmaddr
      w.u64(BigInt(LINKEDIT_OFF), endian); // vmsize 0x4000
      w.u32(0, endian); // fileoff
      w.u32(LINKEDIT_OFF, endian); // filesize
      w.u32(7, endian); // maxprot rwx
      w.u32(5, endian); // initprot rx
      w.u32(1, endian); // nsects
      w.u32(0, endian); // flags
      // section_64
      w.cstr("__text", 16);
      w.cstr("__TEXT", 16);
      w.u64(0x800n, endian);
      w.u64(BigInt(textSize), endian);
      w.u32(0x800, endian);
      w.u32(2, endian);
      w.u32(0, endian);
      w.u32(0, endian);
      w.u32(0, endian);
      w.u32(0, endian);
      w.u32(0, endian);
      void at;
    },
  });

  // LC_SEGMENT_64 __LINKEDIT
  lc.push({
    size: 72,
    write() {
      w.u32(LC_SEGMENT_64, endian);
      w.u32(72, endian);
      w.cstr("__LINKEDIT", 16);
      w.u64(BigInt(LINKEDIT_OFF), endian);
      w.u64(BigInt(linkeditSize + (opts.tailGap ?? 0) + 0x400), endian);
      w.u32(LINKEDIT_OFF, endian);
      w.u32(linkeditSize + (opts.tailGap ?? 0) + 0x400, endian);
      w.u32(7, endian);
      w.u32(1, endian);
      w.u32(0, endian);
      w.u32(0, endian);
    },
  });

  // LC_SYMTAB
  lc.push({
    size: 24,
    write() {
      w.u32(LC_SYMTAB, endian);
      w.u32(24, endian);
      w.u32(0x4000, endian); // symoff
      w.u32(2, endian); // nsyms (12 bytes each => 24)
      w.u32(0x4080, endian); // stroff
      w.u32(0x80, endian); // strsize
    },
  });

  // LC_DYSYMTAB
  lc.push({
    size: 80,
    write() {
      w.u32(LC_DYSYMTAB, endian);
      w.u32(80, endian);
      for (let i = 0; i < 18; i++) w.u32(i < 2 ? 0x4000 + i * 12 : 0, endian);
    },
  });

  // LC_UUID
  lc.push({
    size: 24,
    write() {
      w.u32(LC_UUID, endian);
      w.u32(24, endian);
      const seed = cputype ^ 0xa5a5_0000;
      for (let i = 0; i < 16; i++) w.byte((seed >>> ((i % 4) * 8)) & 0xff);
    },
  });

  // LC_BUILD_VERSION
  lc.push({
    size: 24,
    write() {
      w.u32(LC_BUILD_VERSION, endian);
      w.u32(24, endian);
      w.u32(1, endian); // platform macOS
      w.u32(0x000e_0000, endian); // 14.0
      w.u32(0, endian); // sdk
      w.u32(0, endian); // ntools
    },
  });

  // LC_CODE_SIGNATURE (patched offsets later)
  let sigoffPos = 0;
  lc.push({
    size: 16,
    write() {
      w.u32(LC_CODE_SIGNATURE, endian);
      w.u32(16, endian);
      sigoffPos = w.length;
      w.u32(0, endian);
      w.u32(0, endian);
    },
  });

  const sizeofcmds = lc.reduce((s, c) => s + c.size, 0);
  const ncmds = lc.length;

  // --- mach_header_64 ------------------------------------------------------
  w.u32(endian === "little" ? MH_MAGIC_64 : 0xcffaedfe, endian);
  w.u32(cputype, endian);
  w.u32(cpusubtype, endian);
  w.u32(2, endian); // MH_EXECUTE
  w.u32(ncmds, endian);
  w.u32(sizeofcmds, endian);
  w.u32(0x00200085, endian);
  w.u32(0, endian);

  for (const cmd of lc) cmd.write(w.length);
  while (w.length < HEADER_END) w.byte(0);

  // --- __TEXT.__text -------------------------------------------------------
  while (w.length < 0x800) w.byte(0);
  const textStart = w.length;
  for (let i = 0; i < textSize; i++) {
    w.byte((i * 31 + cputype + (opts.arch === "x86_64" ? 0x55 : 0x11)) & 0xff);
  }
  if (opts.flipTextByte !== undefined) {
    w.patchByte(textStart + opts.flipTextByte, 0xa5);
  }
  while (w.length < LINKEDIT_OFF) w.byte(0);

  // --- __LINKEDIT symbol/string payload ------------------------------------
  // nlist_64 x2 (24 bytes)
  for (let i = 0; i < 24; i++) w.byte((i * 7 + cputype) & 0xff);
  while (w.length < 0x4080) w.byte(0);
  w.byte(0);
  const strTable = `_entry_${opts.arch}\0_lcsig_probe\0`;
  w.bytes(new TextEncoder().encode(strTable));
  while (w.length < LINKEDIT_OFF + linkeditSize) w.byte(0);

  // optional unsigned-tail bytes still before the signature (inside linkedit)
  if (opts.tailGap) w.fill(opts.tailGap, 0);

  const sigOff = w.length;
  const codeLimit = sigOff;

  // --- CodeDirectory -------------------------------------------------------
  const ident = `com.example.${opts.arch}`;
  const identBytes = new TextEncoder().encode(ident + "\0");
  const slotsHashCount = 1; // code slots = ceil(codeLimit/page)
  const codeSlots = Math.ceil(codeLimit / sigPage);
  const specialSlots = 1; // slot -1 = Requirements hash
  const cdHeaderSize = 44;
  const hashOffset =
    cdHeaderSize + identBytes.length + ((4 - (identBytes.length % 4)) % 4);
  const cdLength = hashOffset + (specialSlots + codeSlots) * 32;
  void slotsHashCount;

  const cdStart = 0x2c; // superblob header 12 + 2*index entries 16 = 44
  const reqBlobLen = 24;
  const reqStart = cdStart + cdLength;
  const superLen = reqStart + reqBlobLen;

  // patch LC_CODE_SIGNATURE
  w.patchU32(sigoffPos, sigOff, endian);
  w.patchU32(sigoffPos + 4, superLen, endian);

  // SuperBlob header (always big-endian on disk, per convention)
  w.u32(CSMAGIC_EMBEDDED_SIGNATURE, "big");
  w.u32(superLen, "big");
  w.u32(2, "big");
  // index entries in ascending slot type (CodeDirectory slot 0, Requirements slot 2)
  w.u32(CSSLOT_CODEDIRECTORY, "big");
  w.u32(cdStart, "big");
  w.u32(CSSLOT_REQUIREMENTS, "big");
  w.u32(reqStart, "big");

  const cdBlobStart = w.length;
  if (cdBlobStart - sigOff !== cdStart) throw new Error("cd layout drift");

  // Requirements blob (filled first so its hash is computable)
  const reqDigest = createHash("sha256");
  // CodeDirectory header
  w.u32(CSMAGIC_CODEDIRECTORY, "big");
  w.u32(cdLength, "big");
  w.u32(0x20100, "big"); // version 2.1
  w.u32(0, "big"); // flags
  w.u32(hashOffset, "big");
  const identFileOff = w.length;
  w.u32(identFileOff - cdBlobStart, "big");
  w.u32(0, "big"); // nSpecialSlots
  w.u32(codeSlots, "big"); // nCodeSlots
  w.u32(codeLimit, "big");
  w.u32(1, "big"); // size = 1 byte
  w.u32(CS_HASHTYPE_SHA256, "big");
  w.u32(pageExp, "big");
  w.u32(0, "big"); // spare2
  w.bytes(identBytes);
  while ((w.length - cdBlobStart) % 4 !== 0) w.byte(0);
  // placeholder for special slots; real value patched after requirements blob
  const specialSlotPos = w.length;
  for (let i = 0; i < specialSlots * 32; i++) w.byte(0);
  const codeSlotPos: number[] = [];
  const hashes: Uint8Array[] = [];
  const body = w.toBytes(); // body currently ends right after placeholders
  for (let slot = 0; slot < codeSlots; slot++) {
    codeSlotPos.push(w.length);
    const start = slot * sigPage;
    const len = Math.min(sigPage, codeLimit - start);
    const h = createHash("sha256").update(body.subarray(start, start + len)).digest();
    hashes.push(h);
    w.bytes(h);
  }
  if (w.length - cdBlobStart !== cdLength) throw new Error("cd length drift");

  // Requirements blob
  const reqBlobPos = w.length;
  if (reqBlobPos - sigOff !== reqStart) throw new Error("req layout drift");
  if (opts.unknownBlob) {
    // Recognized slot index but a magic that is not a supported requirement blob.
    w.u32(0xabad1dea, "big");
    w.u32(reqBlobLen, "big");
    for (let i = 8; i < reqBlobLen; i++) w.byte(0xf0 | (i & 0x0f));
  } else {
    w.u32(CSMAGIC_REQUIREMENTS, "big");
    w.u32(reqBlobLen, "big");
    // empty requirement expression: count=0
    w.u32(0, "big");
    for (let i = 12; i < reqBlobLen; i++) w.byte(0);
  }
  const reqBytes = w.toBytes().subarray(reqBlobPos, reqBlobPos + reqBlobLen);
  reqDigest.update(reqBytes);
  const reqHash = reqDigest.digest();
  for (let i = 0; i < 32; i++) w.patchByte(specialSlotPos + i, reqHash[i]!);

  if (w.length - sigOff !== superLen) throw new Error("superblob length drift");
  return w.toBytes();
}

void magicBE;
void pageHash;
void bytesToBase64;
