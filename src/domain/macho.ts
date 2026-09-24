import { q, qHex, Quantity } from "./types.js";
import { stableId, sha256Hex } from "./ids.js";

export const FAT_MAGIC = 0xcafebabe; // 磁盘字节 ca fe ba be，字段大端
export const FAT_CIGAM = 0xbebafeca; // 磁盘字节 be ba fe ca，字段小端
export const MH_MAGIC_64 = 0xfeedfacf; // 磁盘 cf fa ed fe，小端
export const MH_CIGAM_64 = 0xcffaedfe; // 磁盘 fe ed fa cf，大端
export const LC_CODE_SIGNATURE = 0x1d;
export const CSMAGIC_EMBEDDED_SIGNATURE = 0xfade0cc0;
export const CSMAGIC_CODEDIRECTORY = 0xfade0c02;

export const COMMAND_NAMES: Record<number, string> = {
  0x1: "LC_SEGMENT", 0x2: "LC_SYMTAB", 0xb: "LC_DYSYMTAB", 0x19: "LC_SEGMENT_64",
  0x1b: "LC_UUID", 0x1d: "LC_CODE_SIGNATURE", 0x2c: "LC_ENCRYPTION_INFO_64",
  0x32: "LC_BUILD_VERSION", 0x24: "LC_VERSION_MIN_MACOSX",
};

export const ARCH_NAMES: Record<number, string> = {
  0x01000007: "x86_64", 0x0100000c: "arm64", 0x00000007: "i386", 0x0000000c: "arm",
};

export interface ParseDiagnostic {
  kind: "format-corrupt" | "unconvertible";
  message: string;
  offset: Quantity;
}

export interface FatArchEntry {
  id: string;
  index: number;
  cpuType: Quantity;
  cpuSubtype: Quantity;
  archName: string; // 未知时 "unknown(<raw>)"
  offset: Quantity; // file-offset
  size: Quantity;
  align: Quantity; // 2 的指数
}

export interface LoadCommandModel {
  id: string;
  sliceId: string;
  index: number;
  cmd: Quantity;
  cmdName: string;
  cmdSize: Quantity;
  offset: Quantity; // slice-offset
  /** LC_CODE_SIGNATURE 时给出签名区（slice 相对坐标） */
  sigDataOff?: Quantity;
  sigDataSize?: Quantity;
}

export interface CodeDirectoryModel {
  id: string;
  hashType: number;
  hashSize: number;
  pageSizeExp: number;
  nCodeSlots: number;
  nSpecialSlots: number;
  codeLimit: Quantity; // slice-offset 基准
  slots: { index: number; kind: "special" | "code"; hashHex: string }[];
}

export interface SignatureModel {
  id: string;
  sliceId: string;
  dataOff: Quantity; // slice-offset
  dataSize: Quantity;
  blobMagic: Quantity;
  blobKind: "embedded-signature" | "unknown";
  codeDirectory?: CodeDirectoryModel;
}

export interface SliceModel {
  id: string;
  arch: FatArchEntry;
  endian: "le" | "be" | "unknown";
  magic: Quantity;
  ncmds: Quantity;
  sizeofcmds: Quantity;
  commands: LoadCommandModel[];
  signature?: SignatureModel;
}

export interface FatModel {
  id: string;
  fileLength: number;
  fatEndian: "be" | "le";
  magic: Quantity;
  nfatArch: Quantity;
  arches: FatArchEntry[];
  slices: SliceModel[];
  diagnostics: ParseDiagnostic[];
  fileDigest: string;
}

function readU32(bytes: Uint8Array, off: number, endian: "le" | "be"): number {
  const b = bytes;
  return endian === "le"
    ? (b[off]! | (b[off + 1]! << 8) | (b[off + 2]! << 16) | (b[off + 3]! << 24)) >>> 0
    : ((b[off]! << 24) | (b[off + 1]! << 16) | (b[off + 2]! << 8) | b[off + 3]!) >>> 0;
}

function hexAt(bytes: Uint8Array, off: number, len: number): string {
  const end = Math.min(off + len, bytes.length);
  let out = "";
  for (let i = off; i < end; i++) out += bytes[i]!.toString(16).padStart(2, "0");
  return out;
}

/** 解析 universal (fat) Mach-O。所有量保留原始表示；越界/不可解析处附诊断。 */
export function parseFat(bytes: Uint8Array): FatModel {
  const diagnostics: ParseDiagnostic[] = [];
  const fileDigest = sha256Hex(bytes);
  const fileId = stableId("fat", fileDigest);

  const magicRaw = hexAt(bytes, 0, 4);
  let fatEndian: "be" | "le";
  const magicBE = readU32(bytes, 0, "be");
  if (magicBE === FAT_MAGIC) fatEndian = "be";
  else if (magicBE === FAT_CIGAM) fatEndian = "le";
  else {
    diagnostics.push({
      kind: "format-corrupt",
      message: `未知 fat magic 0x${magicRaw}，无法确定容器字节序`,
      offset: qHex(0, "byte", "file-offset"),
    });
    return {
      id: fileId, fileLength: bytes.length, fatEndian: "be",
      magic: q(`0x${magicRaw}`, null, "hex", "file-offset", "未知 magic，无法规范化"),
      nfatArch: q("?", null, "count", "fat-header", "magic 未知，nfat_arch 不可信"),
      arches: [], slices: [], diagnostics, fileDigest,
    };
  }

  const nfat = readU32(bytes, 4, fatEndian);
  const arches: FatArchEntry[] = [];
  for (let i = 0; i < nfat; i++) {
    const base = 8 + i * 20;
    if (base + 20 > bytes.length) {
      diagnostics.push({
        kind: "format-corrupt",
        message: `fat_arch[${i}] 超出文件末尾`,
        offset: qHex(base, "byte", "file-offset"),
      });
      break;
    }
    const cpuType = readU32(bytes, base, fatEndian);
    const entry: FatArchEntry = {
      id: stableId("arch", fileDigest, i, cpuType),
      index: i,
      cpuType: qHex(cpuType, "hex", "fat-arch"),
      cpuSubtype: qHex(readU32(bytes, base + 4, fatEndian), "hex", "fat-arch"),
      archName: ARCH_NAMES[cpuType] ?? `unknown(0x${cpuType.toString(16)})`,
      offset: qHex(readU32(bytes, base + 8, fatEndian), "byte", "file-offset"),
      size: qHex(readU32(bytes, base + 12, fatEndian), "byte", "file-offset"),
      align: qHex(readU32(bytes, base + 16, fatEndian), "count", "power-of-two-exponent"),
    };
    arches.push(entry);
  }

  const slices: SliceModel[] = [];
  for (const arch of arches) {
    slices.push(parseSlice(bytes, arch, fileId, diagnostics));
  }

  return {
    id: fileId,
    fileLength: bytes.length,
    fatEndian,
    magic: q(`0x${magicRaw}`, magicBE, "hex", "file-offset"),
    nfatArch: q(String(nfat), nfat, "count", "fat-header"),
    arches, slices, diagnostics, fileDigest,
  };
}

function parseSlice(
  bytes: Uint8Array, arch: FatArchEntry, fileId: string, diagnostics: ParseDiagnostic[],
): SliceModel {
  const sliceId = stableId("slice", fileId, arch.index, arch.archName);
  const base = arch.offset.value ?? 0;
  const size = arch.size.value ?? 0;
  const unknown = (why: string): SliceModel => ({
    id: sliceId, arch, endian: "unknown",
    magic: q("?", null, "hex", "slice-offset", why),
    ncmds: q("?", null, "count", "mach-header", why),
    sizeofcmds: q("?", null, "byte", "mach-header", why),
    commands: [],
  });

  if (base + 4 > bytes.length) {
    diagnostics.push({ kind: "format-corrupt", message: `slice[${arch.index}] 头越界`, offset: arch.offset });
    return unknown("slice 头越界");
  }
  const magicRaw = hexAt(bytes, base, 4);
  let endian: "le" | "be";
  const magicLE = readU32(bytes, base, "le");
  const magicBE = readU32(bytes, base, "be");
  if (magicLE === MH_MAGIC_64) endian = "le";
  else if (magicBE === MH_MAGIC_64) endian = "be";
  else {
    diagnostics.push({
      kind: "format-corrupt",
      message: `slice[${arch.index}] 未知 Mach-O magic 0x${magicRaw}，字节序不可判定`,
      offset: qHex(base, "byte", "file-offset"),
    });
    return unknown(`未知 magic 0x${magicRaw}`);
  }

  const ncmds = readU32(bytes, base + 16, endian);
  const sizeofcmds = readU32(bytes, base + 20, endian);
  const slice: SliceModel = {
    id: sliceId, arch, endian,
    magic: q(`0x${magicRaw}`, endian === "le" ? MH_MAGIC_64 : MH_CIGAM_64, "hex", "slice-offset"),
    ncmds: q(String(ncmds), ncmds, "count", "mach-header"),
    sizeofcmds: qHex(sizeofcmds, "byte", "mach-header"),
    commands: [],
  };

  // load commands：范围受 sizeofcmds 与 slice 边界双重约束
  let cursor = 32;
  const cmdsEnd = Math.min(32 + sizeofcmds, size);
  for (let i = 0; i < ncmds; i++) {
    if (cursor + 8 > cmdsEnd || base + cursor + 8 > bytes.length) {
      diagnostics.push({
        kind: "format-corrupt",
        message: `load command[${i}] 头越界（slice-offset ${cursor}）`,
        offset: qHex(cursor, "byte", "slice-offset"),
      });
      break;
    }
    const cmd = readU32(bytes, base + cursor, endian);
    const cmdSize = readU32(bytes, base + cursor + 4, endian);
    const lc: LoadCommandModel = {
      id: stableId("cmd", sliceId, i, cmd, cursor),
      sliceId, index: i,
      cmd: qHex(cmd, "hex", "load-command"),
      cmdName: COMMAND_NAMES[cmd] ?? `unknown(0x${cmd.toString(16)})`,
      cmdSize: qHex(cmdSize, "byte", "load-command"),
      offset: qHex(cursor, "byte", "slice-offset"),
    };
    if (cmd === LC_CODE_SIGNATURE && cursor + 16 <= cmdsEnd && base + cursor + 16 <= bytes.length) {
      const dataOff = readU32(bytes, base + cursor + 8, endian);
      const dataSize = readU32(bytes, base + cursor + 12, endian);
      lc.sigDataOff = qHex(dataOff, "byte", "slice-offset");
      lc.sigDataSize = qHex(dataSize, "byte", "slice-offset");
      slice.signature = parseSignature(bytes, base, size, sliceId, dataOff, dataSize, diagnostics);
    }
    slice.commands.push(lc);
    if (cmdSize < 8) break; // 越界规则会报告；此处防止死循环
    cursor += cmdSize;
  }
  return slice;
}

function parseSignature(
  bytes: Uint8Array, sliceBase: number, sliceSize: number, sliceId: string,
  dataOff: number, dataSize: number, diagnostics: ParseDiagnostic[],
): SignatureModel {
  const sigId = stableId("sig", sliceId, dataOff, dataSize);
  const abs = sliceBase + dataOff;
  const model: SignatureModel = {
    id: sigId, sliceId,
    dataOff: qHex(dataOff, "byte", "slice-offset"),
    dataSize: qHex(dataSize, "byte", "slice-offset"),
    blobMagic: q("?", null, "hex", "blob-header", "blob 越界"),
    blobKind: "unknown",
  };
  if (abs + 4 > bytes.length || dataOff + dataSize > sliceSize) {
    diagnostics.push({
      kind: "format-corrupt", message: "签名 blob 超出 slice 范围",
      offset: qHex(dataOff, "byte", "slice-offset"),
    });
    return model;
  }
  // 签名 blob 一律大端
  const magic = readU32(bytes, abs, "be");
  model.blobMagic = qHex(magic, "hex", "blob-header");
  if (magic !== CSMAGIC_EMBEDDED_SIGNATURE) return model; // 未知 blob：保留原值，规则层判“不支持格式”
  model.blobKind = "embedded-signature";

  const count = readU32(bytes, abs + 8, "be");
  for (let i = 0; i < count; i++) {
    const idxOff = abs + 12 + i * 8;
    const type = readU32(bytes, idxOff, "be");
    const relOff = readU32(bytes, idxOff + 4, "be");
    if (type !== 0) continue; // 只取 CodeDirectory
    const cdAbs = abs + relOff;
    if (cdAbs + 44 > bytes.length) break;
    if (readU32(bytes, cdAbs, "be") !== CSMAGIC_CODEDIRECTORY) break;
    const hashOffset = readU32(bytes, cdAbs + 16, "be");
    const nSpecial = readU32(bytes, cdAbs + 24, "be");
    const nCode = readU32(bytes, cdAbs + 28, "be");
    const codeLimit = readU32(bytes, cdAbs + 32, "be");
    const hashSize = bytes[cdAbs + 36]!;
    const pageSizeExp = bytes[cdAbs + 39]!;
    const slots: CodeDirectoryModel["slots"] = [];
    const hashBase = cdAbs + hashOffset - nSpecial * hashSize;
    for (let s = 0; s < nSpecial + nCode; s++) {
      const hOff = hashBase + s * hashSize;
      if (hOff + hashSize > bytes.length) break;
      slots.push({
        index: s - nSpecial,
        kind: s < nSpecial ? "special" : "code",
        hashHex: hexAt(bytes, hOff, hashSize),
      });
    }
    model.codeDirectory = {
      id: stableId("cd", sigId, codeLimit, nCode),
      hashType: bytes[cdAbs + 37]!, hashSize, pageSizeExp,
      nCodeSlots: nCode, nSpecialSlots: nSpecial,
      codeLimit: qHex(codeLimit, "byte", "slice-offset"),
      slots,
    };
  }
  return model;
}

/** 读取文件坐标下的字节（失败字节证据读回） */
export function readEvidence(bytes: Uint8Array, fileOffset: number, length: number): string {
  return hexAt(bytes, fileOffset, Math.max(0, Math.min(length, 64)));
}
