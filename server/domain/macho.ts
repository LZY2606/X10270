import { createHash } from "node:crypto";
import {
  CSMAGIC_BLOBWRAPPER,
  CSMAGIC_CODEDIRECTORY,
  CSMAGIC_EMBEDDED_SIGNATURE,
  CSMAGIC_REQUIREMENTS,
  CPU_TYPE_NAMES,
  FAT_CIGAM,
  FAT_CIGAM_64,
  FAT_MAGIC,
  FAT_MAGIC_64,
  HASH_TYPE_NAMES,
  LC_CODE_SIGNATURE,
  LOAD_COMMAND_NAMES,
  MH_CIGAM,
  MH_CIGAM_64,
  MH_MAGIC,
  MH_MAGIC_64,
  type CodeDirectoryView,
  type CodeSlotView,
  type Coord,
  type Derived,
  type Diagnostic,
  type Endian,
  type FatContainer,
  type FatHeaderView,
  type FatSliceView,
  type LoadCommandView,
  type MachHeaderView,
  type ParseBudget,
  type SigBlobView,
  type SignatureView,
  type SliceView
} from "./types.js";

export type ParseOutcome =
  | { status: "ok"; container: FatContainer }
  | { status: "corrupt_format"; diagnostic: Diagnostic }
  | { status: "budget_exhausted"; diagnostic: Diagnostic };

function hex(buf: Uint8Array, start: number, len: number): string {
  const end = Math.min(buf.length, start + len);
  let s = "";
  for (let i = start; i < end; i++) s += buf[i]!.toString(16).padStart(2, "0");
  return s;
}

function coord(value: number, basis: Coord["basis"], raw: string): Coord {
  return { value, unit: "byte", basis, raw };
}

function derived<T>(raw: string, value: T | null, diagnostic?: Diagnostic): Derived<T> {
  return { raw, value, diagnostic };
}

function diag(code: string, message: string, offset?: Coord): Diagnostic {
  return { code, message, offset };
}

class Reader {
  dv: DataView;
  constructor(public buf: Uint8Array) {
    this.dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  }
  has(off: number, len: number): boolean {
    return off >= 0 && Number.isInteger(off) && len >= 0 && off + len <= this.buf.length;
  }
  u32(off: number, e: Endian): number | null {
    if (!this.has(off, 4)) return null;
    return this.dv.getUint32(off, e === "little");
  }
  u8(off: number): number | null {
    if (!this.has(off, 1)) return null;
    return this.buf[off]!;
  }
  u64(off: number, e: Endian): bigint | null {
    if (!this.has(off, 8)) return null;
    return this.dv.getBigUint64(off, e === "little");
  }
}

export function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function detectFatMagic(r: Reader): { magic: number; endian: Endian; is64: boolean } | null {
  const be = r.u32(0, "big");
  if (be === null) return null;
  switch (be) {
    case FAT_MAGIC:
      return { magic: be, endian: "big", is64: false };
    case FAT_MAGIC_64:
      return { magic: be, endian: "big", is64: true };
    case FAT_CIGAM:
      return { magic: be, endian: "little", is64: false };
    case FAT_CIGAM_64:
      return { magic: be, endian: "little", is64: true };
    default:
      return null;
  }
}

function detectMachMagic(
  r: Reader,
  off: number
): { magic: number; endian: Endian; is64: boolean } | null {
  const be = r.u32(off, "big");
  if (be === null) return null;
  switch (be) {
    case MH_MAGIC:
      return { magic: be, endian: "big", is64: false };
    case MH_MAGIC_64:
      return { magic: be, endian: "big", is64: true };
    case MH_CIGAM:
      return { magic: be, endian: "little", is64: false };
    case MH_CIGAM_64:
      return { magic: be, endian: "little", is64: true };
    default:
      return null;
  }
}

function readU64Field(r: Reader, off: number, e: Endian): Derived<number> {
  const raw = hex(r.buf, off, 8);
  const v = r.u64(off, e);
  if (v === null)
    return derived(raw, null, diag("TRUNCATED_FIELD", "u64 字段超出可读字节"));
  if (v > BigInt(Number.MAX_SAFE_INTEGER))
    return derived(raw, null, diag("U64_OUT_OF_RANGE", `u64 值 ${v} 超出安全整数范围，保留原始表示`));
  return derived(raw, Number(v));
}

function parseCodeDirectory(
  r: Reader,
  co: number,
  length: number
): { cd: CodeDirectoryView; slots: CodeSlotView[] } {
  const cdRaw = (off: number, len: number) => hex(r.buf, co + off, len);
  const hashType = r.u8(co + 37);
  const hashSize = r.u32(co + 36, "big");
  const pageExp = r.u8(co + 38);
  const nCodeSlots = r.u32(co + 28, "big");
  const codeLimit = r.u32(co + 32, "big");
  const hashOffset = r.u32(co + 16, "big");
  const pageSize = pageExp !== null && pageExp <= 30 ? 2 ** pageExp : null;
  const slots: CodeSlotView[] = [];
  const hashKnown = hashType !== null && HASH_TYPE_NAMES[hashType] !== undefined;
  if (
    hashKnown &&
    hashSize !== null &&
    nCodeSlots !== null &&
    codeLimit !== null &&
    hashOffset !== null &&
    pageSize !== null
  ) {
    for (let i = 0; i < nCodeSlots; i++) {
      const so = hashOffset + i * hashSize;
      slots.push({
        index: i,
        slotOffset: coord(so, "codedirectory", `0x${so.toString(16)}`),
        coveredStart: coord(i * pageSize, "slice", `0x${(i * pageSize).toString(16)}`),
        coveredEnd: coord(
          Math.min((i + 1) * pageSize, codeLimit),
          "slice",
          `0x${Math.min((i + 1) * pageSize, codeLimit).toString(16)}`
        ),
        expectedDigest: cdRaw(so, hashSize),
        actualDigest: null,
        rawHex: cdRaw(so, hashSize)
      });
    }
  }
  const magic = r.u32(co, "big");
  const cd: CodeDirectoryView = {
    magic: derived(cdRaw(0, 4), magic ?? null),
    hashType: derived(cdRaw(37, 1), hashType),
    hashName: derived(
      hashKnown ? HASH_TYPE_NAMES[hashType!]! : cdRaw(37, 1),
      hashKnown ? hashType : null,
      hashKnown
        ? undefined
        : diag("UNSUPPORTED_HASH_TYPE", `不支持的 hash 类型 ${hashType}，不进行摘要比对`)
    ),
    hashSize: derived(
      cdRaw(36, 4),
      hashSize,
      hashSize === null ? diag("TRUNCATED_FIELD", "hashSize 截断") : undefined
    ),
    pageSize: derived(
      cdRaw(38, 1),
      pageSize,
      pageSize === null ? diag("BAD_PAGE_SIZE", `页大小指数 ${pageExp} 无效`) : undefined
    ),
    nCodeSlots: derived(cdRaw(28, 4), nCodeSlots),
    codeLimit: coord(codeLimit ?? 0, "slice", cdRaw(32, 4)),
    hashOffset: coord(hashOffset ?? 0, "codedirectory", cdRaw(16, 4)),
    rawHex: cdRaw(0, Math.min(length, 44))
  };
  return { cd, slots };
}

function parseSignature(
  r: Reader,
  sliceStart: number,
  dataoff: Coord,
  datasize: Coord,
  budget: ParseBudget
): SignatureView | { diagnostic: Diagnostic } {
  const so = sliceStart + dataoff.value;
  const rawHex = hex(r.buf, so, datasize.value);
  const magic = r.u32(so, "big");
  if (magic === null)
    return { diagnostic: diag("SIG_TRUNCATED", "签名字节不足，无法读取 superblob magic") };
  const superMagic = derived(
    hex(r.buf, so, 4),
    magic === CSMAGIC_EMBEDDED_SIGNATURE ? magic : null,
    magic === CSMAGIC_EMBEDDED_SIGNATURE
      ? undefined
      : diag("SIG_BAD_SUPER_MAGIC", `未知签名容器 magic 0x${magic.toString(16)}`)
  );
  const length = r.u32(so + 4, "big");
  const count = r.u32(so + 8, "big");
  if (length === null || count === null)
    return { diagnostic: diag("SIG_TRUNCATED", "签名字节不足，无法读取 superblob 头部") };
  if (count > budget.maxCommandsPerSlice)
    return { diagnostic: diag("BUDGET_EXHAUSTED", `superblob 条目数 ${count} 超出预算`) };

  const blobs: SigBlobView[] = [];
  for (let i = 0; i < count; i++) {
    const ie = 12 + i * 8;
    const slotType = r.u32(so + ie, "big");
    const relOff = r.u32(so + ie + 4, "big");
    if (slotType === null || relOff === null) {
      blobs.push({
        superIndex: i,
        slotType: slotType ?? -1,
        magic: derived("", null, diag("SIG_TRUNCATED", "superblob 索引项截断")),
        offset: coord(relOff ?? 0, "superblob", "truncated"),
        length: coord(0, "superblob", "truncated"),
        rawHex: ""
      });
      continue;
    }
    const bo = so + relOff;
    const bMagic = r.u32(bo, "big");
    const bLen = r.u32(bo + 4, "big");
    const knownMagic =
      bMagic === CSMAGIC_CODEDIRECTORY ||
      bMagic === CSMAGIC_REQUIREMENTS ||
      bMagic === CSMAGIC_BLOBWRAPPER;
    const blob: SigBlobView = {
      superIndex: i,
      slotType,
      magic: derived(
        hex(r.buf, bo, 4),
        knownMagic ? bMagic : null,
        knownMagic
          ? undefined
          : diag(
              "UNKNOWN_BLOB",
              `未知签名 blob magic 0x${(bMagic ?? 0).toString(16)}，保留原始字节不猜测类型`
            )
      ),
      offset: coord(relOff, "superblob", `0x${relOff.toString(16)}`),
      length: coord(bLen ?? 0, "superblob", `0x${(bLen ?? 0).toString(16)}`),
      rawHex: hex(r.buf, bo, bLen ?? 0)
    };
    if (bMagic === CSMAGIC_CODEDIRECTORY && bLen !== null) {
      const parsed = parseCodeDirectory(r, bo, bLen);
      blob.codeDirectory = parsed.cd;
      blob.slots = parsed.slots;
    }
    blobs.push(blob);
  }
  return {
    dataoff,
    datasize,
    superMagic,
    count: derived(hex(r.buf, so + 8, 4), count),
    blobs,
    rawHex
  };
}

function parseSlice(r: Reader, fat: FatSliceView, budget: ParseBudget): SliceView {
  const start = fat.offset.value;
  const m = detectMachMagic(r, start);
  const id = `slice@${fat.offset.raw}`;
  if (!m) {
    return {
      id,
      fat,
      header: null,
      commands: [],
      signature: null,
      parseDiagnostic: diag(
        "BAD_MACH_MAGIC",
        `切片偏移 0x${start.toString(16)} 处不是 Mach-O magic，实际字节 ${hex(r.buf, start, 4)}`
      )
    };
  }
  const e = m.endian;
  const is64 = m.is64;
  const headerSize = is64 ? 32 : 28;
  const ncmds = r.u32(start + 16, e);
  const sizeofcmds = r.u32(start + 20, e);
  const header: MachHeaderView = {
    magic: derived(hex(r.buf, start, 4), m.magic),
    endian: e,
    is64,
    filetype: derived(hex(r.buf, start + 12, 4), r.u32(start + 12, e)),
    ncmds: derived(hex(r.buf, start + 16, 4), ncmds),
    sizeofcmds: derived(hex(r.buf, start + 20, 4), sizeofcmds),
    rawHex: hex(r.buf, start, headerSize)
  };
  let parseDiagnostic: Diagnostic | undefined;
  const commands: LoadCommandView[] = [];
  let signature: SignatureView | null = null;

  if (ncmds === null || sizeofcmds === null) {
    parseDiagnostic = diag("TRUNCATED_HEADER", "Mach-O 头部截断，ncmds/sizeofcmds 不可读");
  } else if (ncmds > budget.maxCommandsPerSlice) {
    parseDiagnostic = diag(
      "BUDGET_EXHAUSTED",
      `load command 数量 ${ncmds} 超出预算 ${budget.maxCommandsPerSlice}`
    );
  } else {
    let off = start + headerSize;
    for (let i = 0; i < ncmds; i++) {
      const cmd = r.u32(off, e);
      const cmdsize = r.u32(off + 4, e);
      const raw = hex(r.buf, off, cmdsize !== null && cmdsize >= 8 ? cmdsize : 8);
      const name = cmd !== null ? LOAD_COMMAND_NAMES[cmd] : undefined;
      const view: LoadCommandView = {
        index: i,
        cmd: derived(cmd !== null ? cmd.toString(16) : "", cmd),
        cmdName: derived(
          name ?? (cmd !== null ? `0x${cmd.toString(16)}` : ""),
          name ?? null,
          name === undefined
            ? diag("UNKNOWN_LOAD_COMMAND", `未知 load command，保留原始数值不猜测语义`)
            : undefined
        ),
        cmdsize: derived(cmdsize !== null ? cmdsize.toString(16) : "", cmdsize),
        start: coord(off - start, "slice", `0x${(off - start).toString(16)}`),
        end: coord(off - start + (cmdsize ?? 0), "slice", ""),
        rawHex: raw
      };
      if (cmd === LC_CODE_SIGNATURE && cmdsize !== null && cmdsize >= 16) {
        const dataoff = r.u32(off + 8, e);
        const datasize = r.u32(off + 12, e);
        if (dataoff !== null && datasize !== null) {
          view.codeSignature = {
            dataoff: coord(dataoff, "slice", `0x${dataoff.toString(16)}`),
            datasize: coord(datasize, "slice", `0x${datasize.toString(16)}`)
          };
        }
      }
      commands.push(view);
      if (cmdsize === null || cmdsize < 8) {
        parseDiagnostic = diag(
          "COMMAND_OUT_OF_BOUNDS",
          `load command #${i} 在切片偏移 0x${(off - start).toString(16)} 处 cmdsize 无效（${cmdsize}），停止遍历`
        );
        break;
      }
      off += cmdsize;
      if (off > start + headerSize + sizeofcmds) {
        parseDiagnostic = diag(
          "COMMAND_OUT_OF_BOUNDS",
          `load command #${i} 越过 sizeofcmds 声明的命令区末端`
        );
        break;
      }
    }
  }

  const sigCmd = commands.find((c) => c.codeSignature);
  if (sigCmd?.codeSignature) {
    const { dataoff, datasize } = sigCmd.codeSignature;
    if (dataoff.value + datasize.value > fat.size.value) {
      parseDiagnostic = diag(
        "SIG_OUT_OF_SLICE",
        `LC_CODE_SIGNATURE 指向切片外：dataoff 0x${dataoff.value.toString(16)} + datasize 0x${datasize.value.toString(16)} > 切片大小 0x${fat.size.value.toString(16)}`
      );
    } else {
      const sig = parseSignature(r, start, dataoff, datasize, budget);
      if ("diagnostic" in sig) {
        parseDiagnostic = sig.diagnostic;
      } else {
        signature = sig;
      }
    }
  }

  return { id, fat, header, commands, signature, parseDiagnostic };
}

/**
 * 解析入口：fat（通用二进制）或 thin Mach-O 都归一化为 FatContainer。
 * thin 输入包装成单切片伪容器，fat header 标记为 synthetic。
 */
export function parseContainer(
  bytes: Uint8Array,
  budget: ParseBudget
): ParseOutcome {
  const r = new Reader(bytes);
  const inputDigest = sha256Hex(bytes);
  const totalSize = coord(bytes.length, "file", `0x${bytes.length.toString(16)}`);

  const fatMagic = detectFatMagic(r);
  if (!fatMagic) {
    const machMagic = detectMachMagic(r, 0);
    if (!machMagic) {
      return {
        status: "corrupt_format",
        diagnostic: diag(
          "BAD_MAGIC",
          `文件头既不是 fat magic 也不是 Mach-O magic，实际字节 ${hex(bytes, 0, 4)}`,
          coord(0, "file", "0x0")
        )
      };
    }
    const e = machMagic.endian;
    const fakeFat: FatSliceView = {
      index: 0,
      cputype: derived(hex(bytes, 4, 4), r.u32(4, e)),
      cpusubtype: derived(hex(bytes, 8, 4), r.u32(8, e)),
      archName: derived(
        CPU_TYPE_NAMES[r.u32(4, e) ?? -1] ?? hex(bytes, 4, 4),
        CPU_TYPE_NAMES[r.u32(4, e) ?? -1] ?? null,
        CPU_TYPE_NAMES[r.u32(4, e) ?? -1]
          ? undefined
          : diag("UNKNOWN_CPU_TYPE", "未知 cputype，保留原始数值")
      ),
      offset: coord(0, "file", "0x0"),
      size: totalSize,
      alignExponent: derived("0", 0),
      alignment: derived("1", 1),
      rawHex: hex(bytes, 0, 20)
    };
    const header: FatHeaderView = {
      magic: derived(hex(bytes, 0, 4), machMagic.magic),
      endian: machMagic.endian,
      is64: machMagic.is64,
      nfatArch: derived("1(synthetic)", 1),
      rawHex: hex(bytes, 0, 8)
    };
    return {
      status: "ok",
      container: {
        inputDigest,
        totalSize,
        header,
        slices: [parseSlice(r, fakeFat, budget)]
      }
    };
  }

  const e = fatMagic.endian;
  const entrySize = fatMagic.is64 ? 32 : 20;
  const nfat = r.u32(4, e);
  const header: FatHeaderView = {
    magic: derived(hex(bytes, 0, 4), fatMagic.magic),
    endian: e,
    is64: fatMagic.is64,
    nfatArch: derived(hex(bytes, 4, 4), nfat),
    rawHex: hex(bytes, 0, 8)
  };
  if (nfat === null) {
    return {
      status: "corrupt_format",
      diagnostic: diag("TRUNCATED_HEADER", "fat header 截断，nfat_arch 不可读", coord(4, "file", "0x4"))
    };
  }
  if (nfat > budget.maxSlices) {
    return {
      status: "budget_exhausted",
      diagnostic: diag(
        "BUDGET_EXHAUSTED",
        `nfat_arch=${nfat} 超出切片预算 ${budget.maxSlices}，拒绝展开`,
        coord(4, "file", "0x4")
      )
    };
  }
  if (!r.has(8, nfat * entrySize)) {
    return {
      status: "corrupt_format",
      diagnostic: diag(
        "TRUNCATED_HEADER",
        `fat arch 表需要 ${nfat * entrySize} 字节但文件只有 ${bytes.length} 字节`,
        coord(8, "file", "0x8")
      )
    };
  }

  const slices: SliceView[] = [];
  for (let i = 0; i < nfat; i++) {
    const base = 8 + i * entrySize;
    const cputype = r.u32(base, e);
    const cpusubtype = r.u32(base + 4, e);
    let offsetD: Derived<number>;
    let sizeD: Derived<number>;
    let alignD: Derived<number>;
    if (fatMagic.is64) {
      offsetD = readU64Field(r, base + 8, e);
      sizeD = readU64Field(r, base + 16, e);
      alignD = derived(hex(bytes, base + 24, 4), r.u32(base + 24, e));
    } else {
      offsetD = derived(hex(bytes, base + 8, 4), r.u32(base + 8, e));
      sizeD = derived(hex(bytes, base + 12, 4), r.u32(base + 12, e));
      alignD = derived(hex(bytes, base + 16, 4), r.u32(base + 16, e));
    }
    const archName = CPU_TYPE_NAMES[cputype ?? -1];
    const fat: FatSliceView = {
      index: i,
      cputype: derived(hex(bytes, base, 4), cputype),
      cpusubtype: derived(hex(bytes, base + 4, 4), cpusubtype),
      archName: derived(
        archName ?? hex(bytes, base, 4),
        archName ?? null,
        archName ? undefined : diag("UNKNOWN_CPU_TYPE", "未知 cputype，保留原始数值")
      ),
      offset: coord(offsetD.value ?? 0, "file", offsetD.raw),
      size: coord(sizeD.value ?? 0, "file", sizeD.raw),
      alignExponent: alignD,
      alignment: derived(
        alignD.raw,
        alignD.value !== null && alignD.value <= 30 ? 2 ** alignD.value : null,
        alignD.value !== null && alignD.value > 30
          ? diag("ALIGNMENT_OVERFLOW", `对齐指数 ${alignD.value} 使 2^align 溢出 32 位偏移域`)
          : undefined
      ),
      rawHex: hex(bytes, base, entrySize)
    };
    if (offsetD.value === null || sizeD.value === null) {
      slices.push({
        id: `slice#${i}`,
        fat,
        header: null,
        commands: [],
        signature: null,
        parseDiagnostic:
          offsetD.diagnostic ?? sizeD.diagnostic ?? diag("BAD_ARCH_ENTRY", "arch 表项不可解析")
      });
      continue;
    }
    if (!r.has(offsetD.value, sizeD.value)) {
      slices.push({
        id: `slice@${offsetD.raw}`,
        fat,
        header: null,
        commands: [],
        signature: null,
        parseDiagnostic: diag(
          "SLICE_OUT_OF_FILE",
          `切片 [0x${offsetD.value.toString(16)}, +0x${sizeD.value.toString(16)}) 超出文件末尾 0x${bytes.length.toString(16)}`
        )
      });
      continue;
    }
    slices.push(parseSlice(r, fat, budget));
  }

  return { status: "ok", container: { inputDigest, totalSize, header, slices } };
}
