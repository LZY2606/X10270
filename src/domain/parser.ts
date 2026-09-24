import { ByteView, rangesOverlap } from "./bytes.js";
import {
  FAT_CIGAM, FAT_CIGAM_64, FAT_MAGIC, FAT_MAGIC_64,
  MH_CIGAM, MH_CIGAM_64, MH_MAGIC, MH_MAGIC_64,
  LC_CODE_SIGNATURE, LC_SEGMENT, LC_SEGMENT_64,
  CSMAGIC_CODEDIRECTORY, CSMAGIC_EMBEDDED_SIGNATURE,
  BLOB_TYPE_NAMES, cpuTypeName, loadCommandName,
} from "./constants.js";
import type {
  BlobIndexEntry, CodeSignatureRef, CodeSlotView, CoverageBand,
  Diagnostic, FatHeader, Finding, FindingCode, LoadCommandView, ParseResult,
  ParsedSlice, ResultClass, SignatureView, SliceDescriptor,
} from "./model.js";

let findingCounter = 0;
function resetIdentityCounter() {
  findingCounter = 0;
}
function fid(prefix: string, ...parts: (string | number)[]): string {
  return `${prefix}:${parts.join(":")}`;
}

export interface ParseOptions {
  scanBudgetBytes: number;
  unknownBlobIsError: boolean;
}

class FindingBuilder {
  readonly items: Finding[] = [];
  private seen = new Set<string>();
  add(d: Diagnostic, affected: string[]): Finding {
    const f: Finding = { ...d, id: fid("finding", this.items.length), affected };
    this.items.push(f);
    this.seen.add(d.code);
    return f;
  }
  addFinding(f: Finding): void {
    this.items.push(f);
    this.seen.add(f.code);
  }
  mark(code: string) {
    this.seen.add(code);
  }
  has(code: string): boolean {
    return this.seen.has(code);
  }
}

/** 解析 fat 容器（含 thin Mach-O 单切片兼容路径）。预算耗尽返回 budget-exhausted。 */
export function parseContainer(input: Buffer, opts: ParseOptions): ParseResult {
  resetIdentityCounter();
  const v = new ByteView(input);
  const findings = new FindingBuilder();
  const result: ParseResult = {
    resultClass: "ok",
    containerSize: v.length,
    fat: null,
    slices: [],
    findings: findings.items,
  };

  let bytesScanned = 0;
  const budgetLeft = (): boolean => {
    bytesScanned += 1;
    if (bytesScanned > opts.scanBudgetBytes) {
      if (!findings.has("BUDGET_EXHAUSTED")) {
        findings.mark("BUDGET_EXHAUSTED");
        findings.add(
          {
            code: "BUDGET_EXHAUSTED",
            severity: "error",
            message: `扫描预算耗尽：已扫描 ${bytesScanned} 字节，预算 ${opts.scanBudgetBytes} 字节，安全中止`,
            location: { offset: Math.min(bytesScanned, v.length), basis: "container-offset" },
          },
          ["container"],
        );
      }
      return false;
    }
    return true;
  };

  if (v.length < 4) {
    findings.add(
      {
        code: "RAW_PARSE_CORRUPT",
        severity: "error",
        message: "容器不足 4 字节，无法读取任何 magic",
        evidence: { actual: v.raw(0, v.length), range: { start: 0, end: v.length } },
      },
      ["container"],
    );
    result.resultClass = "corrupt";
    return finalize(result);
  }

  const be = v.u32(0, "big");
  const le = v.u32(0, "little");
  let fat: FatHeader | null = null;
  let descriptors: SliceDescriptor[] = [];
  let isThin = false;

  if (be === FAT_MAGIC || be === FAT_MAGIC_64 || le === FAT_CIGAM || le === FAT_CIGAM_64) {
    const flavor64 = be === FAT_MAGIC_64 || le === FAT_CIGAM_64;
    const swapped = le === FAT_CIGAM || le === FAT_CIGAM_64;
    // fat 头部字节序：magic 命中大端即 big；命中小端表示 fat 头本身被字节交换
    const endian = swapped ? "little" : "big";
    const nfatArch = v.u32(4, endian) ?? 0;
    const magicVal = flavor64 ? FAT_MAGIC_64 : FAT_MAGIC;
    const headerLen = flavor64 ? 8 : 8;
    fat = {
      id: "fat-header",
      magic: magicVal,
      magicHex: `0x${magicVal.toString(16)}`,
      declaredEndian: endian,
      nfatArch: v.u32(4, endian) ?? -1,
      rawMagic: v.hex(0, 4),
      flavor: flavor64 ? "fat64" : "fat32",
      rawBytes: v.hex(0, headerLen),
      range: { start: 0, end: headerLen },
    };
    result.fat = fat;
    if (swapped) {
      findings.mark("ENDIAN_SWAPPED");
      findings.add(
        {
          code: "ENDIAN_SWAPPED",
          severity: "warning",
          message: "fat header 字节序被交换（命中 CIGAM）；字段按小端重新解释，原始字节保留",
          location: { offset: 0, basis: "container-offset" },
          evidence: {
            actual: v.raw(0, 4),
            expected: [0xca, 0xfe, 0xba, flavor64 ? 0xbf : 0xbe],
            range: { start: 0, end: 4 },
          },
        },
        ["fat-header"],
      );
    }
    const parseDescr = parseDescriptors(v, endian, flavor64, nfatArch, findings, budgetLeft);
    descriptors = parseDescr.descriptors;
    if (parseDescr.aborted) {
      result.resultClass = "budget-exhausted";
      result.budget = { bytesScanned, limit: opts.scanBudgetBytes };
      return finalize(result);
    }
  } else if (be === MH_MAGIC || be === MH_MAGIC_64 || le === MH_CIGAM || le === MH_CIGAM_64) {
    isThin = true;
  } else {
    findings.add(
      {
        code: "ENDIAN_UNKNOWN",
        severity: "error",
        message: "容器 magic 既非 fat 也非 Mach-O（两种字节序均不命中），不支持的格式",
        location: { offset: 0, basis: "container-offset" },
        evidence: { actual: v.raw(0, 4), range: { start: 0, end: 4 } },
      },
      ["container"],
    );
    result.resultClass = "corrupt";
    return finalize(result);
  }

  if (isThin) {
    descriptors = [
      {
        id: "slice:0",
        index: 0,
        cputype: 0,
        cpusubtype: 0,
        archName: "thin",
        offset: 0,
        size: v.length,
        align: 0,
        alignmentBytes: 1,
        rawAlign: 0,
        endian: le === MH_CIGAM || le === MH_CIGAM_64 ? "little" : "big",
        range: { start: 0, end: v.length },
        descriptorRange: { start: 0, end: 0 },
        rawMagic: v.hex(0, 4),
      },
    ];
  }

  validateSliceLayout(v, descriptors, findings, !!fat);
  result.slices = descriptors.map((d) =>
    parseSlice(v, d, findings, opts, budgetLeft),
  );
  if (findings.has("BUDGET_EXHAUSTED")) {
    result.resultClass = "budget-exhausted";
    result.budget = { bytesScanned, limit: opts.scanBudgetBytes };
  }
  return finalize(result);
}

interface DescriptorParse {
  descriptors: SliceDescriptor[];
  aborted: boolean;
}

function parseDescriptors(
  v: ByteView,
  endian: "big" | "little",
  flavor64: boolean,
  count: number,
  findings: FindingBuilder,
  budgetLeft: () => boolean,
): DescriptorParse {
  const out: SliceDescriptor[] = [];
  let pos = flavor64 ? 8 : 8;
  const entrySize = flavor64 ? 32 : 20;
  if (count < 0 || count > 4096) {
    findings.add(
      {
        code: "RAW_PARSE_CORRUPT",
        severity: "error",
        message: `nfatArch 非法：${count}`,
        location: { offset: 4, basis: "container-offset" },
      },
      ["fat-header"],
    );
    return { descriptors: out, aborted: false };
  }
  for (let i = 0; i < count; i++) {
    if (!budgetLeft()) return { descriptors: out, aborted: true };
    const entryStart = pos;
    const entryEnd = pos + entrySize;
    if (entryEnd > v.length) {
      findings.add(
        {
          code: "RAW_PARSE_CORRUPT",
          severity: "error",
          message: `slice 描述符 #${i} 超出容器（声明区间 ${entryStart}..${entryEnd}，容器长度 ${v.length}）`,
          location: { offset: entryStart, basis: "container-offset" },
          evidence: { actual: v.raw(entryStart, Math.max(0, v.length - entryStart)), range: { start: entryStart, end: Math.min(entryEnd, v.length) } },
        },
        [fid("slice", i)],
      );
      break;
    }
    const cputype = v.u32(pos, endian)!;
    const cpusubtype = flavor64 ? Number(v.u64(pos + 8, endian)!) : v.u32(pos + 4, endian)!;
    let offset: number;
    let size: number;
    let align: number;
    if (flavor64) {
      // fat_arch_64: cputype(4) cpusubtype(4) pad(4) offset(8) size(8) align(4) reserved(4)
      offset = Number(v.u64(pos + 16, endian)!);
      size = Number(v.u64(pos + 24, endian)!);
      align = v.u32(pos + 32 - 4, endian)!;
    } else {
      // fat_arch: cputype(4) cpusubtype(4) offset(4) size(4) align(4)
      offset = v.u32(pos + 8, endian)!;
      size = v.u32(pos + 12, endian)!;
      align = v.u32(pos + 16, endian)!;
    }
    const d: SliceDescriptor = {
      id: fid("slice", i),
      index: i,
      cputype,
      cpusubtype,
      archName: cpuTypeName(cputype, cpusubtype),
      offset,
      size,
      align,
      alignmentBytes: safePow2(align),
      rawAlign: align,
      endian,
      range: { start: offset, end: offset + size },
      descriptorRange: { start: entryStart, end: entryEnd },
      rawMagic: offset + 4 <= v.length ? v.hex(offset, 4) : "",
    };
    out.push(d);
    pos = entryEnd;
  }
  return { descriptors: out, aborted: false };
}

/** 2^align；align>=32 视为溢出（对齐不靠四舍五入修正）。 */
function safePow2(align: number): number {
  if (!Number.isInteger(align) || align < 0) return NaN;
  if (align >= 32) return Infinity;
  return 2 ** align;
}

/** slice 布局规则：不得越界、不得重叠、对齐精确（不靠四舍五入）、多架构同名报告。 */
function validateSliceLayout(
  v: ByteView,
  slices: SliceDescriptor[],
  findings: FindingBuilder,
  isFat: boolean,
): void {
  // 越界与对齐
  for (const s of slices) {
    if (!isFat) continue;
    if (s.size < 4 || s.offset < 0 || s.range.end > v.length) {
      findings.add(
        {
          code: "RAW_PARSE_CORRUPT",
          severity: "error",
          message: `slice #${s.index} 数据区超出容器（offset=${s.offset}, size=${s.size}, container=${v.length}）`,
          location: { offset: s.offset, basis: "container-offset", sliceId: s.id },
        },
        [s.id],
      );
    }
    if (!Number.isFinite(s.alignmentBytes)) {
      findings.add(
        {
          code: "ALIGNMENT_OVERFLOW",
          severity: "error",
          message: `slice #${s.index} align=${s.align} 使 2^align 溢出；保留原始字段，不做修正`,
          location: { offset: s.descriptorRange.start, basis: "container-offset", sliceId: s.id },
        },
        [s.id],
      );
    } else if (s.alignmentBytes > 1 && s.offset % s.alignmentBytes !== 0) {
      const rounded = Math.round(s.offset / s.alignmentBytes) * s.alignmentBytes;
      findings.add(
        {
          code: "ALIGNMENT_ROUNDING_REFUSED",
          severity: "error",
          message: `slice #${s.index} offset=${s.offset} 不是 2^${s.align}=${s.alignmentBytes} 的倍数；拒绝四舍五入到 ${rounded}，保留原始偏移`,
          location: { offset: s.offset, basis: "container-offset", sliceId: s.id },
        },
        [s.id],
      );
    }
  }
  // 重叠（两两比较，等价输入顺序稳定：按 offset,size,index 排序）
  const ordered = [...slices].sort((a, b) => a.offset - b.offset || a.size - b.size || a.index - b.index);
  for (let i = 0; i < ordered.length; i++) {
    for (let j = i + 1; j < ordered.length; j++) {
      const a = ordered[i]!;
      const b = ordered[j]!;
      if (rangesOverlap(a.range, b.range)) {
        findings.add(
          {
            code: "SLICE_OVERLAP",
            severity: "error",
            message: `slice #${a.index} [${a.range.start},${a.range.end}) 与 slice #${b.index} [${b.range.start},${b.range.end}) 重叠`,
            location: { offset: Math.max(a.range.start, b.range.start), basis: "container-offset", sliceId: a.id },
          },
          [a.id, b.id],
        );
      }
    }
  }
  // 多架构同名：同一 archName 出现多次（保留全部候选，不自动选择）
  const byName = new Map<string, SliceDescriptor[]>();
  for (const s of slices) {
    const arr = byName.get(s.archName) ?? [];
    arr.push(s);
    byName.set(s.archName, arr);
  }
  for (const [name, arr] of byName) {
    if (arr.length > 1) {
      findings.add(
        {
          code: "ARCH_DUPLICATE",
          severity: "error",
          message: `架构 ${name} 对应多个 slice：${arr.map((s) => `#${s.index}`).join(", ")}；全部保留为合法候选，不自动选择`,
          location: { offset: arr[0]!.range.start, basis: "container-offset", sliceId: arr[0]!.id },
        },
        arr.map((s) => s.id),
      );
    }
  }
}

function parseSlice(
  v: ByteView,
  d: SliceDescriptor,
  findings: FindingBuilder,
  opts: ParseOptions,
  budgetLeft: () => boolean,
): ParsedSlice {
  const base = d.offset;
  const be = v.u32(base, "big");
  const le = v.u32(base, "little");
  let endian: "big" | "little";
  let is64 = false;
  if (be === MH_MAGIC || be === MH_MAGIC_64) {
    endian = "big";
    is64 = be === MH_MAGIC_64;
  } else if (le === MH_CIGAM || le === MH_CIGAM_64) {
    endian = "little";
    is64 = le === MH_CIGAM_64;
    findings.mark("ENDIAN_SWAPPED");
    findings.add(
      {
        code: "ENDIAN_SWAPPED",
        severity: "warning",
        message: `slice #${d.index} Mach-O 头为字节交换形式（CIGAM），按小端解释 load command`,
        location: { offset: base, basis: "container-offset", sliceId: d.id },
        evidence: { actual: v.raw(base, 4), range: { start: base, end: base + 4 } },
      },
      [d.id],
    );
  } else {
    findings.add(
      {
        code: "RAW_PARSE_CORRUPT",
        severity: "error",
        message: `slice #${d.index} Mach-O magic 不识别（be=0x${(be ?? 0).toString(16)}, le=0x${(le ?? 0).toString(16)}）`,
        location: { offset: base, basis: "container-offset", sliceId: d.id },
        evidence: { actual: v.raw(base, 4), range: { start: base, end: base + 4 } },
      },
      [d.id],
    );
    return {
      id: d.id,
      descriptor: d,
      machMagic: 0,
      machMagicHex: "0x0",
      commands: [],
      signature: null,
      ncmds: 0,
      sizeofcmds: 0,
    };
  }

  const machMagic = is64 ? MH_MAGIC_64 : MH_MAGIC;
  const headerSize = is64 ? 32 : 28;
  const ncmds = v.u32(base + 16, endian) ?? 0;
  const sizeofcmds = v.u32(base + 20, endian) ?? 0;
  const sliceEnd = Math.min(d.range.end, v.length);
  const declaredCmdEnd = base + headerSize + sizeofcmds;
  const commandAreaEnd = Math.min(declaredCmdEnd, sliceEnd);
  if (sizeofcmds > 0 && declaredCmdEnd > sliceEnd) {
    findings.add(
      {
        code: "COMMAND_OUT_OF_BOUNDS",
        severity: "error",
        message: `slice #${d.index} mach_header 声明 sizeofcmds=${sizeofcmds}，命令区结束 ${declaredCmdEnd} 越出 slice 结束 ${sliceEnd}`,
        location: { offset: base + 20, basis: "container-offset", sliceId: d.id },
        evidence: { actual: v.raw(base + 20, 4), range: { start: base + 20, end: base + 24 } },
      },
      [d.id],
    );
  }

  const commands: LoadCommandView[] = [];
  let p = base + headerSize;
  for (let i = 0; i < ncmds; i++) {
    if (!budgetLeft()) break;
    if (p + 8 > sliceEnd) {
      commands.push(oobCommand(i, p, v, endian, d));
      findings.addFinding(commandOob(i, p, d, v));
      break;
    }
    const cmd = v.u32(p, endian)!;
    const cmdsize = v.u32(p + 4, endian)!;
    const declEnd = p + cmdsize;
    let segName: string | undefined;
    if (cmd === LC_SEGMENT || cmd === LC_SEGMENT_64) {
      const raw = v.slice(p + 8, p + 24);
      if (raw) segName = Buffer.from(raw).toString("utf8").replace(/\0+$/g, "");
    }
    const outOfBounds = cmdsize < 8 || declEnd > sliceEnd || declEnd > commandAreaEnd;
    const lc: LoadCommandView = {
      id: fid(d.id, "lc", i),
      index: i,
      cmd,
      cmdHex: `0x${cmd.toString(16).padStart(8, "0")}`,
      cmdsize,
      name: loadCommandName(cmd),
      range: { start: p, end: Math.min(declEnd, sliceEnd) },
      outOfBounds,
      segmentName: segName || undefined,
      isCodeSignature: cmd === LC_CODE_SIGNATURE,
    };
    if (declEnd > commandAreaEnd || declEnd > sliceEnd || cmdsize < 8) {
      lc.outOfBounds = true;
      findings.addFinding(commandOob(i, p, d, v, cmdsize, commandAreaEnd));
    }
    commands.push(lc);
    if (cmdsize < 8) break;
    p = declEnd;
  }

  const sigLc = commands.find((c) => c.isCodeSignature && !c.outOfBounds);
  let signature: SignatureView | null = null;
  if (sigLc) {
    signature = parseSignature(v, d, sigLc, endian, findings, opts, budgetLeft);
  }
  return {
    id: d.id,
    descriptor: d,
    machMagic,
    machMagicHex: `0x${machMagic.toString(16)}`,
    commands,
    signature,
    ncmds,
    sizeofcmds,
  };
}


function oobCommand(i: number, p: number, v: ByteView, endian: "big" | "little", d: SliceDescriptor): LoadCommandView {
  const cmd = v.u32(p, endian) ?? 0;
  const cmdsize = v.u32(p + 4, endian) ?? 0;
  return {
    id: fid(d.id, "lc", i),
    index: i,
    cmd,
    cmdHex: `0x${cmd.toString(16).padStart(8, "0")}`,
    cmdsize,
    name: loadCommandName(cmd),
    range: { start: p, end: p + Math.max(cmdsize, 0) },
    outOfBounds: true,
    isCodeSignature: cmd === LC_CODE_SIGNATURE,
  };
}

function commandOob(
  i: number,
  p: number,
  d: SliceDescriptor,
  v: ByteView,
  cmdsize?: number,
  commandAreaEnd?: number,
): Finding {
  return {
    id: fid("finding", `lcoob-${d.index}-${i}`),
    code: "COMMAND_OUT_OF_BOUNDS",
    severity: "error",
    message:
      cmdsize === undefined
        ? `slice #${d.index} load command #${i} 头部超出 slice 边界（offset=${p}）`
        : `slice #${d.index} load command #${i} cmdsize=${cmdsize} 使区间越出 command 区（command 区结束=${commandAreaEnd}）`,
    location: { offset: p, basis: "container-offset", sliceId: d.id },
    evidence: { actual: v.raw(p, 8), range: { start: p, end: p + 8 } },
    affected: [d.id, fid(d.id, "lc", i)],
  };
}

const SHA1_LEN = 20;
const CODE_PAGE_SIZE = 256; // 本案例包统一页大小（CodeDirectory codeShift 会真实编码）

function parseSignature(
  v: ByteView,
  d: SliceDescriptor,
  sigLc: LoadCommandView,
  endian: "big" | "little",
  findings: FindingBuilder,
  opts: ParseOptions,
  budgetLeft: () => boolean,
): SignatureView {
  // LC_CODE_SIGNATURE: cmd(4) cmdsize(4) dataoff(4, slice-local) datasize(4)
  const lcStart = sigLc.range.start;
  const dataoff = v.u32(lcStart + 8, endian)!;
  const datasize = v.u32(lcStart + 12, endian)!;
  const sigStart = d.offset + dataoff;
  const sigEnd = sigStart + datasize;
  const affectedId = fid(d.id, "signature");

  const ref: CodeSignatureRef = {
    id: fid(d.id, "sigref"),
    dataoff,
    datasize,
    range: { start: sigStart, end: sigEnd },
    magic: 0,
    magicHex: "0x0",
    length: datasize,
    blobCount: 0,
    rawMagic: v.hex(sigStart, 4),
  };

  const view: SignatureView = { id: affectedId, sliceId: d.id, ref, blobs: [], slots: [], coverage: [] };
  if (sigEnd > d.range.end || dataoff < 0) {
    ref.magic = v.u32(sigStart, "little") ?? 0;
    ref.magicHex = `0x${ref.magic.toString(16)}`;
    findings.add(
      {
        code: "UNSUPPORTED_SIGNATURE_FORMAT",
        severity: "error",
        message: `slice #${d.index} LC_CODE_SIGNATURE 声明区间 [${sigStart},${sigEnd}) 越出 slice 结束 ${d.range.end}`,
        location: { offset: sigStart, basis: "container-offset", sliceId: d.id },
        evidence: { actual: v.raw(Math.min(sigStart, v.length - 4), 4), range: { start: sigStart, end: sigEnd } },
      },
      [d.id, affectedId],
    );
    return view;
  }

  const magic = v.u32(sigStart, "little");
  ref.magic = magic ?? 0;
  ref.magicHex = `0x${(magic ?? 0).toString(16)}`;
  if (magic !== CSMAGIC_EMBEDDED_SIGNATURE) {
    findings.add(
      {
        code: "UNSUPPORTED_SIGNATURE_FORMAT",
        severity: "error",
        message: `slice #${d.index} 签名 blob magic=0x${(magic ?? 0).toString(16)} 非嵌入签名 SuperBlob 0x${CSMAGIC_EMBEDDED_SIGNATURE.toString(16)}`,
        location: { offset: sigStart, basis: "container-offset", sliceId: d.id },
        evidence: {
          actual: v.raw(sigStart, 4),
          expected: [0xc0, 0x0c, 0xde, 0xfa],
          range: { start: sigStart, end: sigStart + 4 },
        },
      },
      [d.id, affectedId],
    );
    return view;
  }

  const length = v.u32(sigStart + 4, "little")!;
  const count = v.u32(sigStart + 8, "little")!;
  ref.length = length;
  ref.blobCount = count;

  // SuperBlob 声明长度超出 slice：覆盖缺口（签名未覆盖尾部由覆盖带另行标注）
  if (sigStart + length > d.range.end) {
    findings.add(
      {
        code: "SIGNATURE_COVERAGE_GAP",
        severity: "error",
        message: `slice #${d.index} SuperBlob length=${length} 越出 slice（声明结束 ${sigStart + length} > ${d.range.end}）`,
        location: { offset: d.range.end, basis: "container-offset", sliceId: d.id },
      },
      [d.id, affectedId],
    );
  }

  const blobs: BlobIndexEntry[] = [];
  let codeDirRange: { start: number; end: number } | null = null;
  for (let i = 0; i < count; i++) {
    if (!budgetLeft()) break;
    const idxPos = sigStart + 12 + i * 8;
    const type = v.u32(idxPos, "little")!;
    const offset = v.u32(idxPos + 4, "little")!;
    const blobStart = sigStart + offset;
    const blobLen = v.u32(blobStart + 4, "little") ?? 0;
    const blobEnd = blobStart + blobLen;
    const known = type === 0 || BLOB_TYPE_NAMES[type] !== undefined || v.u32(blobStart, "little") === CSMAGIC_CODEDIRECTORY;
    const typeName = blobTypeName(type, v, blobStart);
    const entry: BlobIndexEntry = {
      id: fid(d.id, "blob", i),
      type,
      typeName,
      offset,
      length: blobLen,
      range: { start: blobStart, end: blobEnd },
      known: type === 0 || typeName !== "UnknownBlob",
    };
    blobs.push(entry);
    if (entry.typeName === "UnknownBlob") {
      findings.add(
        {
          code: "UNKNOWN_BLOB",
          severity: opts.unknownBlobIsError ? "error" : "warning",
          message: `slice #${d.index} 签名索引 #${i} 出现未知 blob type=0x${type.toString(16)}（offset=${offset}）；保留候选，不丢弃`,
          location: { offset: idxPos, basis: "container-offset", sliceId: d.id },
          evidence: { actual: v.raw(idxPos, 8), range: { start: idxPos, end: idxPos + 8 } },
        },
        [d.id, entry.id],
      );
    }
    if (type === 0) codeDirRange = { start: blobStart, end: blobEnd };
  }
  view.blobs = blobs;

  if (codeDirRange) {
    const slots = parseCodeDirectory(v, d, codeDirRange.start, sigStart, findings, opts, budgetLeft);
    view.slots = slots;
  }
  view.coverage = buildCoverage(d, ref, view.slots, findings);
  return view;
}

function blobTypeName(type: number, v: ByteView, blobStart: number): string {
  if (type === 0) return "CodeDirectory";
  const named = BLOB_TYPE_NAMES[type];
  if (named) return named;
  const magic = v.u32(blobStart, "little");
  if (magic === CSMAGIC_CODEDIRECTORY) return "CodeDirectory";
  return "UnknownBlob";
}

import { sha1Hex } from "./bytes.js";

/**
 * CodeDirectory（版本 0x20100 布局，本案例包统一构造）：
 * 0  magic(4) 4 length(4) 8 version(4) 12 flags(4)
 * 16 hashOffset(4) 20 identOffset(4) 24 nSpecialSlots(4) 28 nCodeSlots(4)
 * 32 codeLimit(4) 36 hashSize(1) 37 hashType(1) 38 platform(1) 39 pageSize(1)
 * 40 spare2(4) 44 scatterOffset(4) ... codeShift 在本版本偏移 56（可选字段）
 * 对案例包：pageSize=8（2^8=256 字节），hashSize=20，hashType=1(SHA1)
 */
function parseCodeDirectory(
  v: ByteView,
  d: SliceDescriptor,
  cdStart: number,
  _sigStart: number,
  findings: FindingBuilder,
  _opts: ParseOptions,
  budgetLeft: () => boolean,
): CodeSlotView[] {
  const slots: CodeSlotView[] = [];
  const version = v.u32(cdStart + 8, "little");
  const hashOffset = v.u32(cdStart + 16, "little");
  const nSpecial = v.u32(cdStart + 24, "little");
  const nCode = v.u32(cdStart + 28, "little");
  const codeLimit = v.u32(cdStart + 32, "little");
  const hashSize = v.buf[cdStart + 36] ?? 0;
  const hashType = v.buf[cdStart + 37] ?? 0;
  const pageShift = v.buf[cdStart + 39] ?? 0;
  if (
    version === null || hashOffset === null || nSpecial === null ||
    nCode === null || codeLimit === null
  ) {
    findings.add(
      {
        code: "UNSUPPORTED_SIGNATURE_FORMAT",
        severity: "error",
        message: `slice #${d.index} CodeDirectory 头部字段不完整`,
        location: { offset: cdStart, basis: "container-offset", sliceId: d.id },
      },
      [d.id, fid(d.id, "signature")],
    );
    return slots;
  }
  if (hashType !== 1 || hashSize !== SHA1_LEN || version! < 0x20100) {
    findings.add(
      {
        code: "UNSUPPORTED_SIGNATURE_FORMAT",
        severity: "error",
        message: `slice #${d.index} CodeDirectory 不支持：hashType=${hashType} hashSize=${hashSize} version=0x${version!.toString(16)}（仅支持 SHA1/20/v0x20100+）`,
        location: { offset: cdStart + 36, basis: "container-offset", sliceId: d.id },
        evidence: { actual: v.raw(cdStart + 36, 4), range: { start: cdStart + 36, end: cdStart + 40 } },
      },
      [d.id, fid(d.id, "signature")],
    );
    return slots;
  }
  const pageSize = 2 ** pageShift;
  const hashArea = cdStart + hashOffset!;
  const codeStart = d.offset;
  const signedCodeEnd = d.offset + codeLimit!;

  // 特殊槽位（倒序存储：最特殊的在最低地址）
  for (let s = nSpecial!; s >= 1; s--) {
    if (!budgetLeft()) return slots;
    const slotIndex = -s;
    const pos = hashArea + (nSpecial! - s) * hashSize;
    const raw = v.slice(pos, pos + hashSize);
    slots.push({
      id: fid(d.id, "slot", `sp${s}`),
      slot: slotIndex,
      kind: "special",
      hashHex: raw ? Buffer.from(raw).toString("hex") : "",
      match: null,
    });
  }
  // 代码槽位
  for (let i = 0; i < nCode!; i++) {
    if (!budgetLeft()) return slots;
    const pos = hashArea + nSpecial! * hashSize + i * hashSize;
    const stored = v.slice(pos, pos + hashSize);
    const pageStart = codeStart + i * pageSize;
    const pageEnd = Math.min(pageStart + pageSize, signedCodeEnd);
    const pageBuf = v.slice(pageStart, pageEnd);
    let expected: string | undefined;
    let match: boolean | null = null;
    if (pageBuf && pageEnd > pageStart) {
      // 最后一页按实际长度哈希（codesign 规则），其余按整页
      expected = sha1Hex(Buffer.from(pageBuf));
      match = stored ? Buffer.from(stored).toString("hex") === expected : false;
    }
    const slotId = fid(d.id, "slot", i);
    if (match === false) {
      findings.add(
        {
          code: "SIGNATURE_HASH_MISMATCH",
          severity: "error",
          message: `slice #${d.index} code slot #${i}（页偏移 ${i * pageSize}）摘要不匹配`,
          location: { offset: pageStart, basis: "container-offset", sliceId: d.id },
          evidence: {
            actual: stored ? Array.from(stored) : [],
            expected: expected ? Array.from(Buffer.from(expected, "hex")) : undefined,
            range: { start: pos, end: pos + hashSize },
          },
        },
        [d.id, slotId],
      );
    }
    slots.push({
      id: slotId,
      slot: i,
      kind: "code",
      hashHex: stored ? Buffer.from(stored).toString("hex") : "",
      expectedHex: expected,
      match,
      pageIndex: i,
      pageRange: { start: pageStart, end: pageEnd },
    });
  }
  return slots;
}

/** 覆盖带：代码页 covered → 签名前缺口 uncovered → 签名 blob → slice 尾部 tail-gap。 */
function buildCoverage(
  d: SliceDescriptor,
  ref: CodeSignatureRef,
  slots: CodeSlotView[],
  findings: FindingBuilder,
): CoverageBand[] {
  const bands: CoverageBand[] = [];
  let signedEnd = d.offset;
  for (const s of slots) {
    if (s.kind === "code" && s.pageRange) {
      bands.push({
        id: fid(d.id, "band", s.slot),
        kind: s.match === false ? "uncovered" : "code-covered",
        range: { ...s.pageRange },
        label: `code page #${s.slot}`,
        slotId: s.id,
      });
      signedEnd = Math.max(signedEnd, s.pageRange.end);
    }
  }
  const sigStart = ref.range.start;
  if (signedEnd < sigStart) {
    bands.push({
      id: fid(d.id, "band", "pre-sig-gap"),
      kind: "uncovered",
      range: { start: signedEnd, end: sigStart },
      label: "签名前未覆盖字节",
    });
    findings.add(
      {
        code: "SIGNATURE_COVERAGE_GAP",
        severity: "error",
        message: `slice #${d.index} 代码槽只覆盖到 ${signedEnd}，签名始于 ${sigStart}，中间 ${sigStart - signedEnd} 字节无覆盖（覆盖缺口，区别于尾部缺口）`,
        location: { offset: signedEnd, basis: "container-offset", sliceId: d.id },
      },
      [d.id, fid(d.id, "signature")],
    );
  }
  bands.push({
    id: fid(d.id, "band", "signature"),
    kind: "signature-blob",
    range: { ...ref.range },
    label: "embedded signature SuperBlob",
  });
  if (ref.range.end < d.range.end) {
    bands.push({
      id: fid(d.id, "band", "tail"),
      kind: "tail-gap",
      range: { start: ref.range.end, end: d.range.end },
      label: "签名未覆盖尾部",
    });
    findings.add(
      {
        code: "SIGNATURE_TAIL_GAP",
        severity: "error",
        message: `slice #${d.index} 签名 blob 结束于 ${ref.range.end}，slice 结束于 ${d.range.end}，尾部 ${d.range.end - ref.range.end} 字节未被签名覆盖`,
        location: { offset: ref.range.end, basis: "container-offset", sliceId: d.id },
        evidence: { actual: [], range: { start: ref.range.end, end: d.range.end } },
      },
      [d.id, fid(d.id, "signature")],
    );
  }
  return bands.sort((a, b) => a.range.start - b.range.start);
}

function finalize(r: ParseResult): ParseResult {
  if (r.resultClass !== "ok") return r;
  const codes = new Set(r.findings.map((f) => f.code));
  const corruptCodes: FindingCode[] = ["RAW_PARSE_CORRUPT", "ENDIAN_UNKNOWN"];
  const semanticCodes: FindingCode[] = [
    "SLICE_OVERLAP",
    "ALIGNMENT_OVERFLOW",
    "ALIGNMENT_ROUNDING_REFUSED",
    "COMMAND_OUT_OF_BOUNDS",
    "ARCH_DUPLICATE",
  ];
  if (corruptCodes.some((c) => codes.has(c))) r.resultClass = "corrupt";
  else if (semanticCodes.some((c) => codes.has(c))) r.resultClass = "semantically-unsolvable";
  else if (r.findings.length > 0) r.resultClass = "partial";
  return r;
}
