/**
 * 离线案例包固件：真实字节构造的 universal Mach-O（fat64）。
 * 代码槽位覆盖从 slice 偏移 0 开始（含 Mach-O 头与 load commands），
 * codeLimit = pageSize * pageCount；覆盖缺口位于代码区与签名之间，
 * 尾部缺口位于签名之后。所有写入带偏移与字节序，可逐字节复核。
 */

export interface BuiltBinary {
  bytes: Buffer;
  layout: BinaryLayout;
}

export interface BinaryLayout {
  slices: Array<{
    index: number;
    cputype: number;
    cpusubtype: number;
    offset: number;
    size: number;
    align: number;
    codeLimit: number;
    signature: { dataoff: number; datasize: number; start: number; end: number };
  }>;
}

export const CPU_X86_64 = 0x01000007;
export const CPU_ARM64 = 0x0100000c;
export const SUBTYPE_ARM64E = 2;
export const PAGE_SIZE = 256;

function w32(buf: Buffer, off: number, val: number, endian: "big" | "little" = "little"): void {
  if (endian === "big") buf.writeUInt32BE(val >>> 0, off);
  else buf.writeUInt32LE(val >>> 0, off);
}
function w64(buf: Buffer, off: number, val: bigint, endian: "big" | "little" = "little"): void {
  if (endian === "big") buf.writeBigUInt64BE(val, off);
  else buf.writeBigUInt64LE(val, off);
}

import { createHash } from "node:crypto";
import {
  MH_MAGIC_64, LC_SEGMENT_64, LC_CODE_SIGNATURE,
  CSMAGIC_EMBEDDED_SIGNATURE, CSMAGIC_CODEDIRECTORY,
} from "./constants.js";

export interface SliceSpec {
  cputype: number;
  cpusubtype: number;
  /** 写入代码区的数据字节（从 load commands 之后开始铺），用于源数据改动场景 */
  payload: number[];
  pageCount?: number;
  /** 翻转指定代码槽摘要 → hash mismatch */
  corruptSlotPage?: number;
  /** 签名之后未覆盖尾部字节数 */
  tailGap?: number;
  /** 代码区与签名之间的覆盖缺口字节数（不计入 codeLimit） */
  coverageGap?: number;
  /** 覆盖签名 SuperBlob magic（不支持格式） */
  signatureMagic?: number;
  /** 额外未知 blob type */
  extraUnknownBlob?: number;
  /** 追加一条哈希有效但 cmdsize 声明越界的命令 */
  bogusOobCommand?: boolean;
}

const HEADER_LEN = 32;
const LC_SEGMENT_64_LEN = 72;
const LC_SIG_LEN = 16;

export function buildSlice(spec: SliceSpec): { bytes: Buffer; layout: BinaryLayout["slices"][number] } {
  const pageCount = spec.pageCount ?? 1;
  const codeLimit = pageCount * PAGE_SIZE;
  const cmdsLen = LC_SEGMENT_64_LEN + LC_SIG_LEN + (spec.bogusOobCommand ? 16 : 0);
  const gap = spec.coverageGap ?? 0;
  const tail = spec.tailGap ?? 0;

  const nSpecial = 1;
  const nCode = pageCount;
  const cdHeaderLen = 60;
  const hashAreaLen = (nSpecial + nCode) * 20;
  const ident = Buffer.from("fixture.slice\0", "utf8");
  const cdBodyLen = cdHeaderLen + hashAreaLen + ident.length;
  const cdPadded = Math.ceil(cdBodyLen / 8) * 8;

  const hasUnknown = spec.extraUnknownBlob !== undefined;
  const blobCount = hasUnknown ? 2 : 1;
  const indexLen = 12 + blobCount * 8;
  const cdOffset = Math.ceil(indexLen / 8) * 8;
  const unknownLen = hasUnknown ? 16 : 0;
  const unknownOffset = cdOffset + cdPadded;
  const sigLen = hasUnknown ? unknownOffset + unknownLen : cdOffset + cdPadded;

  const sigLocalOff = codeLimit + gap;
  const sliceSize = codeLimit + gap + sigLen + tail;
  const out = Buffer.alloc(sliceSize);

  // Mach-O header（位于代码页 0，因此也被哈希覆盖）
  w32(out, 0, MH_MAGIC_64, "little");
  w32(out, 4, spec.cputype);
  w32(out, 8, spec.cpusubtype);
  w32(out, 12, 0x00002000);
  w32(out, 16, spec.bogusOobCommand ? 3 : 2);
  w32(out, 20, cmdsLen);
  w32(out, 24, 0x00200085);

  let p = HEADER_LEN;
  w32(out, p, LC_SEGMENT_64);
  w32(out, p + 4, LC_SEGMENT_64_LEN);
  out.write("__TEXT", p + 8, "utf8");
  w64(out, p + 24, 0n);
  w64(out, p + 32, BigInt(sliceSize));
  w64(out, p + 40, 0n);
  w64(out, p + 48, BigInt(codeLimit));
  p += LC_SEGMENT_64_LEN;
  w32(out, p, LC_CODE_SIGNATURE);
  w32(out, p + 4, LC_SIG_LEN);
  w32(out, p + 8, sigLocalOff);
  w32(out, p + 12, sigLen);
  if (spec.bogusOobCommand) {
    // 第三条命令的字节真实存在（因此代码页哈希有效），但 cmdsize=96 声明区间越出 slice
    const q = p + LC_SIG_LEN;
    w32(out, q, 0x00000077);
    w32(out, q + 4, 96);
  }

  for (const [i, b] of spec.payload.entries()) {
    const at = HEADER_LEN + cmdsLen + i;
    if (at < codeLimit) out[at] = b & 0xff;
  }

  // 覆盖缺口（位于代码区之后、签名之前）——不写入，保持零字节但区间存在

  // SuperBlob
  const sb = sigLocalOff;
  w32(out, sb, spec.signatureMagic ?? CSMAGIC_EMBEDDED_SIGNATURE, "little");
  w32(out, sb + 4, sigLen);
  w32(out, sb + 8, blobCount);
  w32(out, sb + 12, 0);
  w32(out, sb + 16, cdOffset);
  if (hasUnknown) {
    w32(out, sb + 20, spec.extraUnknownBlob!);
    w32(out, sb + 24, unknownOffset);
  }

  // CodeDirectory
  const cd = sb + cdOffset;
  w32(out, cd, CSMAGIC_CODEDIRECTORY, "little");
  w32(out, cd + 4, cdBodyLen);
  w32(out, cd + 8, 0x00020100);
  w32(out, cd + 12, 0);
  w32(out, cd + 16, cdHeaderLen);
  w32(out, cd + 20, cdHeaderLen + hashAreaLen);
  w32(out, cd + 24, nSpecial);
  w32(out, cd + 28, nCode);
  w32(out, cd + 32, codeLimit);
  out[cd + 36] = 20;
  out[cd + 37] = 1;
  out[cd + 38] = 0;
  out[cd + 39] = 8;
  ident.copy(out, cd + cdHeaderLen + hashAreaLen);

  // 特殊槽位保持零；代码槽位按最终 slice 字节哈希
  for (let i = 0; i < nCode; i++) {
    const page = out.subarray(i * PAGE_SIZE, (i + 1) * PAGE_SIZE);
    const h = createHash("sha1").update(page).digest();
    if (spec.corruptSlotPage === i) h[0] = h[0]! ^ 0xff;
    h.copy(out, cd + cdHeaderLen + nSpecial * 20 + i * 20);
  }
  if (hasUnknown) {
    const u = sb + unknownOffset;
    w32(out, u, 0x11223344);
    w32(out, u + 4, unknownLen);
    out.write("UNKN", u + 8, "utf8");
  }

  return {
    bytes: out,
    layout: {
      index: 0,
      cputype: spec.cputype,
      cpusubtype: spec.cpusubtype,
      offset: 0,
      size: sliceSize,
      align: 12,
      codeLimit,
      signature: { dataoff: sigLocalOff, datasize: sigLen, start: sb, end: sb + sigLen },
    },
  };
}

export interface FatSliceInput {
  cputype: number;
  cpusubtype: number;
  align?: number;
  /** 强制覆盖放置偏移（用于重叠 / 对齐变异） */
  forceOffset?: number;
  /** 强制覆盖 size（用于 command 越界之外的布局问题） */
  forceSize?: number;
  sliceBytes: Buffer;
}

export interface FatBuildOptions {
  /** 交换 fat header 整体字节序（大小端） */
  byteSwapFatHeader?: boolean;
}

/** 构造 fat64 容器（大端 fat 头 + 4096 对齐 slice）。 */
export function buildFat64(inputs: FatSliceInput[], opts: FatBuildOptions = {}): BuiltBinary {
  const headerSize = 8;
  const tableSize = inputs.length * 32;
  let cursor = Math.ceil((headerSize + tableSize) / 4096) * 4096;
  const placed: Array<{ input: FatSliceInput; offset: number }> = [];
  for (const input of inputs) {
    let offset: number;
    if (input.forceOffset !== undefined) {
      offset = input.forceOffset;
    } else {
      const align = 1 << (input.align ?? 12);
      offset = Math.ceil(cursor / align) * align;
    }
    placed.push({ input, offset });
    cursor = offset + input.sliceBytes.length;
  }
  const total = Math.max(...placed.map((p) => p.offset + (p.input.forceSize ?? p.input.sliceBytes.length)));
  const buf = Buffer.alloc(total);

  const endian: "big" | "little" = opts.byteSwapFatHeader ? "little" : "big";
  w32(buf, 0, 0xcafebabf, endian);
  w32(buf, 4, inputs.length, endian);
  placed.forEach((p, i) => {
    const pos = 8 + i * 32;
    w32(buf, pos, p.input.cputype, endian);
    w32(buf, pos + 4, p.input.cpusubtype, endian);
    w64(buf, pos + 8, BigInt(p.offset), endian);
    w64(buf, pos + 16, BigInt(p.input.forceSize ?? p.input.sliceBytes.length), endian);
    w32(buf, pos + 24, p.input.align ?? 12, endian);
    w32(buf, pos + 28, 0, endian);
    p.input.sliceBytes.copy(buf, p.offset);
  });
  return {
    bytes: buf,
    layout: {
      slices: placed.map((p, i) => ({
        index: i,
        cputype: p.input.cputype,
        cpusubtype: p.input.cpusubtype,
        offset: p.offset,
        size: p.input.forceSize ?? p.input.sliceBytes.length,
        align: p.input.align ?? 12,
        codeLimit: 0,
        signature: { dataoff: 0, datasize: 0, start: 0, end: 0 },
      })),
    },
  };
}

/** 便捷构造：基线双架构 fat64（x86_64 + arm64）。 */
export function buildBaselineFat(): BuiltBinary {
  const x64 = buildSlice({
    cputype: CPU_X86_64,
    cpusubtype: 3,
    payload: Array.from(Buffer.from("x86_64 platform engineering baseline", "utf8")),
  });
  const arm = buildSlice({
    cputype: CPU_ARM64,
    cpusubtype: 0,
    payload: Array.from(Buffer.from("arm64 platform engineering baseline", "utf8")),
  });
  const fat = buildFat64([
    { cputype: CPU_X86_64, cpusubtype: 3, sliceBytes: x64.bytes },
    { cputype: CPU_ARM64, cpusubtype: 0, sliceBytes: arm.bytes },
  ]);
  // 记录 slice 内签名坐标到 layout
  fat.layout.slices[0]!.codeLimit = x64.layout.codeLimit;
  fat.layout.slices[0]!.signature = x64.layout.signature;
  fat.layout.slices[1]!.codeLimit = arm.layout.codeLimit;
  fat.layout.slices[1]!.signature = arm.layout.signature;
  // 修正签名容器坐标
  for (let i = 0; i < 2; i++) {
    const off = fat.layout.slices[i]!.offset;
    const s = i === 0 ? x64.layout.signature : arm.layout.signature;
    fat.layout.slices[i]!.signature = {
      dataoff: s.dataoff,
      datasize: s.datasize,
      start: off + s.start,
      end: off + s.end,
    };
  }
  return fat;
}
