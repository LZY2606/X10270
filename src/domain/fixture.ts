import { createHash } from "node:crypto";

const CPU: Record<string, number> = { x86_64: 0x01000007, arm64: 0x0100000c };
const PAGE = 4096;

function u32(buf: Uint8Array, off: number, v: number, be: boolean): void {
  if (be) {
    buf[off] = (v >>> 24) & 0xff; buf[off + 1] = (v >>> 16) & 0xff;
    buf[off + 2] = (v >>> 8) & 0xff; buf[off + 3] = v & 0xff;
  } else {
    buf[off] = v & 0xff; buf[off + 1] = (v >>> 8) & 0xff;
    buf[off + 2] = (v >>> 16) & 0xff; buf[off + 3] = (v >>> 24) & 0xff;
  }
}

export interface SliceSpec {
  arch: "x86_64" | "arm64";
  endian?: "le" | "be";
  pages?: number;
  tailGap?: number;        // 签名前未覆盖尾部
  corruptCode?: boolean;   // 构造后翻转代码字节 → hash 不匹配
  unknownBlob?: boolean;   // 未知签名 blob magic
  cmdOob?: boolean;        // 末条 command 越界
  badMagic?: boolean;      // 无法判定字节序的 magic
}

export interface BuiltSlice { bytes: Uint8Array; sigOff: number; sigSize: number; codeLimit: number }

export function buildSlice(spec: SliceSpec): BuiltSlice {
  const endian = spec.endian ?? "le";
  const be = endian === "be";
  const pages = spec.pages ?? 2;
  const codeLimit = pages * PAGE;
  const sigOff = codeLimit + (spec.tailGap ?? 0);
  const nSlots = Math.ceil(codeLimit / PAGE);

  const sizeofcmds = 72 + 24 + 16;
  const headerSize = 32 + sizeofcmds;
  const cdLen = 44 + nSlots * 32;
  const blobLen = 12 + 8 + cdLen;
  const total = sigOff + blobLen;
  const buf = new Uint8Array(total);

  // mach_header_64
  if (!spec.badMagic) {
    if (be) { buf[0] = 0xfe; buf[1] = 0xed; buf[2] = 0xfa; buf[3] = 0xcf; }
    else { buf[0] = 0xcf; buf[1] = 0xfa; buf[2] = 0xed; buf[3] = 0xfe; }
  } else {
    buf[0] = 0xde; buf[1] = 0xad; buf[2] = 0xbe; buf[3] = 0xef;
  }
  u32(buf, 4, CPU[spec.arch]!, be);
  u32(buf, 8, 0, be);          // cpusubtype
  u32(buf, 12, 2, be);         // MH_EXECUTE
  u32(buf, 16, 3, be);         // ncmds
  u32(buf, 20, sizeofcmds, be);
  // LC_SEGMENT_64
  let c = 32;
  u32(buf, c, 0x19, be); u32(buf, c + 4, 72, be);
  buf.set([...Buffer.from("__TEXT\0")], c + 8);
  // LC_UUID
  c += 72;
  u32(buf, c, 0x1b, be); u32(buf, c + 4, 24, be);
  for (let i = 0; i < 16; i++) buf[c + 8 + i] = (i * 7 + 3) & 0xff;
  // LC_CODE_SIGNATURE
  c += 24;
  u32(buf, c, 0x1d, be);
  u32(buf, c + 4, spec.cmdOob ? sizeofcmds * 4 : 16, be); // cmdOob: cmdsize 冲出 sizeofcmds
  u32(buf, c + 8, sigOff, be);
  u32(buf, c + 12, blobLen, be);

  // 填充代码区内容（确定性伪随机）
  for (let i = headerSize; i < codeLimit; i++) buf[i] = (i * 31 + 17) & 0xff;

  // 签名 blob（一律大端）
  const sb = sigOff;
  u32(buf, sb, spec.unknownBlob ? 0xdeadbeef : 0xfade0cc0, true);
  u32(buf, sb + 4, blobLen, true);
  u32(buf, sb + 8, 1, true);
  u32(buf, sb + 12, 0, true);   // CSSLOT_CODEDIRECTORY
  u32(buf, sb + 16, 20, true);
  const cd = sb + 20;
  u32(buf, cd, 0xfade0c02, true);
  u32(buf, cd + 4, cdLen, true);
  u32(buf, cd + 8, 0x20400, true);
  u32(buf, cd + 16, 44, true);  // hashOffset（nSpecial=0）
  u32(buf, cd + 24, 0, true);   // nSpecialSlots
  u32(buf, cd + 28, nSlots, true);
  u32(buf, cd + 32, codeLimit, true);
  buf[cd + 36] = 32;            // hashSize
  buf[cd + 37] = 2;             // SHA-256
  buf[cd + 39] = 12;            // pageSize 2^12
  for (let s = 0; s < nSlots; s++) {
    const start = s * PAGE;
    const len = Math.min(PAGE, codeLimit - start);
    const h = createHash("sha256").update(buf.slice(start, start + len)).digest();
    buf.set(h, cd + 44 + s * 32);
  }

  if (spec.corruptCode) buf[codeLimit - 1]! ^= 0xff; // 翻转最后一个被覆盖字节
  return { bytes: buf, sigOff, sigSize: blobLen, codeLimit };
}

export interface FatSpec {
  slices: { spec: SliceSpec; align?: number; offsetOverride?: number; sizeOverride?: number }[];
  fatCigam?: boolean; // 容器头字段小端（FAT_CIGAM）
}

export function buildFat(spec: FatSpec): Uint8Array {
  const n = spec.slices.length;
  const headerSize = 8 + 20 * n;
  const built = spec.slices.map((s) => buildSlice(s.spec));
  const offsets: number[] = [];
  let cursor = headerSize;
  for (let i = 0; i < n; i++) {
    const align = spec.slices[i]!.align ?? 12;
    const multiple = 2 ** Math.min(align, 30);
    cursor = Math.ceil(cursor / multiple) * multiple;
    offsets.push(spec.slices[i]!.offsetOverride ?? cursor);
    cursor = Math.max(cursor, (spec.slices[i]!.offsetOverride ?? cursor) + built[i]!.bytes.length);
  }
  const total = cursor;
  const out = new Uint8Array(total);
  const be = !spec.fatCigam;
  u32(out, 0, 0xcafebabe, be);
  u32(out, 4, n, be);
  for (let i = 0; i < n; i++) {
    const base = 8 + i * 20;
    const s = spec.slices[i]!;
    u32(out, base, CPU[s.spec.arch]!, be);
    u32(out, base + 4, 0, be);
    u32(out, base + 8, offsets[i]!, be);
    u32(out, base + 12, s.sizeOverride ?? built[i]!.bytes.length, be);
    u32(out, base + 16, s.align ?? 12, be);
    out.set(built[i]!.bytes, offsets[i]!);
  }
  return out;
}

export type VariantName =
  | "baseline" | "mixed-endian" | "mut-endian" | "overlap" | "align-overflow"
  | "cmd-oob" | "sig-tail-gap" | "hash-mismatch" | "dup-arch" | "unknown-blob";

/** 反例档案的全部变体：baseline 全通过，其余每个只改动一个直接来源 */
export function buildVariant(name: VariantName): Uint8Array {
  switch (name) {
    case "baseline":
      return buildFat({ slices: [{ spec: { arch: "x86_64" } }, { spec: { arch: "arm64" } }] });
    case "mixed-endian":
      return buildFat({ slices: [{ spec: { arch: "x86_64", endian: "le" } }, { spec: { arch: "arm64", endian: "be" } }] });
    case "mut-endian":
      return buildFat({ slices: [{ spec: { arch: "x86_64" } }, { spec: { arch: "arm64", badMagic: true } }] });
    case "overlap": {
      const first = buildSlice({ arch: "x86_64" });
      return buildFat({
        slices: [
          { spec: { arch: "x86_64" } },
          { spec: { arch: "arm64" }, offsetOverride: 4096 + first.bytes.length - 0x800 },
        ],
      });
    }
    case "align-overflow":
      return buildFat({ slices: [{ spec: { arch: "x86_64" } }, { spec: { arch: "arm64" }, align: 31 }] });
    case "cmd-oob":
      return buildFat({ slices: [{ spec: { arch: "x86_64" } }, { spec: { arch: "arm64", cmdOob: true } }] });
    case "sig-tail-gap":
      return buildFat({ slices: [{ spec: { arch: "x86_64" } }, { spec: { arch: "arm64", tailGap: 96 } }] });
    case "hash-mismatch":
      return buildFat({ slices: [{ spec: { arch: "x86_64" } }, { spec: { arch: "arm64", corruptCode: true } }] });
    case "dup-arch":
      return buildFat({ slices: [{ spec: { arch: "arm64" } }, { spec: { arch: "arm64", endian: "be" } }] });
    case "unknown-blob":
      return buildFat({ slices: [{ spec: { arch: "x86_64" } }, { spec: { arch: "arm64", unknownBlob: true } }] });
  }
}
