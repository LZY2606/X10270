/**
 * 确定性 universal Mach-O 夹具构造器（离线案例包专用，不依赖系统文件）。
 * 生成的基线文件满足全部规则：slice 不重叠、对齐真实满足、LC 不越界、
 * 签名覆盖全部被签名字节、code slot 摘要与内容一致。
 *
 * 布局（小端 Mach-O，规范 big-endian fat）：
 *   fat header(8) + fat_arch[n](20n)
 *   slice0(arm64): mach_header_64 + LC_SEGMENT_64(__TEXT) + LC_SEGMENT_64(__LINKEDIT)
 *                  + LC_CODE_SIGNATURE + SuperBlob(CodeDirectory + hashes)
 *   slice1(x86_64): 同构
 * 对齐：slice offset 真实为 2^align 的倍数（不做四舍五入）。
 */
import { sha256 } from './hash.js';
import { CS, LC, MAGIC, SEG_LINKEDIT, SEG_TEXT } from './constants.js';
import type { Endian } from './types.js';

export interface SliceSpec {
  cputype: number;
  cpusubtype: number;
  /** 每片正文的字节内容（决定 code slot 摘要） */
  payload: Uint8Array;
  /** 覆盖尾部缺口：把 codeLimit 人为缩小这么多字节（基线为 0） */
  codeLimitShrink?: number;
}

export interface BuildSpec {
  fatEndian: Endian;        // 规范为 be
  slices: SliceSpec[];
  /** 额外追加到文件末尾但不在任何 slice.size 中的“未覆盖尾部”由签名测试用 */
  extraSlices?: SliceSpec[];
}

class Writer {
  private bytes: number[] = [];
  u8(v: number): void { this.bytes.push(v & 0xff); }
  u32(v: number, e: Endian): void {
    const b = [v & 255, (v >>> 8) & 255, (v >>> 16) & 255, (v >>> 24) & 255];
    (e === 'le' ? b : b.reverse()).forEach((x) => this.u8(x));
  }
  raw(u8arr: Uint8Array): void { for (const b of u8arr) this.u8(b); }
  padTo(off: number, fill = 0): void { while (this.bytes.length < off) this.u8(fill); }
  get length(): number { return this.bytes.length; }
  build(): Uint8Array { return Uint8Array.from(this.bytes); }
  patchU32(off: number, v: number, e: Endian): void {
    const b = [v & 255, (v >>> 8) & 255, (v >>> 16) & 255, (v >>> 24) & 255];
    const out = e === 'le' ? b : b.reverse();
    for (let i = 0; i < 4; i++) this.bytes[off + i] = out[i];
  }
}

const PAGE = 4096;

function buildMachSlice(spec: SliceSpec): { bytes: Uint8Array; sigOff: number; sigSize: number } {
  const w = new Writer();
  const le: Endian = 'le';
  const payload = spec.payload;
  const nCodeSlots = Math.ceil(payload.length / PAGE) || 1;
  // ---- 先计算 code slot 摘要（页式，最后一页不足补 0） ----
  const slotHashes: string[] = [];
  for (let i = 0; i < nCodeSlots; i++) {
    const page = new Uint8Array(PAGE);
    page.set(payload.subarray(i * PAGE, Math.min((i + 1) * PAGE, payload.length)));
    slotHashes.push(sha256(page));
  }
  // CodeDirectory（简化但字段齐全），长度对齐 8
  const cdBaseSize = 88;
  let cdLength = cdBaseSize + slotHashes.length * 32;
  cdLength = Math.ceil(cdLength / 8) * 8;
  const hashOffset = cdBaseSize;
  // SuperBlob: 头部 20 + 一个 CodeDirectory
  const sigBlobLen = Math.ceil((20 + 8 + cdLength) / 8) * 8;
  const cdRelOff = 20;
  const ncmds = 3;
  const sizeofcmds = 72 + 72 + 16; // 两个 segment_64 + code_signature
  const headerSize = 32;
  const sigOff = headerSize + sizeofcmds + payload.length;
  const sliceSize = sigOff + sigBlobLen;
  void sigBlobLen;
  // ---- mach_header_64 ----
  w.u32(MAGIC.MH_MAGIC_64, le);   // 0xfeedfacf 的小端存储
  w.u32(spec.cputype, le);
  w.u32(spec.cpusubtype, le);
  w.u32(0x01000002, le);          // MH_EXECUTE | MH_NOUNDEFS
  w.u32(ncmds, le);
  w.u32(sizeofcmds, le);
  w.u32(0, le); w.u32(0, le);     // reserved
  // ---- LC_SEGMENT_64 __TEXT ----
  w.u32(LC.LC_SEGMENT_64, le); w.u32(72, le);
  const name = new TextEncoder().encode(SEG_TEXT);
  w.raw(name); for (let i = name.length; i < 16; i++) w.u8(0);
  w.u32(0, le); w.u32(0, le);     // vmaddr (8)
  w.u32(payload.length, le); w.u32(0, le); // vmsize
  w.u32(0, le); w.u32(0, le);     // fileoff
  w.u32(payload.length, le); w.u32(0, le); // filesize
  w.u32(7, le); w.u32(5, le); w.u32(0, le); // maxprot initprot nsects flags
  // ---- LC_SEGMENT_64 __LINKEDIT ----
  const linkeditOff = headerSize + sizeofcmds;
  const linkeditSize = sliceSize - linkeditOff;
  w.u32(LC.LC_SEGMENT_64, le); w.u32(72, le);
  const lname = new TextEncoder().encode(SEG_LINKEDIT);
  w.raw(lname); for (let i = lname.length; i < 16; i++) w.u8(0);
  w.u32(0, le); w.u32(0, le);
  w.u32(linkeditSize, le); w.u32(0, le);
  w.u32(linkeditOff, le); w.u32(0, le);
  w.u32(linkeditSize, le); w.u32(0, le);
  w.u32(7, le); w.u32(3, le); w.u32(0, le); w.u32(0, le);
  // ---- LC_CODE_SIGNATURE ----
  w.u32(LC.LC_CODE_SIGNATURE, le); w.u32(16, le);
  w.u32(sigOff, le); w.u32(sliceSize - sigOff, le);
  if (w.length !== sigOff) throw new Error(`fixture invariant: ${w.length} != ${sigOff}`);
  w.raw(payload);
  w.padTo(sigOff);
  // ---- SuperBlob ----
  const sbStart = w.length;
  w.u32(CS.CSMAGIC_EMBEDDED_SIGNATURE, 'be');
  w.u32(sliceSize - sigOff, 'be');       // length
  w.u32(1, 'be');                        // count
  w.u32(0, 'be');                        // blob index 0 type
  w.u32(cdRelOff, 'be');                 // offset
  // ---- CodeDirectory ----
  const cdStart = w.length;
  if (cdStart - sbStart !== cdRelOff) throw new Error('cd offset invariant');
  const codeLimit = payload.length - (spec.codeLimitShrink ?? 0);
  w.u32(CS.CSMAGIC_CODEDIRECTORY, 'be');
  w.u32(cdLength, 'be');
  w.u32(0x20400, 'be');                  // version
  w.u32(0, 'be');                        // flags
  w.u32(CS.CS_HASHTYPE_SHA256, 'be');    // hashType @16
  const ident = new TextEncoder().encode('fixture.binary');
  const identOffset = 48;
  // 布局：0..44 头部基础，44=pageSize(exp 12)，其余到 identOffset
  // 字段：hashOffset @28, identOffset @24, nSpecialSlots @32, nCodeSlots @36,
  //      codeLimit @40, pageSize @44
  w.patchU32(cdStart + 24, identOffset, 'be');
  w.patchU32(cdStart + 28, hashOffset, 'be');
  w.patchU32(cdStart + 32, 0, 'be');
  w.patchU32(cdStart + 36, nCodeSlots, 'be');
  w.patchU32(cdStart + 40, codeLimit, 'be');
  w.padTo(cdStart + 44);
  w.u8(12);                              // pageSize 2^12=4096
  w.u8(0); w.u8(0); w.u8(0);             // spare
  w.padTo(cdStart + identOffset);
  w.raw(ident); w.u8(0);
  w.padTo(cdStart + hashOffset);
  for (const h of slotHashes) {
    for (let i = 0; i < h.length; i += 2) w.u8(parseInt(h.slice(i, i + 2), 16));
  }
  w.padTo(sliceSize);
  return { bytes: w.build(), sigOff, sigSize: sliceSize - sigOff };
}

export interface BuiltSlice extends SliceSpec {
  bytes: Uint8Array;
  sigOff: number;
  sigSize: number;
  offset: number;
  size: number;
  align: number;
}

export function buildFat(spec: BuildSpec): { bytes: Uint8Array; slices: BuiltSlice[] } {
  const all = [...spec.slices, ...(spec.extraSlices ?? [])];
  const builtSlices = all.map((s) => ({ ...buildMachSlice(s), ...s }));
  const fatEndian = spec.fatEndian;
  // 布局：fat 头 + 表，然后每片按 2^14=0x4000 对齐（真实整除）
  const ALIGN_EXP = 14;
  const ALIGN = 1 << ALIGN_EXP;
  let cursor = 8 + builtSlices.length * 20;
  for (const s of builtSlices) {
    cursor = Math.ceil(cursor / ALIGN) * ALIGN;
    s.offset = cursor;
    s.size = s.bytes.length;
    s.align = ALIGN_EXP;
    cursor += s.bytes.length;
  }
  const w = new Writer();
  w.u32(fatEndian === 'be' ? MAGIC.FAT_MAGIC : MAGIC.FAT_CIGAM, fatEndian);
  w.u32(builtSlices.length, fatEndian);
  for (const s of builtSlices) {
    w.u32(s.cputype, fatEndian);
    w.u32(s.cpusubtype, fatEndian);
    w.u32(s.offset, fatEndian);
    w.u32(s.size, fatEndian);
    w.u32(s.align, fatEndian);
    w.u32(0, fatEndian);
  }
  for (const s of builtSlices) {
    w.padTo(s.offset);
    w.raw(s.bytes);
  }
  return { bytes: w.build(), slices: builtSlices };
}
