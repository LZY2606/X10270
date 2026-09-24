// 确定性合成案例：不使用通用表格，而是真实拼装 fat header / fat_arch / Mach-O /
// LC_CODE_SIGNATURE / SuperBlob / CodeDirectory / code slot 字节序列。
import { createHash } from 'node:crypto';
import {
  FAT_MAGIC, MH_MAGIC, MH_CIGAM, LC_SEGMENT, LC_CODE_SIGNATURE,
  CSMAGIC_EMBEDDED_SIGNATURE, CSMAGIC_CODEDIRECTORY,
} from './macho.js';

function u32beAt(b: Uint8Array, p: number, v: number) {
  b[p] = (v >>> 24) & 0xff; b[p + 1] = (v >>> 16) & 0xff;
  b[p + 2] = (v >>> 8) & 0xff; b[p + 3] = v & 0xff;
}
function u32leAt(b: Uint8Array, p: number, v: number) {
  b[p] = v & 0xff; b[p + 1] = (v >>> 8) & 0xff;
  b[p + 2] = (v >>> 16) & 0xff; b[p + 3] = (v >>> 24) & 0xff;
}

export interface SliceSpec {
  cpuType: number;
  cpuSubtype: number;
  le: boolean;
  pages: number;
  pageSizeExp: number;
  tailGap?: number;      // codeLimit 与签名起点之间的未覆盖尾部字节
  corruptSlot?: number; // 篡改某个 code slot 的页面内容
  unknownBlob?: boolean;
  unknownBlobMagic?: number;
  cmdOverflow?: number; // 让最后一个 command 的 cmdsize 越出 sizeofcmds / slice
  sigSizeOverride?: number;
}

const X86_64 = 0x01000007;
const ARM64 = 0x0100000c;

/** 构造单个 Mach-O slice（含链接编辑签名），返回 {bytes, size}。 */
export function buildSlice(spec: SliceSpec): { bytes: Uint8Array; sigSize: number } {
  const pageSize = 2 ** spec.pageSizeExp;
  const bodyPages = spec.pages;
  const tailGap = spec.tailGap ?? 0;
  const body = new Uint8Array(bodyPages * pageSize + tailGap);
  for (let i = 0; i < bodyPages; i++) {
    for (let j = 0; j < pageSize; j++) body[i * pageSize + j] = (i * 31 + j) & 0xff;
  }

  const ncmds = 2;
  const sizeofcmds = 16 + 16;
  const headerSize = 28;
  const sigDataoff0 = headerSize + sizeofcmds + body.length;
  const codeLimit = sigDataoff0 - tailGap; // 正常时恰为签名起点；tailGap 成为覆盖缺口
  const hashType = 2; // SHA-256
  const hashSize = 32;
  const nCodeSlots = Math.ceil(codeLimit / pageSize);
  const nSpecial = 0;
  // CodeDirectory 布局：44 字节头 + hashes
  const cdHead = 44;
  const cdHashes = nCodeSlots * hashSize;
  const cdLength = cdHead + cdHashes;
  const unknownLen = spec.unknownBlob ? 16 : 0;
  const pad = (8 - (cdLength & 7)) & 7;
  // SuperBlob：12 + 8*(1|2) + cd + pad + unknown
  const nBlob = spec.unknownBlob ? 2 : 1;
  const superLen = 12 + 8 * nBlob + cdLength + pad + (spec.unknownBlob ? 16 : 0);
  const sigSize = spec.sigSizeOverride ?? superLen;

  const total = headerSize + sizeofcmds + body.length + sigSize;
  const bytes = new Uint8Array(total);
  const put = spec.le ? u32leAt : u32beAt;

  if (spec.le) u32leAt(bytes, 0, MH_MAGIC);
  else u32beAt(bytes, 0, MH_CIGAM);
  put(bytes, 4, spec.cpuType);
  put(bytes, 8, spec.cpuSubtype);
  put(bytes, 12, 0x2); // MH_EXECUTE
  put(bytes, 16, ncmds);
  put(bytes, 20, sizeofcmds);
  put(bytes, 24, 0); // flags

  // LC_SEGMENT 16B
  put(bytes, 28, LC_SEGMENT);
  put(bytes, 32, 16);
  put(bytes, 36, 0);
  put(bytes, 40, 0);
  // LC_CODE_SIGNATURE 16B：dataoff 相对 slice 起点
  const sigDataoff = sigDataoff0;
  put(bytes, 44, LC_CODE_SIGNATURE);
  put(bytes, 48, spec.cmdOverflow ? 16 + spec.cmdOverflow : 16);
  put(bytes, 52, sigDataoff);
  put(bytes, 56, sigSize);

  bytes.set(body, headerSize + sizeofcmds);
  const sigAt = sigDataoff;
  u32beAt(bytes, sigAt + 0, CSMAGIC_EMBEDDED_SIGNATURE);
  u32beAt(bytes, sigAt + 4, superLen);
  u32beAt(bytes, sigAt + 8, nBlob);
  // index 0: CodeDirectory type=0，blob 偏移 = 12 + 8*nBlob
  const cdOff = 12 + 8 * nBlob;
  u32beAt(bytes, sigAt + 12, 0);
  u32beAt(bytes, sigAt + 16, cdOff);
  const cdAt = sigAt + cdOff;
  u32beAt(bytes, cdAt + 0, CSMAGIC_CODEDIRECTORY);
  u32beAt(bytes, cdAt + 4, cdLength);
  u32beAt(bytes, cdAt + 8, 0x20400); // version
  u32beAt(bytes, cdAt + 12, 0); // flags
  u32beAt(bytes, cdAt + 16, cdHead); // hashOffset
  u32beAt(bytes, cdAt + 20, 0); // identOffset
  u32beAt(bytes, cdAt + 24, nSpecial);
  u32beAt(bytes, cdAt + 28, nCodeSlots);
  u32beAt(bytes, cdAt + 32, codeLimit);
  bytes[cdAt + 36] = hashSize;
  bytes[cdAt + 37] = hashType;
  bytes[cdAt + 38] = 0; // platform
  bytes[cdAt + 39] = spec.pageSizeExp;
  u32beAt(bytes, cdAt + 40, 0); // spare2

  if (spec.corruptSlot !== undefined) {
    bytes[spec.corruptSlot * pageSize] ^= 0x5a;
  }
  for (let s = 0; s < nCodeSlots; s++) {
    const h = createHash(hashType === 2 ? 'sha256' : 'sha256')
      .update(Buffer.from(bytes.subarray(s * pageSize,
        s * pageSize + Math.min(pageSize, codeLimit - s * pageSize))))
      .digest();
    bytes.set(h, cdAt + cdHead + s * hashSize);
  }

  if (spec.unknownBlob) {
    const ubAt = cdAt + cdLength + pad;
    u32beAt(bytes, sigAt + 20, 2); // index type Requirements=2 槽位（仍给未知 magic）
    u32beAt(bytes, sigAt + 24, ubAt - sigAt);
    u32beAt(bytes, ubAt + 0, spec.unknownBlobMagic ?? 0x00000000);
    u32beAt(bytes, ubAt + 4, 16);
  }
  return { bytes, sigSize };
}

export interface FatLayout {
  offset: number;
  alignExp: number;
}
export interface FatOptions {
  fatLE?: boolean;
  specs: SliceSpec[];
  layout?: FatLayout[];
  nfatOverride?: number;
}

/** 拼装 universal(fat) 容器。layout 可显式制造重叠/对齐溢出。 */
export function buildFat(opts: FatOptions): Uint8Array {
  const slices = opts.specs.map(buildSlice);
  const n = opts.specs.length;
  const nfat = opts.nfatOverride ?? n;
  const tableEnd = 8 + nfat * 20;
  const layout =
    opts.layout ??
    slices.map((_, i) => ({ offset: 0x4000 + i * 0x4000, alignExp: 14 }));
  let end = tableEnd;
  for (let i = 0; i < n; i++) {
    const l = layout[i];
    end = Math.max(end, l.offset + slices[i].bytes.length);
  }
  const file = new Uint8Array(end);
  const fatLE = !!opts.fatLE;
  const pu32 = fatLE ? u32leAt : u32beAt;
  const pi32 = pu32;
  pu32(file, 0, fatLE ? 0xbebafeca : FAT_MAGIC);
  pu32(file, 4, nfat);
  for (let i = 0; i < n; i++) {
    const at = 8 + i * 20;
    const spec = opts.specs[i];
    const l = layout[i];
    pi32(file, at + 0, spec.cpuType);
    pi32(file, at + 4, spec.cpuSubtype);
    pu32(file, at + 8, l.offset);
    pu32(file, at + 12, slices[i].bytes.length);
    pu32(file, at + 16, l.alignExp);
    file.set(slices[i].bytes, l.offset);
  }
  return file;
}

export interface Scenario {
  id: string;
  title: string;
  desc: string;
  bytes: Uint8Array;
  expected: string[];
}

export function listScenarios(): Scenario[] {
  return [
    {
      id: 'baseline',
      title: '基线：双架构完整签名',
      desc: 'x86_64(LE) + arm64(LE)，fat 大端；slice 不重叠、对齐、command、签名覆盖全部通过。',
      bytes: buildFat({
        specs: [
          { cpuType: X86_64, cpuSubtype: 3, le: true, pages: 2, pageSizeExp: 12 },
          { cpuType: ARM64, cpuSubtype: 0, le: true, pages: 2, pageSizeExp: 12 },
        ],
      }),
      expected: [],
    },
    {
      id: 'endian',
      title: '字节序：fat 小端 + ppc 大端 slice',
      desc: 'fat magic=FAT_CIGAM，slice 为 MH_CIGAM 大端；解析必须分别处理两处字节序。',
      bytes: buildFat({
        fatLE: true,
        specs: [
          { cpuType: 0x00000012, cpuSubtype: 0, le: false, pages: 2, pageSizeExp: 12 },
          { cpuType: X86_64, cpuSubtype: 3, le: true, pages: 2, pageSizeExp: 12 },
        ],
      }),
      expected: [],
    },
    {
      id: 'slice_overlap',
      title: '反例：slice 范围重叠',
      desc: '第二个 slice 偏移落在第一个 slice 范围内，重叠区间必须被精确定位。',
      bytes: buildFat({
        specs: [
          { cpuType: X86_64, cpuSubtype: 3, le: true, pages: 2, pageSizeExp: 12 },
          { cpuType: ARM64, cpuSubtype: 0, le: true, pages: 2, pageSizeExp: 12 },
        ],
        layout: [
          { offset: 0x4000, alignExp: 14 },
          { offset: 0x6000, alignExp: 12 },
        ],
      }),
      expected: ['slice.overlap'],
    },
    {
      id: 'align_overflow',
      title: '反例：对齐指数溢出，禁止四舍五入修正',
      desc: 'align=2^35 超出 32 位容器；规则报告溢出且不得靠取整改写偏移。',
      bytes: buildFat({
        specs: [{ cpuType: X86_64, cpuSubtype: 3, le: true, pages: 2, pageSizeExp: 12 }],
        layout: [{ offset: 0x4000, alignExp: 35 }],
      }),
      expected: ['slice.alignment_overflow'],
    },
    {
      id: 'command_oob',
      title: '反例：load command 越界',
      desc: 'LC_CODE_SIGNATURE 的 cmdsize 越过 sizeofcmds 与 slice 边界。',
      bytes: buildFat({
        specs: [
          {
            cpuType: X86_64, cpuSubtype: 3, le: true, pages: 2, pageSizeExp: 12,
            cmdOverflow: 4096,
          },
        ],
      }),
      expected: ['command.bounds'],
    },
    {
      id: 'sig_tail_gap',
      title: '反例：签名未覆盖尾部',
      desc: 'codeLimit 与签名 blob 之间留 64 B 未哈希区间（覆盖缺口，非 hash 不匹配）。',
      bytes: buildFat({
        specs: [
          { cpuType: X86_64, cpuSubtype: 3, le: true, pages: 2, pageSizeExp: 12, tailGap: 64 },
        ],
      }),
      expected: ['signature.coverage_gap'],
    },
    {
      id: 'hash_mismatch',
      title: '反例：code slot 摘要不匹配',
      desc: '篡改第 1 页内容但保留原始 slot 摘要，应定位到 slot 与字节区间。',
      bytes: buildFat({
        specs: [
          { cpuType: X86_64, cpuSubtype: 3, le: true, pages: 2, pageSizeExp: 12, corruptSlot: 1 },
        ],
      }),
      expected: ['signature.hash_mismatch'],
    },
    {
      id: 'multi_same_name',
      title: '反例：多架构同名',
      desc: '两个 x86_64 slice（subtype 3 / 8）；目标策略无法唯一决定时保留全部合法候选。',
      bytes: buildFat({
        specs: [
          { cpuType: X86_64, cpuSubtype: 3, le: true, pages: 2, pageSizeExp: 12 },
          { cpuType: X86_64, cpuSubtype: 8, le: true, pages: 2, pageSizeExp: 12 },
        ],
      }),
      expected: ['arch.ambiguous'],
    },
    {
      id: 'unknown_blob',
      title: '反例：未知签名 blob',
      desc: 'SuperBlob 索引含未知 magic 的 blob：标记不支持格式，其余 blob 继续核验。',
      bytes: buildFat({
        specs: [
          { cpuType: ARM64, cpuSubtype: 0, le: true, pages: 2, pageSizeExp: 12, unknownBlob: true },
        ],
      }),
      expected: ['signature.unknown_blob'],
    },
    {
      id: 'budget',
      title: '资源预算耗尽',
      desc: 'slice 主体超过 64 KiB 预算，结果必须区别于格式损坏与语义无解。',
      bytes: buildFat({
        specs: [{ cpuType: X86_64, cpuSubtype: 3, le: true, pages: 20, pageSizeExp: 12 }],
      }),
      expected: ['budget_exhausted'],
    },
    {
      id: 'corrupt',
      title: '格式损坏',
      desc: '截断文件，magic 不完整，必须给出带位置的诊断。',
      bytes: new Uint8Array([0xca, 0xfe, 0xba]),
      expected: ['format_corrupt'],
    },
  ];
}
