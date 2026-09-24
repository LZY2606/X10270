// Offline case pack generator:
//   node --experimental-strip-types tools/build-case.ts
//
// Produces deterministic fat images (baseline + single-source counterexamples)
// under cases/images/*.hex and a machine-readable, replayable scenario script
// under cases/sessions/*.json. The scenario is exactly the event stream the
// service replays on first boot.

import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildFat, buildThinSlice, arm64Spec, x86Spec, type FatLayoutEntry, type SliceSpec } from '../src/shared/build';
import { fromHex, toHex } from '../src/shared/binio';
import { sha256Hex } from '../src/shared/sha256';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const imageDir = join(root, 'cases', 'images');
const sessionDir = join(root, 'cases', 'sessions');
mkdirSync(imageDir, { recursive: true });
mkdirSync(sessionDir, { recursive: true });

const PAGE = 0x4000;

interface Variant {
  key: string;
  title: string;
  directSource: string;
  expected: string[];
  budget?: number;
  build: () => { bytes: Uint8Array; note: string };
}

function fatFromSlices(
  slices: { spec: SliceSpec }[],
  overrides: Record<number, FatLayoutEntry['overrides']> = {},
): Uint8Array {
  const built = slices.map((s) => buildThinSlice(s.spec));
  const entries: FatLayoutEntry[] = built.map((thin, i) => ({
    cpuType: slices[i].spec.cpuType,
    cpuSubtype: slices[i].spec.cpuSubtype,
    offset: 0,
    size: thin.bytes.length,
    alignShift: slices[i].spec.alignShift,
    bytes: thin.bytes,
    overrides: overrides[i],
  }));
  return buildFat(entries);
}

function tamperFirstPageCode(bytes: Uint8Array, at = 0x100): Uint8Array {
  const out = bytes.slice();
  out[at] ^= 0xff;
  return out;
}

const arm = arm64Spec();
const x86 = x86Spec();

const baseline = buildThinSlice(arm);
const baselineX86 = buildThinSlice(x86);

export const VARIANTS: Variant[] = [
  {
    key: 'baseline',
    title: '基线：fat header / slice 偏移对齐 / 字节序 / load command / 签名 blob / code slot / 原始摘要全部保留',
    directSource: 'cases/images/baseline.hex（确定性构建，无篡改）',
    expected: ['accepted_clean'],
    build: () => ({
      bytes: fatFromSlices([{ spec: arm }, { spec: x86 }]),
      note: '双架构 fat：arm64@0x4000 与 x86_64@2^14 对齐，签名 SHA-256 一致',
    }),
  },
  {
    key: 'endian_swap',
    title: '反例：fat_arch[0] 字段以小端编码（fat header 仍是大端）',
    directSource: '只改 fat_arch[0] 的写字节序（LE），slice 字节不动',
    expected: ['FAT_BYTE_ORDER_SWAP'],
    build: () => ({
      bytes: fatFromSlices([{ spec: arm }, { spec: x86 }], { 0: { littleEndianEntry: true } }),
      note: '影响应仅在 fat_arch[0] 的解释；slice 内部材料不变',
    }),
  },
  {
    key: 'slice_overlap',
    title: '反例：两个 slice 的 FAT_BYTE 区间重叠',
    directSource: '只把 x86_64 fat_arch.offset 前移到 arm64 区间内',
    expected: ['SLICE_OVERLAP', 'SLICE_OUT_OF_BOUNDS'],
    build: () => {
      const armSize = baseline.bytes.length;
      const overlapOffset = PAGE + 0x200;
      return {
        bytes: fatFromSlices(
          [
            { spec: arm },
            { spec: { ...x86 } },
          ],
          { 1: { offset: overlapOffset } },
        ),
        note: `arm64=[0x4000,0x${(PAGE + armSize).toString(16)}), x86_64 raw offset=0x${overlapOffset.toString(16)}`,
      };
    },
  },
  {
    key: 'align_overflow',
    title: '反例：align 移位超过域上限 2^30，且 offset 非对齐（不四舍五入修正）',
    directSource: '只改 arm64 fat_arch.align=0x40 并把 raw offset 偏移 4 字节',
    expected: ['SLICE_ALIGN_SHIFT_OVERFLOW', 'SLICE_MISALIGNED'],
    build: () => {
      const bytes = fatFromSlices(
        [{ spec: arm }, { spec: x86 }],
        {
          0: { alignShift: 0x40, offset: PAGE + 4 },
        },
      );
      return { bytes, note: 'align=64 -> 2^64 无法表达；offset=0x4004 不做取整修复' };
    },
  },
  {
    key: 'lc_out_of_bounds',
    title: '反例：arm64 首个 load command cmdsize 越界',
    directSource: '只改 arm64 slice 内 LC[0].cmdsize=0xffff（slice-local 改动）',
    expected: ['LC_OUT_OF_BOUNDS'],
    build: () => {
      const bytes = fatFromSlices([{ spec: arm }, { spec: x86 }]);
      const fatArmOffset = PAGE;
      bytes[fatArmOffset + 32 + 4] = 0xff;
      bytes[fatArmOffset + 32 + 5] = 0xff;
      return { bytes, note: 'LC[0] @SLICE_BYTE 32，cmdsize 低 16 位置为 0xffff' };
    },
  },
  {
    key: 'sig_tail_uncovered',
    title: '反例：签名 blob 之前留下 0x100 字节未覆盖尾部',
    directSource: '只把 arm64 的 tailGap 设为 0x100（签名起点后移，codeLimit 不变）',
    expected: ['SIGNATURE_TAIL_UNCOVERED'],
    build: () => ({
      bytes: fatFromSlices([{ spec: arm64Spec(0x100) }, { spec: x86 }]),
      note: 'code slot 只哈希 [0,0x4000)，签名 blob 位于 0x4100',
    }),
  },
  {
    key: 'multi_arch_same_name',
    title: '反例：fat 中出现两个 arm64 同名架构',
    directSource: '只把第二 slice 的 cputype/cpusubtype 改成 arm64（x86_64 字节体保留）',
    expected: ['MULTI_ARCH_SAME_NAME'],
    build: () => ({
      bytes: fatFromSlices([{ spec: arm }, { spec: x86 }], { 1: { cpuType: 0x0100000c } }),
      note: '两个合法 arm64 候选都保留，等待人工决定',
    }),
  },
  {
    key: 'unknown_blob',
    title: '反例：签名 SuperBlob 额外携带未知 blob 类型',
    directSource: '只让 arm64 签名多出一个 type=0x12345678 的 blob',
    expected: ['SIGNATURE_UNKNOWN_BLOB_TYPE'],
    build: () => ({
      bytes: fatFromSlices([{ spec: arm64Spec(0, true) }, { spec: x86 }]),
      note: '未知 blob 不解析为签名结论，归为 unsupported_format',
    }),
  },
  {
    key: 'hash_mismatch',
    title: '反例：arm64 第一页被篡改但 CodeDirectory 摘要保留',
    directSource: '只翻转 arm64 slice 偏移 0x100 处一个字节',
    expected: ['SIGNATURE_CODE_SLOT_HASH_MISMATCH'],
    build: () => ({ bytes: tamperFirstPageCode(fatFromSlices([{ spec: arm }, { spec: x86 }]), PAGE + 0x100), note: 'code slot 0 期望摘要与实测摘要分叉' }),
  },
];

void baseline;
void baselineX86;

// ---------------------------------------------------------------------------
// Emit deterministic image assets + the machine-readable scenario script.
// ---------------------------------------------------------------------------

interface Step {
  seqHint?: string;
  op: 'import' | 'revise_policy' | 'decision' | 'branch';
  variant?: string;
  maxObjects?: number;
  reason?: string;
  policy?: Record<string, unknown>;
  disposition?: string;
  targetVariant?: string;
  candidateArch?: string;
  candidateIndex?: number;
  branch?: string;
  parentBranch?: string;
  conflictsWith?: string;
  rationale?: string;
}

const variantCatalog: Record<
  string,
  { title: string; directSource: string; expected: string[]; asset: string; sha256: string; byteLength: number; note: string }
> = {};

for (const variant of VARIANTS) {
  const { bytes, note } = variant.build();
  const asset = `${variant.key}.hex`;
  writeFileSync(join(imageDir, asset), toHex(bytes) + '\n');
  variantCatalog[variant.key] = {
    title: variant.title,
    directSource: variant.directSource,
    expected: variant.expected,
    asset,
    sha256: sha256Hex(bytes),
    byteLength: bytes.length,
    note,
  };
}

const steps: Step[] = [
  { op: 'import', variant: 'baseline' },
  { op: 'import', variant: 'endian_swap' },
  { op: 'import', variant: 'slice_overlap' },
  { op: 'import', variant: 'align_overflow' },
  { op: 'import', variant: 'lc_out_of_bounds' },
  {
    op: 'revise_policy',
    reason: '参数修订（v2）：尾部覆盖容差设为 4096 字节，仅影响 tail-gap 派生，fat/slice 材料不变',
    policy: {
      version: 2,
      name: 'platform-target-policy',
      requiredArchKeys: ['arm64', 'x86_64'],
      forbidDuplicateArch: true,
      enforceFatEntryAlignment: true,
      tailCoverageGraceBytes: 4096,
      signatureHashAlgorithm: 'sha256',
    },
  },
  { op: 'import', variant: 'sig_tail_uncovered', reason: '局部依赖源数据改动：仅 arm64 签名起点后移 0x100' },
  { op: 'import', variant: 'multi_arch_same_name' },
  {
    op: 'decision',
    disposition: 'accept',
    targetVariant: 'multi_arch_same_name',
    candidateArch: 'arm64',
    candidateIndex: 0,
    rationale: '冲突人工决定 A：接受 fat_arch[0] 的 arm64',
  },
  { op: 'import', variant: 'unknown_blob' },
  { op: 'import', variant: 'hash_mismatch' },
];

const branchSteps: Step[] = [
  {
    op: 'branch',
    branch: 'conflict-review',
    parentBranch: 'main',
    reason: '第二分支：对同名架构给出互相冲突的人工决定，验证全部合法候选保留且不覆盖历史',
  },
  {
    op: 'decision',
    branch: 'conflict-review',
    disposition: 'accept',
    targetVariant: 'multi_arch_same_name',
    candidateArch: 'arm64',
    candidateIndex: 0,
    rationale: '决定 B：接受 fat_arch[0]',
  },
  {
    op: 'decision',
    branch: 'conflict-review',
    disposition: 'reject',
    targetVariant: 'multi_arch_same_name',
    candidateArch: 'arm64',
    candidateIndex: 0,
    conflictsWith: 'previous',
    rationale: '决定 C：拒绝同一候选，与决定 B 直接冲突；两个决定与全部候选均保留',
  },
];

const scenario = {
  schema: 'macho-slice-testimony-scenario/1',
  title: 'Mach-O 切片证言：fat slice、load command 与代码签名覆盖核验',
  session: {
    id: 'session-offline-case',
    narrative:
      '平台工程团队导入 universal Mach-O 与目标架构策略，沿 fat header -> slice 地图 -> load command -> 链接编辑信息 -> 签名覆盖带 -> 失败字节证据 的同一条证据路径完成导入、推导、复核与时间旅行。',
  },
  coordinateBasis: {
    fat: 'FAT_BYTE（自 universal 镜像起点的无符号字节偏移）',
    slice: 'SLICE_BYTE（自 thin slice 起点）',
    alignment: 'ALIGN_BITS（align 字段为移位位数，对齐=2^align 字节）',
    digest: 'SHA256_HEX（code slot 与镜像摘要）',
    page: '4096 字节页',
  },
  layering: {
    immutableMaterials: ['fat_header', 'slice', 'load_command', 'linkedit', 'signature_blob', 'code_slot', 'image_digest'],
    mutableDecisions: ['policy revision', 'reviewer accept/reject/parameter adjustment'],
  },
  variants: variantCatalog,
  mainBranch: { branch: 'main', steps },
  secondaryBranch: { branch: 'conflict-review', steps: branchSteps },
  acceptanceMatrix: {
    byteOrder: 'endian_swap -> FAT_BYTE_ORDER_SWAP（blast radius 限 fat_arch[0]）',
    sliceOverlap: 'slice_overlap -> SLICE_OVERLAP，区间不得重叠，不做合并',
    alignmentOverflow: 'align_overflow -> SLICE_ALIGN_SHIFT_OVERFLOW + SLICE_MISALIGNED，禁止四舍五入修正',
    loadCommandBounds: 'lc_out_of_bounds -> LC_OUT_OF_BOUNDS',
    signatureTail: 'sig_tail_uncovered -> SIGNATURE_TAIL_UNCOVERED（v2 容差内可消失，历史评估保留）',
    multiArchSameName: 'multi_arch_same_name -> rejected_semantic_no_solution + 全部合法候选',
    unknownBlob: 'unknown_blob -> unsupported_format',
    hashMismatch: 'hash_mismatch -> signature_hash_mismatch（区别于覆盖缺口与不支持格式）',
  },
};

writeFileSync(join(sessionDir, 'scenario.json'), JSON.stringify(scenario, null, 2) + '\n');

console.log(`generated ${VARIANTS.length} variants + scenario.json in cases/`);
