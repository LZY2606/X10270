// 派生规则层：规范化与语义判定。导入层只保留原始表示，本层负责单位换算与核验。
// 每条判定输出结构化 Finding（稳定身份、受影响对象、坐标区间、失败证据）。
import { createHash } from 'node:crypto';
import type { ParsedFile } from './macho.js';
import type { KeyedMaterial } from './materials.js';
import type { Finding, RuleStatus } from '../shared/types.js';

export const RULE_VERSION = '1.0.0';

export interface RuleParams {
  targetArch?: string; // 目标架构策略，如 'x86_64'
  requireFullCoverage: boolean;
  strictUnknownBlob: boolean;
  expectedHashTypes: number[];
}

export const DEFAULT_PARAMS: RuleParams = {
  targetArch: 'x86_64',
  requireFullCoverage: true,
  strictUnknownBlob: true,
  expectedHashTypes: [2],
};

export interface RuleRun {
  status: RuleStatus | 'ok';
  findings: Finding[];
}

function f(
  id: string,
  rule: string,
  status: Finding['status'],
  objects: string[],
  detail: string,
  extra?: Partial<Finding>,
): Finding {
  return { id, rule, status, objects, detail, ...extra };
}

export function evaluate(
  parsed: ParsedFile,
  idByKey: Record<string, string>,
  params: RuleParams,
): RuleRun {
  const findings: Finding[] = [];
  const id = (k: string) => idByKey[k];
  const slices = parsed.slices;

  // R1 slice 范围不得重叠
  for (let a = 0; a < slices.length; a++) {
    for (let b = a + 1; b < slices.length; b++) {
      const A = slices[a];
      const B = slices[b];
      const lo = Math.max(A.offset, B.offset);
      const hi = Math.min(A.offset + A.size, B.offset + B.size);
      if (lo < hi) {
        findings.push(
          f(
            `f:slice.overlap:${A.ref}:${B.ref}`,
            'slice.overlap',
            'violation',
            [id(`slice:${A.ref}`), id(`slice:${B.ref}`)],
            `slice ${A.archName}[${A.index}] 与 ${B.archName}[${B.index}] 在文件坐标 ` +
              `[0x${lo.toString(16)}, 0x${hi.toString(16)}) 重叠 ${hi - lo} B`,
            {
              position: { offset: lo, length: hi - lo, basis: 'file' },
              evidence: { offset: lo, length: hi - lo, basis: 'file' },
            },
          ),
        );
      }
    }
  }

  // R2 对齐：指数不得溢出 32 位容器；偏移必须精确对齐，禁止四舍五入修正
  for (const s of slices) {
    if (s.alignExp >= 32) {
      findings.push(
        f(
          `f:slice.alignment_overflow:${s.ref}`,
          'slice.alignment',
          'violation',
          [id(`slice:${s.ref}`)],
          `slice[${s.index}] align=2^${s.alignExp} B 超出 32 位容器对齐能力（单位：2 的幂指数）；` +
            `不得通过四舍五入或改写偏移来修正`,
          {
            position: { offset: s.offset, length: s.size, basis: 'file' },
            evidence: { offset: 8 + s.index * 20 + 16, length: 4, basis: 'file' },
          },
        ),
      );
    } else {
      const alignment = 2 ** s.alignExp;
      const rem = s.offset % alignment;
      if (rem !== 0) {
        findings.push(
          f(
            `f:slice.misaligned:${s.ref}`,
            'slice.alignment',
            'violation',
            [id(`slice:${s.ref}`)],
            `slice[${s.index}] 偏移 0x${s.offset.toString(16)} B 不是 2^${s.alignExp} B ` +
              `(=0x${alignment.toString(16)} B) 的整数倍，余数 ${rem} B；对齐不靠四舍五入修正`,
            {
              position: { offset: s.offset, length: s.size, basis: 'file' },
              evidence: { offset: 8 + s.index * 20 + 8, length: 4, basis: 'file' },
            },
          ),
        );
      }
    }
  }

  // R3 load command 不越界：每条 command 落在 header 声明的 command 区内且在 slice 内
  for (const s of slices) {
    const cmdRegionEnd = s.offset + 28 + s.sizeofcmds;
    for (const c of s.commands) {
      const end = c.at + c.cmdsize;
      const overCmds = end > cmdRegionEnd;
      const overSlice = c.at < s.offset || end > s.offset + s.size;
      if (c.cmdsize < 8 || overCmds || overSlice) {
        findings.push(
          f(
            `f:command.bounds:${s.ref}:${c.index}`,
            'command.bounds',
            'violation',
            [id(`command:${s.ref}:${c.index}`)],
            `load_command[${s.index}][${c.index}] cmdsize=${c.cmdsize}B 越界` +
              `（command 区结束 0x${Math.min(cmdRegionEnd, s.offset + s.size).toString(16)} B，` +
              `命令结束 0x${end.toString(16)} B；基准：文件坐标）`,
          {
            position: { offset: c.at, length: c.cmdsize, basis: 'file', sliceId: s.ref },
            evidence: { offset: c.at, length: Math.min(c.cmdsize, 32), basis: 'file', sliceId: s.ref },
          },
        );
      }
    }
  }

  // R4 签名覆盖：codeLimit..签名起点 与 签名结束..slice 结束 不得有未覆盖尾部
  for (const s of slices) {
    const sig = s.signature;
    if (!sig) continue;
    const sigStart = s.offset + sig.dataoff;
    const sigEnd = sigStart + sig.datasize;
    const sliceEnd = s.offset + s.size;
    const gaps: { lo: number; hi: number; kind: string }[] = [];
    if (sig.codeLimit < sigStart) {
      gaps.push({ lo: sig.codeLimit, hi: sigStart, kind: 'blob 前未覆盖尾部' });
    }
    if (sigEnd < sliceEnd) {
      gaps.push({ lo: sigEnd, hi: sliceEnd, kind: 'blob 后未覆盖尾部' });
    }
    if (params.requireFullCoverage) {
      for (const g of gaps) {
        findings.push(
          f(
            `f:signature.coverage_gap:${s.ref}:${g.kind}`,
            'signature.coverage',
            'coverage_gap',
            [id(`superblob:${s.ref}`)],
            `${s.archName}[${s.index}] ${g.kind}：文件坐标 ` +
              `[0x${g.lo.toString(16)}, 0x${g.hi.toString(16)}) 共 ${g.hi - g.lo} B ` +
              `未被 code slot 覆盖（覆盖缺口，非摘要不匹配）`,
            {
              position: { offset: g.lo, length: g.hi - g.lo, basis: 'file', sliceId: s.ref },
              evidence: { offset: g.lo, length: Math.min(g.hi - g.lo, 32), basis: 'file', sliceId: s.ref },
            },
          ),
        );
      }
    }

    // R5 hash 核验：逐 slot 重算，明确区别于覆盖缺口
    for (const slot of sig.slots) {
      const algo = sig.hashType === 2 ? 'sha256' : null;
      if (!algo || !params.expectedHashTypes.includes(sig.hashType)) {
        findings.push(
          f(
            `f:signature.hash_unsupported:${s.ref}:${slot.index}`,
            'signature.hash',
            'unsupported_format',
            [id(`slot:${s.ref}:${slot.index}`)],
            `${s.archName}[${s.index}] slot[${slot.index}] 使用不支持的 hashType=${sig.hashType}`,
            { position: { offset: slot.pageOffset, length: slot.length, basis: 'file', sliceId: s.ref } },
          ),
        );
        continue;
      }
      const actual = createHash(algo)
        .update(Buffer.from(parsed.materials.length ? rawPage(parsed, slot.pageOffset, slot.length) : new Uint8Array()))
        .digest();
      if (!bytesEqual(actual, slot.expected)) {
        findings.push(
          f(
            `f:signature.hash_mismatch:${s.ref}:${slot.index}`,
            'signature.hash',
            'hash_mismatch',
            [id(`slot:${s.ref}:${slot.index}`), id(`superblob:${s.ref}`)],
            `${s.archName}[${s.index}] code slot[${slot.index}] 摘要不匹配：` +
              `期望 ${toHex(slot.expected.slice(0, 8))}… 实算 ${actual.subarray(0, 8).toString('hex')}… ` +
              `（页面文件坐标 0x${slot.pageOffset.toString(16)} B，${slot.length} B）`,
            {
              position: { offset: slot.pageOffset, length: slot.length, basis: 'file', sliceId: s.ref },
              evidence: { offset: slot.pageOffset, length: 32, basis: 'file', sliceId: s.ref },
            },
          ),
        );
      }
    }

    // R6 未知 blob：不支持格式，且不阻断其余 blob 核验
    for (const blob of sig.blobs) {
      if (!blob.known && params.strictUnknownBlob) {
        findings.push(
          f(
            `f:signature.unknown_blob:${s.ref}:${blob.type}`,
            'signature.blob',
            'unsupported_format',
            [id(`superblob:${s.ref}`)],
            `${s.archName}[${s.index}] SuperBlob 含未知/不支持 blob（slot_type=0x${blob.type
              .toString(16)
              .padStart(8, 'x')}，magic=0x${blob.magic.toString(16).padStart(8, '0')}），` +
              `其余 blob 的核验不受影响`,
            {
              position: { offset: blob.offset, length: blob.length, basis: 'file', sliceId: s.ref },
              evidence: { offset: blob.offset, length: Math.min(blob.length, 16), basis: 'file', sliceId: s.ref },
            },
          ),
        );
      }
    }
  }

  // R7 目标架构策略：同名歧义时保留全部合法候选（语义无解 vs 可决定）
  if (params.targetArch) {
    const matches = slices.filter((s) => s.archName === params.targetArch);
    if (matches.length === 0) {
      findings.push(
        f(
          `f:arch.unsolvable:${params.targetArch}`,
          'arch.policy',
          'violation',
          ['fat_header'],
          `目标架构策略 '${params.targetArch}' 在容器中无任何 slice 对应（语义无解，区别于格式损坏）`,
        ),
      );
    } else if (matches.length > 1) {
      const candidates = matches.map((s) => s.ref);
      findings.push(
        f(
          `f:arch.ambiguous:${params.targetArch}`,
          'arch.policy',
          'indeterminate',
          matches.map((s) => id(`slice:${s.ref}`)),
          `目标架构 '${params.targetArch}' 命中 ${matches.length} 个同名 slice，` +
            `无法唯一决定；保留全部合法候选（cpu subtype 不同）：${candidates.join(', ')}`,
          { candidates: matches.map((s) => `${s.ref}(subtype=${s.cpuSubtype})`) },
        ),
      );
    }
  }

  const status: RuleRun['status'] = findings.some((x) => x.status === 'hash_mismatch')
    ? 'hash_mismatch'
    : findings.some((x) => x.status === 'coverage_gap')
      ? 'coverage_gap'
      : findings.some((x) => x.status === 'unsupported_format')
        ? 'unsupported_format'
        : findings.some((x) => x.status === 'indeterminate')
          ? 'indeterminate'
          : findings.some((x) => x.status === 'violation')
            ? 'violation'
            : 'ok';
  return { status, findings };
}

function rawPage(parsed: ParsedFile, fileOffset: number, length: number): Uint8Array {
  const digestMat = parsed.materials.find((m) => m.kind === 'file_digest');
  return digestMat!.raw.subarray(fileOffset, fileOffset + length);
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

function toHex(b: Uint8Array): string {
  return Buffer.from(b).toString('hex');
}
