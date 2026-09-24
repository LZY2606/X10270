// Rule layer: converts parse materials + raw parse findings into a structured
// Evaluation with stable-identity findings, derived view rows and legal
// candidates.
//
// Result classification contract (three distinct failure kinds):
//   rejected_budget_exhausted  - resource budget ran out
//   rejected_format_corrupt    - malformed bytes / unparseable structure
//   rejected_semantic_no_solution - structurally parseable but rules conflict
// Signature verification further distinguishes (without collapsing them):
//   signature_coverage_gap  - signed extent does not cover the blob/tail
//   signature_hash_mismatch - a code slot digest disagrees with observed bytes
//   unsupported_format      - unknown blob type / unsupported hash algorithm

import { digestHex, shortDigest, stableId } from './identity';
import { PAGE_SIZE } from './macho';
import type {
  Candidate,
  CommandListRow,
  CoverageBand,
  Evaluation,
  EvaluationStatus,
  FatImageMaterial,
  Finding,
  FindingCode,
  RawField,
  SliceMapRow,
  TargetPolicy,
} from './types';
import type { ParseResult, RawFinding } from './parse';

export const ENGINE_VERSION = '1.0.0';

export interface EvaluateOptions {
  maxObjects?: number;
  accepted?: boolean;
}

export function defaultPolicy(): TargetPolicy {
  return {
    version: 1,
    name: 'platform-target-policy',
    requiredArchKeys: ['arm64', 'x86_64'],
    forbidDuplicateArch: true,
    enforceFatEntryAlignment: true,
    tailCoverageGraceBytes: 0,
    signatureHashAlgorithm: 'sha256',
  };
}

function makeFinding(raw: RawFinding, seq: number, imageId: string): Finding {
  const classMap: Record<RawFinding['code'], Finding['class']> = {
    FAT_BAD_MAGIC: 'unsupported_format',
    FAT_BYTE_ORDER_SWAP: 'byte_order',
    SLICE_OVERLAP: 'range',
    SLICE_ALIGN_SHIFT_OVERFLOW: 'alignment',
    SLICE_MISALIGNED: 'alignment',
    SLICE_OUT_OF_BOUNDS: 'range',
    THIN_MAGIC_BYTE_ORDER_SWAP: 'byte_order',
    LC_OUT_OF_BOUNDS: 'load_command',
    SIGNATURE_BLOB_OUT_OF_BOUNDS: 'unsupported_format',
    SIGNATURE_UNKNOWN_BLOB_TYPE: 'unsupported_format',
    BUDGET_EXHAUSTED: 'budget',
  };
  const severitySet = new Set<FindingCode>([
    'SLICE_MISALIGNED',
    'FAT_BYTE_ORDER_SWAP',
    'THIN_MAGIC_BYTE_ORDER_SWAP',
  ]);
  return {
    id: stableId('finding', [imageId, seq, raw.code, raw.subjectId]),
    code: raw.code,
    class: classMap[raw.code],
    severity: severitySet.has(raw.code as FindingCode) ? 'warning' : 'error',
    message: raw.message,
    subject: { kind: raw.subjectKind === 'image' ? 'image' : raw.subjectKind, id: raw.subjectId },
    coordinates: [{ basis: raw.at.basis, ...(raw.at.sliceKey ? { sliceKey: raw.at.sliceKey } : {}) }],
    evidence: raw.observedHex
      ? [
          {
            basis: raw.at.basis,
            ...(raw.at.sliceKey ? { sliceKey: raw.at.sliceKey } : {}),
            start: raw.at.start,
            length: raw.at.length,
            expectedHex: raw.expectedHex ?? '',
            observedHex: raw.observedHex,
          },
        ]
      : [],
    affectedObjectIds: raw.affected,
  };
}

export interface EvaluateResult {
  evaluation: Evaluation;
  sliceMap: SliceMapRow[];
  commands: CommandListRow[];
  coverage: CoverageBand[];
}

export function evaluateImage(
  parsed: ParseResult,
  policy: TargetPolicy,
  parentDepIds: string[] = [],
  options: EvaluateOptions = {},
): EvaluateResult {
  const { image } = parsed;
  const findings: Finding[] = parsed.parseFindings.map((raw, i) => makeFinding(raw, i, image.imageId));

  // --- Slice map with overlap/validity geometry ----------------------------
  const sliceMap: SliceMapRow[] = image.slices.map((slice) => {
    const overlapsWith = image.slices
      .filter((other) => {
        if (other.id === slice.id) return false;
        return slice.offset < other.offset + other.size && other.offset < slice.offset + slice.size;
      })
      .map((other) => other.archKey);
    const inBounds = image.fatHeader
      ? slice.offset >= image.fatHeader.headerBytes && slice.offset + slice.size <= image.byteLength
      : false;
    return {
      id: stableId('maprow', [image.imageId, slice.index]),
      sliceKey: slice.archKey,
      archLabel: slice.archKey,
      start: slice.offset,
      end: slice.offset + slice.size,
      size: slice.size,
      alignShift: slice.alignShift,
      validRange: inBounds && overlapsWith.length === 0,
      overlapsWith,
      coordinates: { basis: 'FAT_BYTE' as const },
    };
  });

  // --- Load command list with bounds status --------------------------------
  const commands: CommandListRow[] = image.loadCommands.map((lc) => {
    const slice = image.slices.find((s) => s.archKey === lc.sliceKey);
    const inBounds = slice ? lc.offsetInSlice + lc.cmdsize <= slice.size : false;
    return {
      id: stableId('cmdrow', [image.imageId, lc.sliceKey, lc.commandIndex]),
      sliceKey: lc.sliceKey,
      commandIndex: lc.commandIndex,
      cmdName: lc.cmdName,
      cmd: lc.cmd,
      cmdsize: lc.cmdsize,
      offsetInSlice: lc.offsetInSlice,
      inBounds,
      coordinates: { basis: 'SLICE_BYTE' as const, sliceKey: lc.sliceKey },
    };
  });

  // --- Coverage bands + signature semantic checks --------------------------
  const coverage: CoverageBand[] = [];
  for (const blob of image.signatureBlobs) {
    const slots = image.codeSlots.filter((slot) => slot.sliceKey === blob.sliceKey);
    const orderedSlots = [...slots].sort((a, b) => a.slotIndex - b.slotIndex);
    let coveredEnd = 0;
    for (const slot of orderedSlots) {
      const slotEnd = slot.codeOffset + slot.codeLength;
      coverage.push({
        id: stableId('band', [image.imageId, blob.sliceKey, 'code', slot.slotIndex]),
        sliceKey: blob.sliceKey,
        kind: slot.expectedDigest === slot.observedDigest ? 'code_hashed' : 'code_hashed',
        start: slot.codeOffset,
        end: slotEnd,
        length: slot.codeLength,
        coordinates: { basis: 'SLICE_BYTE', sliceKey: blob.sliceKey },
        valid: slot.expectedDigest === slot.observedDigest,
        note:
          slot.expectedDigest === slot.observedDigest
            ? `code slot ${slot.slotIndex} SHA-256 一致`
            : `code slot ${slot.slotIndex} SHA-256 不一致`,
      });
      coveredEnd = Math.max(coveredEnd, slotEnd);

      if (slot.expectedDigest !== slot.observedDigest && slot.expectedDigest !== null) {
        findings.push({
          id: stableId('finding', [image.imageId, findings.length, 'SIGNATURE_CODE_SLOT_HASH_MISMATCH', slot.id]),
          code: 'SIGNATURE_CODE_SLOT_HASH_MISMATCH',
          class: 'signature_hash',
          severity: 'error',
          message: `${blob.sliceKey} code slot ${slot.slotIndex} @SLICE_BYTE ${slot.codeOffset} 摘要不匹配（期望 ${shortDigest(slot.expectedDigest ?? '', 16)}… 实测 ${shortDigest(slot.observedDigest ?? '', 16)}…）`,
          subject: { kind: 'code_slot', id: slot.id },
          coordinates: [{ basis: 'SLICE_BYTE', sliceKey: blob.sliceKey }],
          evidence: [
            {
              basis: 'SLICE_BYTE',
              sliceKey: blob.sliceKey,
              start: slot.codeOffset,
              length: Math.min(PAGE_SIZE, slot.codeLength),
              expectedHex: slot.expectedDigest ?? '',
              observedHex: slot.observedDigest ?? '',
            },
          ],
          affectedObjectIds: [slot.id, blob.id],
        });
      }
    }

    // Coverage gap: bytes between the last hashed page and the signature blob.
    const grace = policy.tailCoverageGraceBytes;
    if (coveredEnd < blob.fileOffset) {
      const gap = blob.fileOffset - coveredEnd;
      if (gap > grace) {
        findings.push({
          id: stableId('finding', [image.imageId, findings.length, 'SIGNATURE_TAIL_UNCOVERED', blob.id]),
          code: 'SIGNATURE_TAIL_UNCOVERED',
          class: 'signature_coverage',
          severity: 'error',
          message: `${blob.sliceKey} 签名覆盖到 ${coveredEnd}，签名 blob 起于 ${blob.fileOffset}，尾部 ${gap} 字节未被 code slot 覆盖（容差 ${grace}）`,
          subject: { kind: 'signature_blob', id: blob.id },
          coordinates: [{ basis: 'SLICE_BYTE', sliceKey: blob.sliceKey }],
          evidence: [
            {
              basis: 'SLICE_BYTE',
              sliceKey: blob.sliceKey,
              start: coveredEnd,
              length: gap,
              expectedHex: '',
              observedHex: '',
            },
          ],
          affectedObjectIds: [blob.id],
        });
        coverage.push({
          id: stableId('band', [image.imageId, blob.sliceKey, 'gap']),
          sliceKey: blob.sliceKey,
          kind: 'tail_gap',
          start: coveredEnd,
          end: blob.fileOffset,
          length: gap,
          coordinates: { basis: 'SLICE_BYTE', sliceKey: blob.sliceKey },
          valid: false,
          note: `未覆盖尾部 ${gap} 字节`,
        });
      }
    }
    coverage.push({
      id: stableId('band', [image.imageId, blob.sliceKey, 'sig']),
      sliceKey: blob.sliceKey,
      kind: 'signature_blob',
      start: blob.fileOffset,
      end: blob.fileOffset + blob.blobSize,
      length: blob.blobSize,
      coordinates: { basis: 'SLICE_BYTE', sliceKey: blob.sliceKey },
      valid: true,
      note: `Embedded Signature SuperBlob（${blob.count} 个索引）`,
    });
  }

  // --- Multi-arch same name: identity ambiguity keeps all legal candidates -
  const archCounts = new Map<string, number>();
  for (const slice of image.slices) {
    archCounts.set(slice.archKey, (archCounts.get(slice.archKey) ?? 0) + 1);
  }
  for (const [arch, count] of archCounts) {
    if (count > 1) {
      const group = image.slices.filter((s) => s.archKey === arch);
      findings.push({
        id: stableId('finding', [image.imageId, findings.length, 'MULTI_ARCH_SAME_NAME', arch]),
        code: 'MULTI_ARCH_SAME_NAME',
        class: 'identity',
        severity: 'error',
        message: `fat 镜像中存在 ${count} 个同名架构 ${arch}（fat_arch 索引 ${group.map((s) => s.index).join(', ')}），策略 forbidDuplicateArch=${policy.forbidDuplicateArch}`,
        subject: { kind: 'image', id: image.imageId },
        coordinates: [{ basis: 'FAT_BYTE' }],
        evidence: [],
        affectedObjectIds: group.map((s) => s.id),
      });
    }
  }

  for (const required of policy.requiredArchKeys) {
    if (!image.slices.some((s) => s.archKey === required)) {
      findings.push({
        id: stableId('finding', [image.imageId, findings.length, 'POLICY_REQUIRED_ARCH_MISSING', required]),
        code: 'POLICY_REQUIRED_ARCH_MISSING',
        class: 'policy',
        severity: 'warning',
        message: `目标策略 v${policy.version} 要求架构 ${required}，镜像中缺失`,
        subject: { kind: 'policy', id: `policy:v${policy.version}` },
        coordinates: [],
        evidence: [],
        affectedObjectIds: [image.imageId],
      });
    }
  }

  // --- Status classification (priority order matters) ---------------------
  const has = (code: FindingCode) => findings.some((f) => f.code === code);
  const formatCodes: FindingCode[] = [
    'FAT_BAD_MAGIC',
    'SLICE_OUT_OF_BOUNDS',
    'SLICE_OVERLAP',
    'SLICE_ALIGN_SHIFT_OVERFLOW',
    'LC_OUT_OF_BOUNDS',
    'SIGNATURE_BLOB_OUT_OF_BOUNDS',
  ];
  let status: EvaluationStatus = 'accepted_clean';
  if (parsed.budgetExhausted || has('BUDGET_EXHAUSTED')) status = 'rejected_budget_exhausted';
  else if (formatCodes.some(has) || (has('SLICE_MISALIGNED') && policy.enforceFatEntryAlignment)) {
    status = 'rejected_format_corrupt';
  } else if (has('SIGNATURE_UNKNOWN_BLOB_TYPE')) status = 'unsupported_format';
  else if (has('SIGNATURE_CODE_SLOT_HASH_MISMATCH')) status = 'signature_hash_mismatch';
  else if (has('SIGNATURE_TAIL_UNCOVERED')) status = 'signature_coverage_gap';
  else if (has('MULTI_ARCH_SAME_NAME') && policy.forbidDuplicateArch) {
    status = 'rejected_semantic_no_solution';
  } else if (findings.some((f) => f.severity === 'error')) {
    status = 'rejected_semantic_no_solution';
  }

  // --- Legal candidates for non-unique decisions ---------------------------
  const candidates: Candidate[] = [];
  if (status === 'rejected_semantic_no_solution' && archCounts.size > 0) {
    for (const [arch, count] of archCounts) {
      if (count <= 1) continue;
      const group = image.slices.filter((s) => s.archKey === arch);
      for (const slice of group) {
        candidates.push({
          id: stableId('cand', [image.imageId, arch, slice.index]),
          resolution: `retain_${arch}_fat_arch_${slice.index}`,
          selectedSliceKeys: image.slices
            .filter((s) => s.archKey !== arch || s.id === slice.id)
            .map((s) => s.archKey + (s.id === slice.id ? '' : '')),
          rationale: `保留 fat_arch[${slice.index}]（offset=${slice.offset},size=${slice.size}）作为 ${arch} 的合法解析，拒绝其余同名条目`,
          legal: true,
          chosen: false,
        });
      }
    }
  }
  if (status === 'accepted_clean') {
    candidates.push({
      id: stableId('cand', [image.imageId, 'accept-all']),
      resolution: 'accept_all_slices',
      selectedSliceKeys: image.slices.map((s) => s.archKey),
      rationale: '所有 slice 区间不重叠、对齐合法、load command 不越界、签名覆盖且摘要一致',
      legal: true,
      chosen: false,
    });
  }
  if (candidates.length === 0) {
    candidates.push({
      id: stableId('cand', [image.imageId, 'no-legal-resolution']),
      resolution: 'no_legal_resolution',
      selectedSliceKeys: [],
      rationale: '不存在可唯一决定的合法候选',
      legal: false,
      chosen: false,
    });
  }
  candidates.sort((a, b) => a.resolution.localeCompare(b.resolution));

  const used = parsed.objectCount;
  const maxObjects = options.maxObjects ?? 4096;
  const evaluation: Evaluation = {
    id: stableId('eval', [image.imageId, `p${policy.version}`, shortDigest(digestHex(canonicalFindingInput(findings, policy)), 16)]),
    imageId: image.imageId,
    policyVersion: policy.version,
    ruleVersion: `${ENGINE_VERSION}+policy${policy.version}`,
    inputDigest: image.sha256,
    parentDepIds,
    status,
    findings,
    candidates,
    computedAt: new Date(0).toISOString(),
    engine: { name: 'macho-testimony-engine', version: ENGINE_VERSION },
    budget: { maxObjects, used, exhausted: status === 'rejected_budget_exhausted' },
  };

  return { evaluation, sliceMap, commands, coverage };
}

function canonicalFindingInput(findings: Finding[], policy: TargetPolicy): Uint8Array {
  const text = JSON.stringify({ policy, codes: findings.map((f) => f.code + '@' + f.subject.id) });
  return new TextEncoder().encode(text);
}

export function inputDigestOf(bytes: Uint8Array): string {
  return digestHex(bytes);
}

export type { RawField };
