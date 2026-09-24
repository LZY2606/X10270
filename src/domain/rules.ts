import { FatModel, SliceModel, readEvidence } from "./macho.js";
import { Evidence, Finding, Quantity, RuleOutput, RuleParams, qHex } from "./types.js";
import { sha256Hex, stableId } from "./ids.js";

export const RULE_VERSION = "rules/v1";

const ev = (
  objectId: string, bytes: Uint8Array, fileOffset: number, length: number,
  expected?: string, actual?: string,
): Evidence => ({
  objectId,
  offset: qHex(fileOffset, "byte", "file-offset"),
  length: qHex(length, "byte", "file-offset"),
  bytesHex: readEvidence(bytes, fileOffset, length),
  ...(expected !== undefined ? { expected } : {}),
  ...(actual !== undefined ? { actual } : {}),
});

export interface CoverageBand {
  id: string;
  sliceId: string;
  kind: "covered" | "gap" | "signature";
  start: Quantity; // slice-offset
  end: Quantity;
  reason: string;
}

/** 签名覆盖带：已覆盖区间 / 覆盖缺口 / 签名区本身 */
export function coverageBands(model: FatModel): CoverageBand[] {
  const bands: CoverageBand[] = [];
  for (const slice of model.slices) {
    const sig = slice.signature;
    if (!sig || sig.blobKind !== "embedded-signature" || !sig.codeDirectory) continue;
    const limit = sig.codeDirectory.codeLimit.value ?? 0;
    const dataOff = sig.dataOff.value ?? 0;
    const dataSize = sig.dataSize.value ?? 0;
    bands.push({
      id: stableId("band", slice.id, "covered", 0, limit),
      sliceId: slice.id, kind: "covered",
      start: qHex(0, "byte", "slice-offset"), end: qHex(limit, "byte", "slice-offset"),
      reason: `CodeDirectory codeLimit 覆盖 [0, 0x${limit.toString(16)})`,
    });
    if (limit < dataOff) {
      bands.push({
        id: stableId("band", slice.id, "gap", limit, dataOff),
        sliceId: slice.id, kind: "gap",
        start: qHex(limit, "byte", "slice-offset"), end: qHex(dataOff, "byte", "slice-offset"),
        reason: "签名前尾部未被任何 code slot 覆盖",
      });
    }
    bands.push({
      id: stableId("band", slice.id, "sig", dataOff, dataOff + dataSize),
      sliceId: slice.id, kind: "signature",
      start: qHex(dataOff, "byte", "slice-offset"), end: qHex(dataOff + dataSize, "byte", "slice-offset"),
      reason: "embedded signature blob",
    });
  }
  return bands;
}

/** 运行全部规则。等价输入 → 稳定顺序（规则序固定，对象按坐标/身份排序）。 */
export function runRules(model: FatModel, bytes: Uint8Array, params: RuleParams): RuleOutput {
  const findings: Finding[] = [];
  const rv = RULE_VERSION;

  // ---- 资源预算：耗尽是独立结果类别 ----
  if (bytes.length > params.budgetBytes) {
    return { resultKind: "budget-exhausted", findings: [] };
  }
  const totalCommands = model.slices.reduce((n, s) => n + s.commands.length, 0);
  if (totalCommands > params.budgetCommands) {
    return { resultKind: "budget-exhausted", findings: [] };
  }

  // ---- 1. 字节序：fat 容器与每个 slice 的字节序都必须可判定 ----
  {
    const bad = model.slices.filter((s) => s.endian === "unknown");
    const magicBad = model.magic.value === null;
    findings.push({
      ruleId: "endianness", ruleVersion: rv,
      status: bad.length === 0 && !magicBad ? "pass" : "fail",
      summary: magicBad
        ? "fat 容器 magic 未知，字节序不可判定"
        : bad.length === 0
          ? `容器 ${model.fatEndian.toUpperCase()}，slice 字节序全部可判定（${model.slices.map((s) => `${s.arch.archName}:${s.endian}`).join(", ")}）`
          : `${bad.length} 个 slice 的 Mach-O magic 未知，字节序不可判定`,
      affected: bad.map((s) => s.id),
      evidence: bad.map((s) =>
        ev(s.id, bytes, s.arch.offset.value ?? 0, 4, "cf fa ed fe | fe ed fa cf", s.magic.raw)),
    });
  }

  // ---- 2. slice 范围不得重叠 ----
  {
    const ranges = model.arches
      .map((a) => ({ a, start: a.offset.value ?? 0, end: (a.offset.value ?? 0) + (a.size.value ?? 0) }))
      .sort((x, y) => x.start - y.start || x.a.id.localeCompare(y.a.id));
    const evidence: Evidence[] = [];
    const affected: string[] = [];
    for (let i = 1; i < ranges.length; i++) {
      const prev = ranges[i - 1]!, cur = ranges[i]!;
      if (cur.start < prev.end) {
        affected.push(prev.a.id, cur.a.id);
        evidence.push(
          ev(cur.a.id, bytes, cur.start, Math.min(16, prev.end - cur.start),
            `slice 起点 >= 0x${prev.end.toString(16)}`, `0x${cur.start.toString(16)}`),
        );
      }
    }
    findings.push({
      ruleId: "slice-overlap", ruleVersion: rv,
      status: evidence.length === 0 ? "pass" : "fail",
      summary: evidence.length === 0 ? "slice 范围两两不相交" : `发现 ${evidence.length} 处 slice 范围重叠`,
      affected: [...new Set(affected)], evidence,
    });
  }

  // ---- 3. 对齐：offset 必须是 2^align 的整数倍，不靠四舍五入修正；指数/范围溢出即失败 ----
  {
    const evidence: Evidence[] = [];
    const affected: string[] = [];
    for (const a of model.arches) {
      const off = a.offset.value, size = a.size.value, align = a.align.value;
      if (off === null || size === null || align === null) continue;
      if (align > 30) {
        affected.push(a.id);
        evidence.push(ev(a.id, bytes, off, 4, "align 指数 <= 30", `2^${align} 溢出 32 位寻址`));
        continue;
      }
      const multiple = 2 ** align;
      if (off % multiple !== 0) {
        affected.push(a.id);
        evidence.push(ev(a.id, bytes, off, 4,
          `offset 为 2^${align} (0x${multiple.toString(16)}) 的整数倍`,
          `0x${off.toString(16)} 未对齐；禁止四舍五入修正`));
      }
      if (off + size > model.fileLength) {
        affected.push(a.id);
        evidence.push(ev(a.id, bytes, model.fileLength > 8 ? model.fileLength - 8 : 0, 8,
          `offset+size <= 文件长度 0x${model.fileLength.toString(16)}`,
          `0x${(off + size).toString(16)} 越界`));
      }
    }
    findings.push({
      ruleId: "slice-alignment", ruleVersion: rv,
      status: evidence.length === 0 ? "pass" : "fail",
      summary: evidence.length === 0
        ? "所有 slice 偏移满足 2^align 对齐且在文件范围内"
        : `${affected.length} 个 slice 对齐/范围越界（不做舍入修正）`,
      affected: [...new Set(affected)], evidence,
    });
  }

  // ---- 4. load command 不越界 ----
  {
    const evidence: Evidence[] = [];
    const affected: string[] = [];
    for (const s of model.slices) {
      const sizeofcmds = s.sizeofcmds.value ?? 0;
      const sliceBase = s.arch.offset.value ?? 0;
      const sliceSize = s.arch.size.value ?? 0;
      let cursor = 32;
      for (const c of s.commands) {
        const size = c.cmdSize.value ?? 0;
        const declaredEnd = 32 + sizeofcmds;
        if (size < 8 || cursor + size > declaredEnd || cursor + size > sliceSize) {
          affected.push(c.id);
          evidence.push(ev(c.id, bytes, sliceBase + cursor, 8,
            `command 完全落在 [32, ${declaredEnd}) 且不超出 slice`,
            `cmdsize=${size} 于 slice-offset ${cursor}`));
        }
        cursor += Math.max(size, 8);
      }
      const walkedEnd = s.commands.length > 0 ? cursor : 32;
      if (s.commands.length > 0 && walkedEnd !== declaredEnd) {
        affected.push(s.id);
        evidence.push(ev(s.id, bytes, sliceBase + Math.min(walkedEnd, sliceSize > 8 ? sliceSize - 8 : 0), 8,
          `命令流恰好结束于 sizeofcmds=${declaredEnd}`, `实际结束于 ${walkedEnd}`));
      }
    }
    findings.push({
      ruleId: "cmd-bounds", ruleVersion: rv,
      status: evidence.length === 0 ? "pass" : "fail",
      summary: evidence.length === 0 ? "load command 全部位于声明范围内" : `发现 ${evidence.length} 处 load command 越界`,
      affected: [...new Set(affected)], evidence,
    });
  }

  // ---- 5/6/7. 签名：未知 blob（不支持格式） / 覆盖缺口 / hash 不匹配，三者明确区分 ----
  for (const s of model.slices) {
    const sig = s.signature;
    if (!sig) continue;
    const sliceBase = s.arch.offset.value ?? 0;

    if (sig.blobKind === "unknown") {
      findings.push({
        ruleId: "sig-unknown-blob", ruleVersion: rv, status: "undecidable",
        summary: `slice ${s.arch.archName} 签名 blob magic ${sig.blobMagic.raw} 不属于已支持格式，无法验证`,
        affected: [sig.id],
        evidence: [ev(sig.id, bytes, sliceBase + (sig.dataOff.value ?? 0), 4,
          "fade0cc0 (embedded signature)", sig.blobMagic.raw)],
      });
      continue;
    }

    const cd = sig.codeDirectory;
    if (!cd) continue;
    const codeLimit = cd.codeLimit.value ?? 0;
    const dataOff = sig.dataOff.value ?? 0;

    // 覆盖缺口：签名前的尾部未被 code slot 覆盖
    const gap = dataOff - codeLimit;
    findings.push({
      ruleId: "sig-coverage-gap", ruleVersion: rv,
      status: gap <= 0 || params.allowSignatureTailGap ? "pass" : "fail",
      summary: gap <= 0
        ? `slice ${s.arch.archName} 签名前无未覆盖字节`
        : `slice ${s.arch.archName} 签名前存在 0x${gap.toString(16)} 字节未覆盖尾部`,
      affected: gap <= 0 ? [] : [sig.id],
      evidence: gap <= 0 ? [] : [ev(sig.id, bytes, sliceBase + codeLimit, Math.min(gap, 16),
        "codeLimit 覆盖至签名起点", `缺口 [0x${codeLimit.toString(16)}, 0x${dataOff.toString(16)})`)],
    });

    // hash 不匹配：逐 code slot 重算 sha256
    const pageSize = 2 ** cd.pageSizeExp;
    const mismatches: Evidence[] = [];
    for (const slot of cd.slots) {
      if (slot.kind !== "code") continue;
      const start = slot.index * pageSize;
      const len = Math.min(pageSize, codeLimit - start);
      if (len <= 0 || sliceBase + start + len > bytes.length) continue;
      const actual = sha256Hex(bytes.slice(sliceBase + start, sliceBase + start + len));
      if (actual !== slot.hashHex) {
        mismatches.push(ev(cd.id, bytes, sliceBase + start, Math.min(len, 16), slot.hashHex, actual));
      }
    }
    findings.push({
      ruleId: "sig-hash-match", ruleVersion: rv,
      status: mismatches.length === 0 ? "pass" : "fail",
      summary: mismatches.length === 0
        ? `slice ${s.arch.archName} ${cd.nCodeSlots} 个 code slot 摘要全部匹配`
        : `slice ${s.arch.archName} ${mismatches.length} 个 code slot 摘要不匹配`,
      affected: mismatches.length === 0 ? [] : [cd.id],
      evidence: mismatches,
    });
  }

  // ---- 8. 多架构同名：无法唯一决定时保留全部合法候选 ----
  {
    const byName = new Map<string, SliceModel[]>();
    for (const s of model.slices) {
      const list = byName.get(s.arch.archName) ?? [];
      list.push(s);
      byName.set(s.arch.archName, list);
    }
    for (const [name, list] of [...byName.entries()].sort(([a], [b]) => a.localeCompare(b))) {
      if (list.length < 2) continue;
      findings.push({
        ruleId: "dup-arch", ruleVersion: rv, status: "undecidable",
        summary: `架构名 "${name}" 对应 ${list.length} 个 slice，目标架构策略无法唯一决定`,
        affected: list.map((s) => s.id),
        evidence: list.map((s) => ev(s.id, bytes, s.arch.offset.value ?? 0, 4)),
        candidates: list.map((s) => ({
          id: s.id,
          description: `${name} @ file-offset 0x${(s.arch.offset.value ?? 0).toString(16)}`,
          basis: { material: s.id, rule: rv },
        })),
      });
    }
  }

  // ---- 结果类别：预算耗尽 / 格式损坏 / 语义无解 必须区分 ----
  const hasCorrupt = model.diagnostics.some((d) => d.kind === "format-corrupt");
  const hasUnsolvable = findings.some((f) => f.status === "undecidable");
  const resultKind = hasCorrupt ? "format-corrupt" : hasUnsolvable ? "semantic-unsolvable" : "ok";
  return { resultKind, findings };
}
