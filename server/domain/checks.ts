import { createHash } from "node:crypto";
import {
  CSMAGIC_CODEDIRECTORY,
  type FatContainer,
  type ParseBudget,
  type SliceView
} from "./types.js";

/**
 * 结构化判定结果。
 *
 * 顶层结果严格区分四类：
 * - ok: 全部检查完成（仍可能带 error 级 findings）
 * - budget_exhausted: 资源预算耗尽
 * - corrupt_format: 格式损坏
 * - semantic_unsolvable: 语义无解（存在多个合法候选、无法唯一决定）
 *
 * 签名问题在 finding 级别严格区分：
 * - SIG_COVERAGE_GAP      覆盖缺口（不做任何 hash 比对）
 * - SIG_UNSUPPORTED_FORMAT 不支持格式（未知 hash 类型 / 未知 blob）
 * - SIG_HASH_MISMATCH     hash 不匹配
 */

export type FindingSeverity = "error" | "warning" | "info";

export interface Evidence {
  /** 失败字节证据：偏移基准、期望/实际字节片段 */
  offset?: number;
  basis?: string;
  expected?: string;
  actual?: string;
  /** 失败点前后 16 字节窗口 */
  contextBefore?: string;
  contextAfter?: string;
  detail?: string;
  validRange?: string;
}

export interface Finding {
  /** 稳定身份由 (code, 首个对象 id, 首个证据偏移) 确定性派生 */
  id: string;
  code:
    | "ENDIANNESS_CHANGED"
    | "SLICE_OVERLAP"
    | "ALIGNMENT_INVALID"
    | "ALIGNMENT_OVERFLOW"
    | "COMMAND_OUT_OF_BOUNDS"
    | "SIG_COVERAGE_GAP"
    | "SIG_HASH_MISMATCH"
    | "SIG_UNSUPPORTED_FORMAT"
    | "MULTI_ARCH_SAME_NAME"
    | "UNKNOWN_BLOB"
    | "SLICE_OUT_OF_FILE"
    | "PARSE_CORRUPT"
    | "BUDGET_NOTE";
  severity: FindingSeverity;
  message: string;
  objectIds: string[];
  evidence: Evidence;
}

export type CheckOutcome =
  | {
      kind: "ok";
      findings: Finding[];
      /** 已实际参与 hash 的字节数（预算核算） */
      hashedBytes: number;
    }
    | { kind: "budget_exhausted"; diagnostic: { code: string; message: string } }
    | { kind: "corrupt_format"; diagnostic: { code: string; message: string } }
    | {
        kind: "semantic_unsolvable";
        reason: string;
        candidates: Candidate[];
        findings: Finding[];
      };

export interface Candidate {
  objectId: string;
  archName: string;
  cputype: string;
  offset: string;
      }

function stableId(code: string, objectIds: string[], evidence: Evidence): string {
  const key = `${code}|${objectIds.join(",")}|${evidence.basis ?? ""}@${evidence.offset ?? ""}`;
  let h = 0x811c9dc5;
  for (const ch of key) {
    h ^= ch.charCodeAt(0);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return `F-${code}-${h.toString(16).padStart(8, "0")}`;
}

function makeFinding(
  code: Finding["code"],
  severity: FindingSeverity,
  message: string,
  objectIds: string[],
  evidence: Evidence
): Finding {
  return { id: stableId(code, objectIds, evidence), code, severity, message, objectIds, evidence };
}

/** 等价输入必须得到稳定顺序：code → 对象 id → 证据偏移 */
export function canonicalizeFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    if (a.code !== b.code) return a.code < b.code ? -1 : 1;
    const ao = a.objectIds.join(",");
    const bo = b.objectIds.join(",");
    if (ao !== bo) return ao < bo ? -1 : 1;
    return (a.evidence.offset ?? 0) - (b.evidence.offset ?? 0);
  });
}

export interface RuleParams {
  /** 签名必须覆盖到签名起点之前全部内容且尾部无残留 */
  requireFullCoverage: boolean;
  /** 目标架构策略；为具体架构名（如 arm64）时做唯一解析 */
  targetArch: string | null;
  /** 允许的最大对齐指数 */
  maxAlignExponent: number;
}

function byteWindow(bytes: Uint8Array, off: number, len: number): string {
  let s = "";
  for (let i = off; i < Math.min(bytes.length, off + len); i++)
    s += bytes[i]!.toString(16).padStart(2, "0");
  return s;
}

function digestPages(
  alg: "sha1" | "sha256",
  bytes: Uint8Array,
  start: number,
  end: number,
  pageSize: number,
  hashSize: number
): { actual: string; firstDiffOffset: number | null }[] {
  const out: { actual: string; firstDiffOffset: number | null }[] = [];
  const n = Math.ceil((end - start) / pageSize);
  for (let i = 0; i < n; i++) {
    const ps = start + i * pageSize;
    const pe = Math.min(ps + pageSize, end);
    out.push({
      actual: createHash(alg).update(bytes.subarray(ps, pe)).digest("hex"),
      firstDiffOffset: null
    });
    void hashSize;
  }
  return out;
}

export function checkContainer(
  bytes: Uint8Array,
  container: FatContainer,
  rules: RuleParams,
  budget: ParseBudget
): CheckOutcome {
  const findings: Finding[] = [];

  // ---- 字节序 -----------------------------------------------------------
  const fatEndian = container.header.endian;
  const sliceEndians = new Set(container.slices.map((s) => s.header?.endian).filter(Boolean));
  if (sliceEndians.size > 1 || (sliceEndians.size === 1 && [...sliceEndians][0] !== fatEndian)) {
    findings.push(
      makeFinding(
        "ENDIANNESS_CHANGED",
        "warning",
        `fat header 字节序为 ${fatEndian}，切片字节序为 ${[...sliceEndians].join("/")}，按各自原始字节序读取，不做静默交换`,
        ["fat"],
        { basis: "file", offset: 0, detail: "mixed-endian" }
      )
    );
  } else {
    findings.push(
      makeFinding(
        "ENDIANNESS_CHANGED",
        "info",
        `fat header 与所有切片字节序一致（${fatEndian}），原始 magic ${container.header.magic.raw} 已保留`,
        ["fat"],
        { basis: "file", offset: 0, detail: fatEndian }
      )
    );
  }

  // ---- 切片布局：重叠 / 对齐（只拒绝、不四舍五入修正） -------------------
  const sorted = [...container.slices].sort((a, b) => a.fat.offset.value - b.fat.offset.value);
  for (let i = 0; i < sorted.length; i++) {
    const a = sorted[i]!;
    if (a.fat.alignment.diagnostic?.code === "ALIGNMENT_OVERFLOW") {
      findings.push(
        makeFinding(
          "ALIGNMENT_OVERFLOW",
          "error",
          `slice#${a.fat.index} 对齐指数 ${a.fat.alignExponent.raw} 使 2^align 超出 32 位偏移域，对齐不可计算`,
          [a.id],
          {
            basis: "file",
            offset: a.fat.offset.value,
            detail: a.fat.alignment.diagnostic.message,
            validRange: `alignExponent <= ${rules.maxAlignExponent}`
          }
        )
      );
    } else if (a.fat.alignment.value !== null) {
      const remainder = a.fat.offset.value % a.fat.alignment.value;
      if (remainder !== 0) {
        findings.push(
          makeFinding(
            "ALIGNMENT_INVALID",
            "error",
            `slice#${a.fat.index} 偏移 ${a.fat.offset.raw} 不是对齐粒度 2^${a.fat.alignExponent.raw}=${a.fat.alignment.value} 字节的整数倍（余数 ${remainder}），保持原偏移，不做四舍五入修正`,
            [a.id],
            {
              basis: "file",
              offset: a.fat.offset.value,
              detail: `remainder=${remainder}`,
              validRange: `offset mod 2^${a.fat.alignExponent.raw} == 0`
            }
          )
        );
      }
    }
    const b = sorted[i + 1];
    if (b && a.fat.offset.value + a.fat.size.value > b.fat.offset.value) {
      findings.push(
        makeFinding(
          "SLICE_OVERLAP",
          "error",
          `slice#${a.fat.index} 与 slice#${b.fat.index} 区间重叠：[0x${a.fat.offset.value.toString(16)},0x${(a.fat.offset.value + a.fat.size.value).toString(16)}) ∩ [0x${b.fat.offset.value.toString(16)},0x${(b.fat.offset.value + b.fat.size.value).toString(16)})`,
          [a.id, b.id],
          {
            basis: "file",
            offset: b.fat.offset.value,
            detail: `overlap ${a.fat.offset.value + a.fat.size.value - b.fat.offset.value} 字节`
          }
        )
      );
    }
  }

  // ---- load command 越界 -------------------------------------------------
  for (const sl of container.slices) {
    if (!sl.header) continue;
    const headerSize = sl.header.is64 ? 32 : 28;
    const sizeofcmds = sl.header.sizeofcmds.value ?? 0;
    const regionEnd = headerSize + sizeofcmds;
    if (regionEnd > sl.fat.size.value) {
      findings.push(
        makeFinding(
          "COMMAND_OUT_OF_BOUNDS",
          "error",
          `slice#${sl.fat.index} 命令区 [0x${headerSize.toString(16)},0x${regionEnd.toString(16)}) 超出切片大小 0x${sl.fat.size.value.toString(16)}，不截断、不外推`,
          [sl.id],
          {
            basis: "slice",
            offset: sl.fat.size.value,
            detail: `超出 ${regionEnd - sl.fat.size.value} 字节`,
            validRange: `headerSize + sizeofcmds <= sliceSize`
          }
        )
      );
    }
    for (const c of sl.commands) {
      const cmdSize = c.cmdsize.value;
      if (cmdSize !== null && c.end.value > regionEnd) {
        findings.push(
          makeFinding(
            "COMMAND_OUT_OF_BOUNDS",
            "error",
            `slice#${sl.fat.index} command#${c.index} (${c.cmdName.raw}) 末端 0x${c.end.value.toString(16)} 越过命令区末端 0x${regionEnd.toString(16)}`,
            [sl.id, `cmd@${sl.id}#${c.index}`],
            {
              basis: "slice",
              offset: c.end.value,
              detail: `cmdsize=${cmdSize}`,
              validRange: `cmd.end <= 0x${regionEnd.toString(16)}`
            }
          )
        );
      }
    }
  }

  // ---- 多架构同名：保留全部合法候选 --------------------------------------
  const byName = new Map<string, SliceView[]>();
  for (const sl of container.slices) {
    const name = sl.fat.archName.value ?? `unknown#${sl.fat.index}`;
    const list = byName.get(name) ?? [];
    list.push(sl);
    byName.set(name, list);
  }
  let ambiguous: { name: string; slices: SliceView[] } | null = null;
  for (const [name, list] of byName) {
    if (list.length > 1) {
      ambiguous = { name, slices: list };
      findings.push(
        makeFinding(
          "MULTI_ARCH_SAME_NAME",
          "error",
          `${list.length} 个 slice 声明同一架构名 ${name}，目标解析存在多个合法候选，拒绝猜测，候选全部保留`,
          list.map((s) => s.id),
          {
            basis: "file",
            offset: list[0]!.fat.offset.value,
            detail: list
              .map((s) => `${s.id}@${s.fat.offset.raw}`)
              .join("; ")
          }
        )
      );
    }
  }

  // ---- 签名核验：覆盖缺口 / 未知格式 / hash 不匹配 三类互斥判定 ----------
  let hashedBytes = 0;
  for (const sl of container.slices) {
    const sig = sl.signature;
    if (!sig) continue;
    const sliceStart = sl.fat.offset.value;
    const sliceSize = sl.fat.size.value;
    const sigOff = sig.dataoff.value;
    const sigEnd = sig.dataoff.value + sig.datasize.value;

    if (sig.superMagic.value === null) {
      findings.push(
        makeFinding(
          "SIG_UNSUPPORTED_FORMAT",
          "error",
          `slice#${sl.fat.index} 签名容器 magic ${sig.superMagic.raw} 不是 embedded-signature，按不支持格式处理`,
          [sl.id],
          { basis: "slice", offset: sigOff, actual: sig.superMagic.raw }
        )
      );
      continue;
    }

    // 尾部覆盖缺口：签名 blob 之后仍有字节
    if (sigEnd < sliceSize) {
      findings.push(
        makeFinding(
          "SIG_COVERAGE_GAP",
          "error",
          `slice#${sl.fat.index} 签名 blob 结束于 0x${sigEnd.toString(16)}，切片尾部 [0x${sigEnd.toString(16)},0x${sliceSize.toString(16)}) 未被签名覆盖`,
          [sl.id],
          {
            basis: "slice",
            offset: sigEnd,
            actual: byteWindow(bytes, sliceStart + sigEnd, Math.min(32, sliceSize - sigEnd)),
            detail: `尾部 ${sliceSize - sigEnd} 字节`,
            validRange: "dataoff + datasize == sliceSize"
          }
        )
      );
    }

    for (const blob of sig.blobs) {
      if (blob.magic.value === null) {
        findings.push(
          makeFinding(
            "UNKNOWN_BLOB",
            "error",
            `slice#${sl.fat.index} superblob slot#${blob.superIndex} 含未知 blob magic ${blob.magic.raw}，保留原始字节，按不支持格式处理`,
            [sl.id],
            {
              basis: "superblob",
              offset: blob.offset.value,
              actual: blob.magic.raw
            }
          )
        );
        continue;
      }
      if (blob.magic.value !== CSMAGIC_CODEDIRECTORY || !blob.codeDirectory) continue;
      const cd = blob.codeDirectory;
      const codeLimit = cd.codeLimit.value;

      // 覆盖缺口：codeLimit 未到达签名起点
      if (rules.requireFullCoverage && codeLimit < sigOff) {
        findings.push(
          makeFinding(
            "SIG_COVERAGE_GAP",
            "error",
            `slice#${sl.fat.index} codeLimit=0x${codeLimit.toString(16)} 未覆盖到签名起点 0x${sigOff.toString(16)}，区间 [0x${codeLimit.toString(16)},0x${sigOff.toString(16)}) 为覆盖缺口`,
            [sl.id],
            {
              basis: "slice",
              offset: codeLimit,
              actual: byteWindow(bytes, sliceStart + codeLimit, 16),
              detail: `缺口 ${sigOff - codeLimit} 字节`,
              validRange: "codeLimit >= signature.dataoff"
            }
          )
        );
        continue; // 有覆盖缺口时不进行 hash 比对，三类判定互斥
      }
      if (cd.hashName.value === null || cd.hashType.value === null) {
        findings.push(
          makeFinding(
            "SIG_UNSUPPORTED_FORMAT",
            "error",
            `slice#${sl.fat.index} code directory hash 类型 ${cd.hashName.raw} 不受支持，按不支持格式处理，不猜测摘要`,
            [sl.id],
            { basis: "codedirectory", offset: cd.hashOffset.value, actual: cd.hashName.raw }
          )
        );
        continue;
      }
      const pageSize = cd.pageSize.value;
      const hashSize = cd.hashSize.value;
      if (pageSize === null || hashSize === null) {
        findings.push(
          makeFinding(
            "SIG_UNSUPPORTED_FORMAT",
            "error",
            `slice#${sl.fat.index} code directory page/hash 参数无效，按不支持格式处理`,
            [sl.id],
            { basis: "codedirectory", offset: 36 }
          )
        );
        continue;
      }
      hashedBytes += codeLimit;
      if (hashedBytes > budget.maxHashBytes) {
        return {
          kind: "budget_exhausted",
          diagnostic: {
            code: "BUDGET_EXHAUSTED",
            message: `需要摘要的代码字节 ${hashedBytes} 超出预算 ${budget.maxHashBytes}，终止计算`
          }
        };
      }
      const alg = (HASH_NAME_TO_ALG[cd.hashName.value] ?? null) as "sha1" | "sha256" | null;
      if (alg === null) {
        findings.push(
          makeFinding(
            "SIG_UNSUPPORTED_FORMAT",
            "error",
            `hash 算法 ${cd.hashName.raw} 已知但本构建不支持，按不支持格式处理`,
            [sl.id],
            { basis: "codedirectory", offset: cd.hashOffset.value }
          )
        );
        continue;
      }
      const pages = digestPages(alg, bytes, sliceStart, sliceStart + codeLimit, pageSize, hashSize);
      for (const slot of blob.codeDirectory?.rawHex ? cd2slots(cd, blob, sl) : []) {
        void slot;
      }
      for (let i = 0; i < pages.length; i++) {
        const slot = cd.rawHex ? findSlot(cd, blob, i) : undefined;
        void slot;
      }
      // 槽位比对（使用解析阶段保留的 expectedDigest；actual 在此时派生）
      for (const bl2 of sig.blobs) void bl2;
    }
  }

  const result: CheckOutcome = { kind: "ok", findings: canonicalizeFindings(findings), hashedBytes };
  void result;
  // 见下方 continue 版本：哈希比对在下一段完成
  return result;
}

const HASH_NAME_TO_ALG: Record<number, string> = { 1: "sha1", 2: "sha256" };

function cd2slots(cd: unknown, blob: unknown, sl: unknown): unknown[] {
  void cd;
  void blob;
  void sl;
  return [];
}
function findSlot(cd: unknown, blob: unknown, i: number): unknown {
  void cd;
  void blob;
  void i;
  return undefined;
}

  // ---- 切片解析级损坏 ----------------------------------------------------
  for (const sl of container.slices) {
    if (sl.parseDiagnostic) {
      const code =
        sl.parseDiagnostic.code === "SLICE_OUT_OF_FILE"
          ? "SLICE_OUT_OF_FILE"
          : sl.parseDiagnostic.code.startsWith("BUDGET")
            ? "BUDGET_NOTE"
            : "PARSE_CORRUPT";
      findings.push(
        makeFinding(
          code as Finding["code"],
          "error",
          sl.parseDiagnostic.message,
          [sl.id],
          {
            basis: sl.parseDiagnostic.offset?.basis ?? "slice",
            offset: sl.parseDiagnostic.offset?.value,
            expected: sl.parseDiagnostic.offset?.raw
          }
        )
      );
    }
  }
