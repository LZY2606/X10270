import { describe, it, expect } from "vitest";
import { buildCasePack } from "../src/domain/casepack.js";
import { parseContainer } from "../src/domain/parser.js";
import { buildSlice, buildFat64, CPU_X86_64, CPU_ARM64 } from "../src/domain/fixtures.js";
import type { ParseResult } from "../src/domain/model.js";

function codes(r: ParseResult): Set<string> {
  return new Set(r.findings.map((f) => f.code));
}

const cp = buildCasePack();
const byId = new Map(cp.scenarios.map((s) => [s.id, s]));

describe("Mach-O 切片证言：基线", () => {
  it("fat64 基线全部保留且无判定问题", () => {
    const r = parseContainer(byId.get("scn-baseline")!.bytes, { scanBudgetBytes: 1e6, unknownBlobIsError: false });
    expect(r.resultClass).toBe("ok");
    expect(r.fat?.flavor).toBe("fat64");
    expect(r.fat?.declaredEndian).toBe("big");
    expect(r.slices).toHaveLength(2);
    expect(r.slices[0]!.commands.length).toBe(2);
    expect(r.slices[0]!.signature?.slots.filter(s=>s.kind==="code").every(s=>s.match===true)).toBe(true);
    // 稳定身份
    expect(r.slices[0]!.id).toBe("slice:0");
    expect(r.slices[1]!.commands[0]!.id).toBe("slice:1:lc:0");
  });
});

describe("七类边界情形", () => {
  it("大小端：fat header 字节交换 -> ENDIAN_SWAPPED 且仍可解析", () => {
    const r = parseContainer(byId.get("scn-endian-swapped")!.bytes, { scanBudgetBytes: 1e6, unknownBlobIsError: false });
    expect(codes(r)).toContain("ENDIAN_SWAPPED");
    expect(r.fat?.declaredEndian).toBe("little");
    expect(r.fat?.rawMagic).toBe("bebafeca");
    expect(r.slices).toHaveLength(2);
  });

  it("slice 重叠 -> SLICE_OVERLAP + 拒绝对齐四舍五入", () => {
    const r = parseContainer(byId.get("scn-slice-overlap")!.bytes, { scanBudgetBytes: 1e6, unknownBlobIsError: false });
    expect(codes(r)).toContain("SLICE_OVERLAP");
    expect(codes(r)).toContain("ALIGNMENT_ROUNDING_REFUSED");
    const f = r.findings.find(f => f.code === "SLICE_OVERLAP")!;
    expect(f.affected).toEqual(expect.arrayContaining(["slice:0", "slice:1"]));
  });

  it("对齐溢出 -> ALIGNMENT_OVERFLOW（不修正）", () => {
    const r = parseContainer(byId.get("scn-alignment-overflow")!.bytes, { scanBudgetBytes: 1e6, unknownBlobIsError: false });
    expect(codes(r)).toContain("ALIGNMENT_OVERFLOW");
    expect(r.slices[0]!.descriptor.rawAlign).toBe(200);
    expect(r.slices[0]!.descriptor.alignmentBytes).toBe(Infinity);
  });

  it("command 越界 -> COMMAND_OUT_OF_BOUNDS（实体保留）", () => {
    const r = parseContainer(byId.get("scn-command-oob")!.bytes, { scanBudgetBytes: 1e6, unknownBlobIsError: false });
    expect(codes(r)).toContain("COMMAND_OUT_OF_BOUNDS");
    const bad = r.slices[1]!.commands.find(c => c.outOfBounds);
    expect(bad).toBeTruthy();
    // 哈希仍然有效：越界来自声明范围，不连累摘要
    expect(codes(r)).not.toContain("SIGNATURE_HASH_MISMATCH");
  });

  it("签名未覆盖尾部 -> SIGNATURE_TAIL_GAP，且不是覆盖缺口", () => {
    const r = parseContainer(byId.get("scn-signature-tail-gap")!.bytes, { scanBudgetBytes: 1e6, unknownBlobIsError: false });
    expect(codes(r)).toContain("SIGNATURE_TAIL_GAP");
    expect(codes(r)).not.toContain("SIGNATURE_COVERAGE_GAP");
    const band = r.slices[1]!.signature!.coverage.find(b => b.kind === "tail-gap")!;
    expect(band.range.end - band.range.start).toBe(64);
  });

  it("多架构同名 -> ARCH_DUPLICATE，保留全部候选", () => {
    const r = parseContainer(byId.get("scn-arch-duplicate")!.bytes, { scanBudgetBytes: 1e6, unknownBlobIsError: false });
    expect(codes(r)).toContain("ARCH_DUPLICATE");
    const f = r.findings.find(f => f.code === "ARCH_DUPLICATE")!;
    expect(f.affected).toEqual(["slice:0", "slice:1"]);
  });

  it("未知 blob：v1=warning，参数修订 v2=error", () => {
    const bytes = byId.get("scn-unknown-blob")!.bytes;
    const v1 = parseContainer(bytes, { scanBudgetBytes: 1e6, unknownBlobIsError: false });
    const v2 = parseContainer(bytes, { scanBudgetBytes: 1e6, unknownBlobIsError: true });
    const f1 = v1.findings.find(f => f.code === "UNKNOWN_BLOB")!;
    const f2 = v2.findings.find(f => f.code === "UNKNOWN_BLOB")!;
    expect(f1.severity).toBe("warning");
    expect(f2.severity).toBe("error");
    expect(v1.slices[1]!.signature!.blobs.some(b => !b.known)).toBe(true);
  });

  it("局部源数据改动：仅 arm64 slot#0 摘要失配，x86_64 不受影响", () => {
    const r = parseContainer(byId.get("scn-source-amendment")!.bytes, { scanBudgetBytes: 1e6, unknownBlobIsError: false });
    const mm = r.findings.filter(f => f.code === "SIGNATURE_HASH_MISMATCH");
    expect(mm).toHaveLength(1);
    expect(mm[0]!.affected).toContain("slice:1:slot:0");
    expect(mm[0]!.evidence?.expected).toBeDefined();
    expect(r.slices[0]!.signature!.slots.every(s => s.match !== false)).toBe(true);
  });
});

describe("三种不同结果：预算 / 损坏 / 语义无解", () => {
  it("资源预算耗尽 -> budget-exhausted（可恢复、安全中止）", () => {
    const r = parseContainer(byId.get("scn-baseline")!.bytes, { scanBudgetBytes: 40, unknownBlobIsError: false });
    expect(r.resultClass).toBe("budget-exhausted");
    expect(codes(r)).toContain("BUDGET_EXHAUSTED");
  });

  it("格式损坏 -> corrupt（带位置诊断）", () => {
    const r = parseContainer(Buffer.from([0, 1, 2, 3, 4, 5, 6, 7]), { scanBudgetBytes: 1e6, unknownBlobIsError: false });
    expect(r.resultClass).toBe("corrupt");
    expect(codes(r)).toContain("ENDIAN_UNKNOWN");
  });

  it("语义无解 -> semantically-unsolvable（可解析但布局冲突）", () => {
    const r = parseContainer(byId.get("scn-slice-overlap")!.bytes, { scanBudgetBytes: 1e6, unknownBlobIsError: false });
    expect(r.resultClass).toBe("semantically-unsolvable");
  });

  it("无法转换/不完整输入返回带位置诊断而非伪装成功", () => {
    const r = parseContainer(Buffer.from([0xca, 0xfe]), { scanBudgetBytes: 1e6, unknownBlobIsError: false });
    expect(r.resultClass).toBe("corrupt");
    expect(r.findings[0]!.code).toBe("RAW_PARSE_CORRUPT");
  });
});

describe("等价输入稳定顺序", () => {
  it("相同输入两次解析，finding/slice/band id 与顺序完全一致", () => {
    const b = byId.get("scn-baseline")!.bytes;
    const a = parseContainer(b, { scanBudgetBytes: 1e6, unknownBlobIsError: false });
    const c = parseContainer(Buffer.from(b), { scanBudgetBytes: 1e6, unknownBlobIsError: false });
    expect(JSON.stringify(a)).toBe(JSON.stringify(c));
  });
});
