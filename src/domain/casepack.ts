/**
 * 离线案例包：Mach-O 切片证言
 * 叙事：平台工程团队导入 universal Mach-O + 目标架构策略 →
 *       核对 fat header/slice/字节序/load command/签名 blob/code slot/原始摘要 →
 *       触发七类边界组合 → 参数修订 → 局部源数据改动 → 冲突人工决定 →
 *       最终复核（fat 容器、slice 地图、command 列表、签名覆盖带、失败字节证据）。
 *
 * 每个场景只改动一个直接来源；同时保留被采纳与未采纳结果。
 */

import {
  buildBaselineFat, buildFat64, buildSlice,
  CPU_ARM64, CPU_X86_64,
} from "./fixtures.js";
import { buildRemainingScenarios } from "./casepack-rest.js";

export interface ScenarioExpectation {
  code: string;
  adopted: boolean;
  rationale: string;
}

export interface Scenario {
  id: string;
  title: string;
  phase: "baseline" | "boundary" | "revision" | "amendment" | "decision";
  /** 仅改动的直接来源描述（机器可读） */
  changedSource: string;
  bytes: Buffer;
  /** 预期判定依据（机器可读事件将在派生时再次生成；这里是案例档案的断言） */
  expectations: ScenarioExpectation[];
  /** 展示用坐标/单位提示 */
  basis: string;
}

const payloadX = Array.from(Buffer.from("x86_64 platform engineering baseline", "utf8"));
const payloadA = Array.from(Buffer.from("arm64 platform engineering baseline", "utf8"));

// 局部源数据改动：只改 arm64 slice 代码页内 1 个数据字节（命令与布局不变）
function locallyAmendedArm(): Buffer {
  const arm = buildSlice({ cputype: CPU_ARM64, cpusubtype: 0, payload: payloadA });
  const at = 32 + 72 + 16 + 5; // __TEXT 内 "arm64 platform..." 的第 6 个字节
  arm.bytes[at] = arm.bytes[at]! ^ 0x01;
  return arm.bytes;
}

export interface CasePack {
  id: string;
  title: string;
  narrative: string[];
  scenarios: Scenario[];
}

export function buildCasePack(): CasePack {
  const scenarios: Scenario[] = [];

  // 1. 基线：fat header、slice 偏移/对齐、字节序、command、签名、slot、摘要全部保留
  const baseline = buildBaselineFat();
  scenarios.push({
    id: "scn-baseline",
    title: "基线：双架构 fat64 完整核验",
    phase: "baseline",
    changedSource: "none",
    bytes: baseline.bytes,
    basis: "unit=byte, basis=container-offset, fat=fat64/BE, slices=2, align=2^12=4096",
    expectations: [
      { code: "ok", adopted: true, rationale: "两 slice 不重叠、4096 对齐、load command 不越界、签名覆盖全部代码页" },
    ],
  });

  // 2. 大小端：fat header 被字节交换（CIGAM 路径）
  const swapped = buildFat64(
    [
      { cputype: CPU_X86_64, cpusubtype: 3, sliceBytes: buildSlice({ cputype: CPU_X86_64, cpusubtype: 3, payload: payloadX }).bytes },
      { cputype: CPU_ARM64, cpusubtype: 0, sliceBytes: buildSlice({ cputype: CPU_ARM64, cpusubtype: 0, payload: payloadA }).bytes },
    ],
    { byteSwapFatHeader: true },
  );
  scenarios.push({
    id: "scn-endian-swapped",
    title: "大小端：fat header 字节交换",
    phase: "boundary",
    changedSource: "fat-header.bytes[0:4] = byteswap(FAT_MAGIC_64)",
    bytes: swapped.bytes,
    basis: "unit=byte, basis=container-offset, endian=LE(swapped)",
    expectations: [
      { code: "ENDIAN_SWAPPED", adopted: true, rationale: "命中 FAT_CIGAM_64，按小端解释描述符；原始 magic 字节保留为证据" },
      { code: "RAW_PARSE_CORRUPT", adopted: false, rationale: "字节交换不是损坏，可解释为合法候选" },
    ],
  });

  buildRemainingScenarios(scenarios);

  // 9. 参数修订：未知 blob 在 v2 策略下升为 error（材料同 scn-unknown-blob）
  const unknownScenario = scenarios.find((s) => s.id === "scn-unknown-blob")!;
  scenarios.push({
    id: "scn-param-revision",
    title: "参数修订：unknownBlobIsError false→true（策略 v2）",
    phase: "revision",
    changedSource: "policy.unknownBlobIsError := true  // 材料未改，仅参数版本变化",
    bytes: unknownScenario.bytes,
    basis: "policyVersion=2, 输入摘要与 scn-unknown-blob 相同",
    expectations: [
      { code: "UNKNOWN_BLOB", adopted: true, rationale: "同一未知 blob 在 v2 下 severity=error；v1 的 warning 结论仍可按历史事件回溯" },
    ],
  });

  // 10. 局部源数据改动：只翻转 arm64 一个数据字节 → 仅该 slice 的 code slot#0 摘要失配
  const amended = buildFat64([
    { cputype: CPU_X86_64, cpusubtype: 3, sliceBytes: buildSlice({ cputype: CPU_X86_64, cpusubtype: 3, payload: payloadX }).bytes },
    { cputype: CPU_ARM64, cpusubtype: 0, sliceBytes: locallyAmendedArm() },
  ]);
  scenarios.push({
    id: "scn-source-amendment",
    title: "局部源数据改动：arm64 代码页 1 字节翻转",
    phase: "amendment",
    changedSource: "slice#1.text[125] ^= 0x01  // 仅影响 arm64 局部依赖，x86_64 不变",
    bytes: amended.bytes,
    basis: "unit=byte, basis=slice-offset@slice#1, page#0",
    expectations: [
      { code: "SIGNATURE_HASH_MISMATCH", adopted: true, rationale: "仅 arm64 code slot#0 失配，失败字节证据给出 actual/expected 摘要；x86_64 仍 ok" },
      { code: "SIGNATURE_TAIL_GAP", adopted: false, rationale: "改动位于签名覆盖区内，不是覆盖缺口" },
    ],
  });

  // 11. 冲突人工决定：在多架构同名材料上，两次互相冲突的人工决定都存档
  const dupScenario = scenarios.find((s) => s.id === "scn-arch-duplicate")!;
  scenarios.push({
    id: "scn-conflicting-decisions",
    title: "冲突人工决定：arm64 vs arm64e（accept 两次互斥选择）",
    phase: "decision",
    changedSource: "human-decision: accept slice#0(arm64) vs accept slice#1(arm64e)",
    bytes: dupScenario.bytes,
    basis: "保留全部合法候选；两次决定在事件流中均有父依赖与参数版本",
    expectations: [
      { code: "ARCH_DUPLICATE", adopted: true, rationale: "材料层架构歧义不消除；人工决定只新增 decision 事件，不回写材料" },
    ],
  });

  return {
    id: "casepack-macho-testimony-v1",
    title: "Mach-O 切片证言：fat slice、load command 与代码签名覆盖核验",
    narrative: [
      "平台工程团队导入 universal Mach-O 与目标架构策略，在一次会话内完成导入、推导与复核。",
      "初始核对 fat header、slice 偏移/对齐、字节序、load command 范围、签名 blob、code slot 与原始摘要。",
      "随后逐个触发七类边界组合，每类只改动一个直接来源。",
      "参数修订提升未知 blob 的严重性；局部源数据改动只影响 arm64 slice；冲突人工决定保留全部合法候选。",
    ],
    scenarios,
  };
}
