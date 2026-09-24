import { buildFat64, buildSlice, CPU_ARM64, CPU_X86_64, SUBTYPE_ARM64E } from "./fixtures.js";
import type { Scenario } from "./casepack.js";

const payloadX = Array.from(Buffer.from("x86_64 platform engineering baseline", "utf8"));
const payloadA = Array.from(Buffer.from("arm64 platform engineering baseline", "utf8"));

export function buildRemainingScenarios(scenarios: Scenario[]): void {
  const x64 = () => buildSlice({ cputype: CPU_X86_64, cpusubtype: 3, payload: payloadX });
  const arm = () => buildSlice({ cputype: CPU_ARM64, cpusubtype: 0, payload: payloadA });

  // 3. slice 重叠：第二 slice forceOffset 落在第一 slice 内部
  const s1 = x64();
  const s2 = arm();
  const overlap = buildFat64([
    { cputype: CPU_X86_64, cpusubtype: 3, sliceBytes: s1.bytes },
    { cputype: CPU_ARM64, cpusubtype: 0, sliceBytes: s2.bytes, forceOffset: 4096 + 16 },
  ]);
  scenarios.push({
    id: "scn-slice-overlap",
    title: "slice 重叠",
    phase: "boundary",
    changedSource: "fat.arch[1].offset := 4112  // 切入 slice#0 区间 [4096,4096+size)",
    bytes: overlap.bytes,
    basis: "unit=byte, basis=container-offset",
    expectations: [
      { code: "SLICE_OVERLAP", adopted: true, rationale: "两 slice 区间相交，受影响对象为 slice#0/slice#1" },
      { code: "ALIGNMENT_ROUNDING_REFUSED", adopted: true, rationale: "4112 非 4096 倍数，拒绝四舍五入到 4096 或 8192" },
    ],
  });

  // 4. 对齐溢出：align=200（2^200 溢出）
  const overflow = buildFat64([
    { cputype: CPU_X86_64, cpusubtype: 3, sliceBytes: s1.bytes, align: 200 },
    { cputype: CPU_ARM64, cpusubtype: 0, sliceBytes: s2.bytes },
  ]);
  scenarios.push({
    id: "scn-alignment-overflow",
    title: "对齐溢出",
    phase: "boundary",
    changedSource: "fat.arch[0].align := 200  // 2^200 溢出",
    bytes: overflow.bytes,
    basis: "unit=byte, basis=container-offset, rawAlign=200",
    expectations: [
      { code: "ALIGNMENT_OVERFLOW", adopted: true, rationale: "align>=32 使 2^align 溢出，保留原始字段，不做修正" },
    ],
  });

  // 5. command 越界：第三命令字节真实存在（哈希有效），cmdsize=96 声明区间越出 slice
  const armBad = buildSlice({ cputype: CPU_ARM64, cpusubtype: 0, payload: payloadA, bogusOobCommand: true });
  const cmdoob = buildFat64([
    { cputype: CPU_X86_64, cpusubtype: 3, sliceBytes: x64().bytes },
    { cputype: CPU_ARM64, cpusubtype: 0, sliceBytes: armBad.bytes },
  ]);
  scenarios.push({
    id: "scn-command-oob",
    title: "load command 越界",
    phase: "boundary",
    changedSource: "slice#1 += load_command{cmd=0x77, cmdsize=96}  // 字节在页内、声明越界",
    bytes: cmdoob.bytes,
    basis: "unit=byte, basis=slice-offset@slice#1",
    expectations: [
      { code: "COMMAND_OUT_OF_BOUNDS", adopted: true, rationale: "按声明 sizeofcmds 推进后命令越出 slice 结束，命令实体保留并标记 outOfBounds" },
    ],
  });

  // 6. 签名未覆盖尾部：arm slice 追加 64 字节 tailGap
  const armTail = buildSlice({ cputype: CPU_ARM64, cpusubtype: 0, payload: payloadA, tailGap: 64 });
  const tail = buildFat64([
    { cputype: CPU_X86_64, cpusubtype: 3, sliceBytes: x64().bytes },
    { cputype: CPU_ARM64, cpusubtype: 0, sliceBytes: armTail.bytes },
  ]);
  scenarios.push({
    id: "scn-signature-tail-gap",
    title: "签名未覆盖尾部",
    phase: "boundary",
    changedSource: "slice#1.bytes += 64 bytes after signature blob (codeLimit unchanged)",
    bytes: tail.bytes,
    basis: "unit=byte, basis=container-offset, tailGap=64",
    expectations: [
      { code: "SIGNATURE_TAIL_GAP", adopted: true, rationale: "签名 blob 结束 < slice 结束，64 字节无覆盖；区别于签名前覆盖缺口" },
      { code: "SIGNATURE_COVERAGE_GAP", adopted: false, rationale: "代码页连续覆盖到签名起点，无签名前缺口" },
    ],
  });

  // 7. 多架构同名：arm64 + arm64e 使用相同 archName 候选（cputype 相同，subtype 0 与 2）
  const arm64e = buildSlice({ cputype: CPU_ARM64, cpusubtype: SUBTYPE_ARM64E, payload: Array.from(Buffer.from("arm64e platform engineering baseline", "utf8")) });
  const dup = buildFat64([
    { cputype: CPU_ARM64, cpusubtype: 0, sliceBytes: arm().bytes },
    { cputype: CPU_ARM64, cpusubtype: SUBTYPE_ARM64E, sliceBytes: arm64e.bytes },
  ]);
  scenarios.push({
    id: "scn-arch-duplicate",
    title: "多架构同名",
    phase: "boundary",
    changedSource: "fat.arch := [arm64@0, arm64@2(arm64e)]  // cputype 相同",
    bytes: dup.bytes,
    basis: "unit=byte, basis=container-offset",
    expectations: [
      { code: "ARCH_DUPLICATE", adopted: true, rationale: "策略无法唯一决定时保留全部合法候选（#0/#1），不自动选择" },
    ],
  });

  // 8. 未知 blob：arm slice 签名索引追加未知 type 0x77777777
  const armUnknown = buildSlice({
    cputype: CPU_ARM64,
    cpusubtype: 0,
    payload: payloadA,
    extraUnknownBlob: 0x77777777,
  });
  const unknown = buildFat64([
    { cputype: CPU_X86_64, cpusubtype: 3, sliceBytes: x64().bytes },
    { cputype: CPU_ARM64, cpusubtype: 0, sliceBytes: armUnknown.bytes },
  ]);
  scenarios.push({
    id: "scn-unknown-blob",
    title: "未知签名 blob",
    phase: "boundary",
    changedSource: "slice#1.superblob.index += {type=0x77777777}",
    bytes: unknown.bytes,
    basis: "unit=byte, basis=blob-offset@slice#1.signature",
    expectations: [
      { code: "UNKNOWN_BLOB", adopted: true, rationale: "v1 策略按 warning 保留未知 blob；参数修订 v2 后升为 error（同一材料，两种决定均存档）" },
      { code: "UNSUPPORTED_SIGNATURE_FORMAT", adopted: false, rationale: "未知 blob 不等于签名整体格式不支持" },
    ],
  });
}
