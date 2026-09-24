import { createHash } from "node:crypto";

/** 规范化 JSON（键排序），保证等价输入得到稳定顺序与稳定摘要 */
export function canonical(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonical(obj[k])}`).join(",")}}`;
}

export function digestOf(value: unknown): string {
  return createHash("sha256").update(canonical(value)).digest("hex");
}

export function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

/** 稳定身份：kind 前缀 + 内容摘要。等价输入 → 同一身份。 */
export function stableId(kind: string, ...parts: unknown[]): string {
  return `${kind}_${digestOf(parts).slice(0, 20)}`;
}
