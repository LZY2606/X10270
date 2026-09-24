/** 领域量：导入时保留原始表示，派生层才做规范化。 */
export interface Quantity {
  /** 原始表示（如 "0x4000"、"16384"、"1.5页"），导入时原样保留 */
  raw: string;
  /** 规范化后的数值；无法转换时为 null，原值留在 raw 中并附 diagnostic */
  value: number | null;
  unit: "byte" | "page" | "slot" | "count" | "flag" | "hex";
  /** 坐标基准，如 "file-offset" / "slice-offset" / "page-index" / "slot-index" */
  basis: string;
  diagnostic?: string;
}

export const q = (
  raw: string,
  value: number | null,
  unit: Quantity["unit"],
  basis: string,
  diagnostic?: string,
): Quantity => ({ raw, value, unit, basis, ...(diagnostic ? { diagnostic } : {}) });

export const qHex = (value: number, unit: Quantity["unit"], basis: string): Quantity =>
  q(`0x${value.toString(16)}`, value, unit, basis);

/** 三种必须区分的结果类别 + ok */
export type ResultKind = "ok" | "budget-exhausted" | "format-corrupt" | "semantic-unsolvable";

export interface Evidence {
  objectId: string;
  /** 失败字节在文件坐标系中的位置 */
  offset: Quantity;
  length: Quantity;
  /** 失败字节证据读回（hex） */
  bytesHex: string;
  expected?: string;
  actual?: string;
}

export interface Candidate {
  id: string;
  description: string;
  /** 该候选依赖的材料/规则版本 */
  basis: Record<string, string>;
}

export interface Finding {
  ruleId: string;
  ruleVersion: string;
  status: "pass" | "fail" | "undecidable";
  summary: string;
  /** 受影响对象的稳定身份 */
  affected: string[];
  evidence: Evidence[];
  /** 无法唯一决定时保留的全部合法候选 */
  candidates?: Candidate[];
}

export interface RuleParams {
  version: string;
  /** 资源预算：最大解析字节数 / 最大 load command 数 */
  budgetBytes: number;
  budgetCommands: number;
  /** 目标架构策略：期望的架构名列表 */
  targetArchs: string[];
  /** 签名尾部是否允许未覆盖 */
  allowSignatureTailGap: boolean;
}

export const DEFAULT_PARAMS: RuleParams = {
  version: "params/v1",
  budgetBytes: 64 * 1024 * 1024,
  budgetCommands: 4096,
  targetArchs: ["x86_64", "arm64"],
  allowSignatureTailGap: true,
};

export interface RuleOutput {
  resultKind: ResultKind;
  findings: Finding[];
}
