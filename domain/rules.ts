// 规则集：版本化。所有派生结果记录 ruleVersion，复核时可反查是哪版规则造成差异。
export interface RuleSet {
  version: string;
  pageSize: number;        // 代码槽分页大小（byte）
  hashAlg: 'fnv1a-32';
  maxSlices: number;       // 资源预算：最多解析的 slice 数
  maxCommands: number;     // 资源预算：每个 slice 最多解析的 load command 数
  strictAlign: boolean;    // 对齐必须整除，不靠四舍五入修正
}

export const RULES_V1: RuleSet = {
  version: 'rules@1', pageSize: 0x1000, hashAlg: 'fnv1a-32',
  maxSlices: 8, maxCommands: 64, strictAlign: true,
};

// 参数修订：分页基准从 4KiB 调整为 16KiB，其余不变。
export const RULES_V2: RuleSet = { ...RULES_V1, version: 'rules@2', pageSize: 0x4000 };

export const ALL_RULES: Record<string, RuleSet> = {
  [RULES_V1.version]: RULES_V1,
  [RULES_V2.version]: RULES_V2,
};
