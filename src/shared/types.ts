// 共享领域类型：服务端、存储层与前端共用，业务规则不只藏在浏览器中。

export type Unit = 'byte' | 'page' | 'align-exponent' | 'slot';

/** 坐标基准：所有偏移都必须声明基准，导入时保留原始表示。 */
export type CoordBasis = 'file' | 'slice' | 'blob';

export interface Diagnostic {
  position: { offset: number; basis: CoordBasis; sliceId?: string };
  message: string;
  code: string;
}

export type RunOutcome = 'ok' | 'budget_exhausted' | 'format_corrupt' | 'semantic_unsolvable';

export type RuleStatus =
  | 'pass'
  | 'violation'
  | 'coverage_gap'
  | 'hash_mismatch'
  | 'unsupported_format'
  | 'indeterminate';

export interface Finding {
  id: string; // 稳定身份：rule + 对象 + 位置
  rule: string;
  status: RuleStatus;
  objects: string[]; // 受影响材料 id
  position?: { offset: number; length: number; basis: CoordBasis; sliceId?: string };
  detail: string;
  candidates?: string[]; // 无法唯一决定时的全部合法候选
  evidence?: { offset: number; length: number; basis: CoordBasis; sliceId?: string };
}

export type MaterialKind =
  | 'fat_header'
  | 'slice'
  | 'load_command'
  | 'signature_blob'
  | 'code_slot'
  | 'file_digest';

export interface Material {
  id: string;
  kind: MaterialKind;
  sliceId?: string;
  name: string;
  raw: string; // base64，原始表示逐字节保留
  meta: Record<string, unknown>; // 解析出的原始字段（未规范化）
  digest: string; // sha256 hex
  seq: number; // 引入该材料的事件序号
}

export type EventType = 'import' | 'param_revision' | 'source_amendment' | 'decision' | 'rule_run';

export interface DomainEvent {
  id: string;
  seq: number;
  branch: string;
  type: EventType;
  ruleVersion: string;
  paramVersion: number;
  parents: string[];
  payload: Record<string, unknown>;
  createdAt: string;
}

export interface Branch {
  name: string;
  head: string;
}

export interface ReviewState {
  outcome: RunOutcome;
  diagnostics: Diagnostic[];
  materials: Material[];
  findings: Finding[];
  events: DomainEvent[];
  branches: Branch[];
  head: string;
  paramVersion: number;
  ruleVersion: string;
  params: Record<string, unknown>;
  asOf: string; // 当前查看的事件 id
}

export interface Archive {
  format: 'macho-slice-testimony/1';
  exportedAt: string;
  meta: Record<string, string>;
  materials: Material[];
  events: DomainEvent[];
  branches: Branch[];
}
