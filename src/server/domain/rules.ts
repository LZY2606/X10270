// 规则引擎：把解析结果包装成一次 AnalysisRun。
// 每次运行记录输入摘要、参数版本与父级依赖；finding 身份由内容推导，稳定可重放。
import { contentId, sha256Hex } from '../../shared/id.js';
import type {
  AnalysisRun, Finding, ParamVersion, RunOutcome,
} from '../../shared/types.js';
import { parseMacho } from './macho.js';

export const DEFAULT_RULES: ParamVersion['rules'] = {
  endianPolicy: 'strict',
  maxCommandsPerSlice: 256,
  maxSlices: 32,
  maxFileBytes: 64 * 1024 * 1024,
  alignmentMaxExponent: 30,
  hashAlgorithm: 'sha256',
  pageSizeBytes: 4096,
};

export function analyze(
  bytes: Buffer,
  materialId: string,
  params: ParamVersion,
  parentRunIds: string[],
  startedSeq: number,
): AnalysisRun {
  const inputDigest = sha256Hex(bytes);
  const runId = contentId('run', {
    materialId,
    paramVersionId: params.paramVersionId,
    inputDigest,
    parentRunIds,
  });
  const parsed = parseMacho(bytes, params.rules);

  const findings: Finding[] = parsed.drafts.map((d, i) => ({
    findingId: contentId('find', { runId, ruleId: d.ruleId, subjects: d.subjects, ordinal: i }),
    ruleId: d.ruleId,
    category: d.category,
    severity: d.severity,
    status: 'open' as const,
    message: d.message,
    subjects: d.subjects,
    evidence: d.evidence,
    ...(d.candidates ? { candidates: d.candidates } : {}),
    params: { paramVersionId: params.paramVersionId },
  }));

  const outcome: RunOutcome = deriveOutcome(findings, parsed.document !== null);
  return {
    runId,
    materialId,
    paramVersionId: params.paramVersionId,
    parentRunIds,
    inputDigest,
    outcome,
    findings,
    document: parsed.document,
    diagnostics: parsed.diagnostics,
    startedSeq,
  };
}

function deriveOutcome(findings: Finding[], hasDocument: boolean): RunOutcome {
  const has = (c: string) => findings.some((f) => f.category === c && f.severity === 'violation');
  // 三种结果必须区分：预算耗尽 / 格式损坏 / 语义无解
  if (has('budget')) return 'budget_exhausted';
  if (!hasDocument || has('format')) return 'format_corrupt';
  if (has('semantic')) return 'semantic_unsatisfiable';
  if (findings.some((f) => f.severity === 'violation')) return 'violations';
  return 'ok';
}
