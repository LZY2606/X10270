import type {
  CoordinateBasis, DomainValue, EvidenceByte, EvidenceSpan, Finding,
  FindingCandidate, FindingInputDigest, RuleKind, Severity, TerminalOutcome,
} from '../shared/types.js';
import { cid } from './domain.js';

export interface FindingSpec {
  code: RuleKind;
  title: string;
  severity: Severity;
  path: string;
  message: string;
  spans?: EvidenceSpan[];
  bytes?: EvidenceByte[];
  detail?: Finding['detail'];
  expectedDigest?: DomainValue;
  actualDigest?: DomainValue;
  candidates?: FindingCandidate[];
  emittedBy: string;
  input: FindingInputDigest;
  status?: TerminalOutcome;
}

export function makeFinding(spec: FindingSpec): Finding {
  const spanKey = (spec.spans ?? [])
    .map((s) => `${s.start}:${s.end}:${s.basis}:${s.label}`).join(';');
  const byteKey = (spec.bytes ?? []).map((b) => `${b.offset}=${b.expected}->${b.actual}`).join(';');
  const id = cid('finding', [
    spec.input.inputSha256, spec.input.paramsId, spec.code, spec.path,
    spanKey, byteKey, spec.expectedDigest?.raw ?? '', spec.actualDigest?.raw ?? '',
  ]);
  return {
    id,
    code: spec.code,
    title: spec.title,
    severity: spec.severity,
    status: spec.status ?? 'undecidable',
    location: { path: spec.path, spans: spec.spans ?? [], bytes: spec.bytes },
    message: spec.message,
    detail: spec.detail ?? {},
    expectedDigest: spec.expectedDigest,
    actualDigest: spec.actualDigest,
    candidates: spec.candidates,
    input: spec.input,
    emittedBy: spec.emittedBy,
  };
}

export function span(start: number, end: number, basis: CoordinateBasis, label: string, hexPreview?: string): EvidenceSpan {
  return { start, end, basis, label, hexPreview };
}
export const byteAt = (offset: number, basis: CoordinateBasis, expected: number | null, actual: number | null): EvidenceByte =>
  ({ offset, basis, expected, actual });
