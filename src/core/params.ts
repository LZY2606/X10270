import type { Outcome } from './types.js';

/**
 * Versioned review policy. Revisions are append-only events; derived
 * results record the paramsVersion they were produced under.
 */
export interface ReviewParams {
  version: number;
  pageSize: number;
  /**
   * v1: (cputype,cpusubtype) full pair must be unique.
   * v2 (revised): cpusubtype low 8 bits masked with capability bits, so
   *    subtypes differing only in capability bits collapse -> ambiguity.
   */
  archIdentityMask: number;
  maxSlices: number;
  maxCommandsPerSlice: number;
  maxContainerBytes: number;
  maxTotalCommands: number;
  rejectUnknownBlob: boolean;
}

export const PARAMS_V1: ReviewParams = {
  version: 1,
  pageSize: 4096,
  archIdentityMask: 0xffffffff,
  maxSlices: 16,
  maxCommandsPerSlice: 256,
  maxContainerBytes: 128 * 1024 * 1024,
  maxTotalCommands: 2048,
  rejectUnknownBlob: true,
};

export function reviseParams(prev: ReviewParams, patch: Partial<ReviewParams>): ReviewParams {
  return { ...prev, ...patch, version: prev.version + 1 };
}

/** Precedence used when collapsing per-layer outcomes. */
export function worseOutcome(a: Outcome, b: Outcome): Outcome {
  const rank: Record<Outcome, number> = {
    OK: 0,
    SEMANTIC: 1,
    CORRUPT: 2,
    BUDGET_EXHAUSTED: 3,
  };
  return rank[a] >= rank[b] ? a : b;
}
