// Event-sourced projection. Evaluations are append-only facts; revisiting an
// old event rebuilds the exact policy/material/decision state that was visible
// then, never overwriting history with the newest computation.

import { defaultPolicy } from './evaluate';
import type {
  Decision,
  Event,
  Evaluation,
  FatImageMaterial,
  TargetPolicy,
} from './types';

export interface ImportRecord {
  eventId: string;
  seq: number;
  imageId: string;
  variantKey: string;
  sourceLabel: string;
  hexAsset?: string;
  image: FatImageMaterial;
}

export interface Frame {
  seq: number;
  eventId: string;
  policy: TargetPolicy;
  imports: ImportRecord[];
  evaluations: Evaluation[];
  decisions: Decision[];
  branches: { branch: string; parentBranch: string; parentSeq: number; reason: string }[];
  title: string;
  narrative: string;
}

export function eventsOfBranch(events: Event[], branch: string): Event[] {
  // A branch inherits its parent branch up to the fork point, then contains
  // only its own events afterwards.
  const branchEvents = events.filter((e) => e.branch === branch).sort((a, b) => a.seq - b.seq);
  const fork = branchEvents.find((e) => e.type === 'branch_created');
  if (!fork || branch === 'main') return branchEvents;
  const payload = fork.payload as { branch: string; parentBranch: string; parentSeq: number };
  const parentPrefix = events
    .filter((e) => e.branch === payload.parentBranch && e.seq <= payload.parentSeq)
    .sort((a, b) => a.seq - b.seq);
  return [...parentPrefix, ...branchEvents];
}

export function project(events: Event[], atSeq?: number, branch = 'main'): Frame {
  const scoped = eventsOfBranch(events, branch);
  const limit = atSeq === undefined ? Number.MAX_SAFE_INTEGER : atSeq;
  let policy = defaultPolicy();
  const imports: ImportRecord[] = [];
  const evaluations: Evaluation[] = [];
  const decisions: Decision[] = [];
  const branches: Frame['branches'] = [];
  let title = '';
  let narrative = '';
  let lastSeq = 0;
  let lastId = '';

  for (const event of scoped) {
    if (event.seq > limit) break;
    lastSeq = event.seq;
    lastId = event.id;
    switch (event.type) {
      case 'session_created':
        title = event.payload.title;
        narrative = event.payload.narrative;
        break;
      case 'material_imported':
        imports.push({
          eventId: event.id,
          seq: event.seq,
          imageId: event.payload.imageId,
          variantKey: event.payload.variantKey,
          sourceLabel: event.payload.sourceLabel,
          hexAsset: event.payload.hexAsset,
          image: event.payload.image,
        });
        break;
      case 'policy_revised':
        policy = event.payload.policy;
        break;
      case 'evaluation_recorded':
        evaluations.push(event.payload.evaluation);
        break;
      case 'decision_recorded':
        decisions.push(event.payload.decision);
        // A decision may choose a candidate; mark it on the matching evaluation
        // snapshot without mutating stored history.
        break;
      case 'branch_created':
        branches.push({
          branch: event.payload.branch,
          parentBranch: event.payload.parentBranch,
          parentSeq: event.payload.parentSeq,
          reason: event.payload.reason,
        });
        break;
    }
  }

  return { seq: lastSeq, eventId: lastId, policy, imports, evaluations, decisions, branches, title, narrative };
}

export function listBranches(events: Event[]): string[] {
  const set = new Set<string>(['main']);
  for (const event of events) {
    set.add(event.branch);
    if (event.type === 'branch_created') set.add(event.payload.branch);
  }
  return [...set];
}

/** Latest evaluation per imported image under the frame's policy. */
export function latestEvaluations(frame: Frame): Map<string, Evaluation> {
  const map = new Map<string, Evaluation>();
  for (const evaluation of frame.evaluations) map.set(evaluation.imageId, evaluation);
  return map;
}
