// Application service: the single orchestration path used by HTTP routes, CLI
// seeding and tests. Browser code never implements business rules itself; it
// calls this logic through the API in dev and the same module is imported by
// Vitest.

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { createBundle, verifyBundle, type Bundle } from '../shared/bundle';
import { evaluateImage, defaultPolicy, type EvaluateResult } from '../shared/evaluate';
import { digestHex } from '../shared/identity';
import { parseFatImage } from '../shared/parse';
import { project } from '../shared/project';
import { Store, type EventRow } from './db';
import type { Decision, Disposition, Event, TargetPolicy } from '../shared/types';
import { fromHex } from '../shared/binio';

export interface SessionSummary {
  id: string;
  title: string;
  narrative: string;
  createdAt: string;
}

function nowIso(): string {
  return new Date().toISOString();
}

function eventRow(event: Event): EventRow {
  return {
    id: event.id,
    seq: event.seq,
    session_id: event.sessionId,
    branch: event.branch,
    at: event.at,
    actor: event.actor,
    type: event.type,
    payload: JSON.stringify(event.payload),
  };
}

function rowEvent(row: EventRow): Event {
  return {
    id: row.id,
    seq: row.seq,
    sessionId: row.session_id,
    branch: row.branch,
    at: row.at,
    actor: row.actor as Event['actor'],
    type: row.type as Event['type'],
    payload: JSON.parse(row.payload),
  } as Event;
}

export class AppService {
  constructor(
    readonly store: Store,
    private readonly assetDir?: string,
  ) {}

  listSessions(): SessionSummary[] {
    return this.store.listSessions();
  }

  loadEvents(sessionId: string): Event[] {
    return this.store.getEvents(sessionId).map(rowEvent);
  }

  view(sessionId: string, atSeq?: number, branch = 'main') {
    const events = this.loadEvents(sessionId);
    const frame = project(events, atSeq, branch);
    const latest = frame.evaluations;
    return { frame, events, latestEvaluationByImage: new Map(latest.map((e) => [e.imageId, e])) };
  }

  createSession(id: string, title: string, narrative: string): Event {
    const event: Event = {
      id: `evt:${id}:1:session_created`,
      seq: 1,
      sessionId: id,
      branch: 'main',
      at: nowIso(),
      actor: 'importer',
      type: 'session_created',
      payload: { title, narrative },
    };
    this.store.insertSession(id, title, event.at, narrative);
    this.store.insertEvent(eventRow(event), id);
    return event;
  }

  /**
   * Import bytes, parse and evaluate in one transactional narrative step.
   * Raw materials are retained verbatim; incomplete input yields a
   * position-bearing diagnostic instead of fabricated success.
   */
  importImage(opts: {
    sessionId: string;
    branch?: string;
    variantKey: string;
    sourceLabel: string;
    bytes: Uint8Array;
    hexAsset?: string;
    maxObjects?: number;
    policy?: TargetPolicy;
    actor?: Event['actor'];
  }): { importEvent: Event; evaluationEvent: Event; result: EvaluateResult } {
    const branch = opts.branch ?? 'main';
    const seq = this.store.nextSeq(opts.sessionId, branch);
    const parsed = parseFatImage(opts.bytes, { maxObjects: opts.maxObjects, label: opts.sourceLabel });
    const events = this.loadEvents(opts.sessionId);
    const frame = project(events, undefined, branch);
    const policy = opts.policy ?? frame.policy ?? defaultPolicy();
    const result = evaluateImage(parsed, policy, [], { maxObjects: opts.maxObjects });
    const computedAt = nowIso();
    result.evaluation.computedAt = computedAt;

    const importEvent: Event = {
      id: `evt:${opts.sessionId}:${seq}:material_imported:${parsed.image.imageId}`,
      seq,
      sessionId: opts.sessionId,
      branch,
      at: nowIso(),
      actor: opts.actor ?? 'importer',
      type: 'material_imported',
      payload: {
        imageId: parsed.image.imageId,
        variantKey: opts.variantKey,
        sourceLabel: opts.sourceLabel,
        hexAsset: opts.hexAsset,
        image: parsed.image,
        inputFragmentRefs: parsed.parseFindings.map((f) => `${f.at.basis}:${f.at.start}+${f.at.length}`),
      },
    };
    this.store.insertEvent(eventRow(importEvent), opts.sessionId);

    const evaluationEvent: Event = {
      id: `evt:${opts.sessionId}:${seq + 1}:evaluation_recorded:${result.evaluation.id}`,
      seq: seq + 1,
      sessionId: opts.sessionId,
      branch,
      at: computedAt,
      actor: 'engine',
      type: 'evaluation_recorded',
      payload: { evaluation: result.evaluation },
    };
    this.store.insertEvent(eventRow(evaluationEvent), opts.sessionId);

    return { importEvent, evaluationEvent, result };
  }

  revisePolicy(sessionId: string, policy: TargetPolicy, reason: string, branch = 'main'): Event[] {
    const seq = this.store.nextSeq(sessionId, branch);
    const event: Event = {
      id: `evt:${sessionId}:${seq}:policy_revised:v${policy.version}`,
      seq,
      sessionId,
      branch,
      at: nowIso(),
      actor: 'reviewer',
      type: 'policy_revised',
      payload: { policy, previousVersion: policy.version - 1, reason },
    };
    this.store.insertEvent(eventRow(event), sessionId);

    // Re-evaluate each retained import under the new parameter version, keeping
    // prior evaluation events intact.
    const events = this.loadEvents(sessionId);
    const frame = project(events, undefined, branch);
    const out: Event[] = [event];
    for (const record of frame.imports) {
      const bytes = this.resolveImageBytes(record.hexAsset);
      if (!bytes || bytes.length === 0) continue;
      const next = this.store.nextSeq(sessionId, branch);
      const parsed = parseFatImage(bytes, { label: record.sourceLabel });
      const result = evaluateImage(parsed, policy, [record.eventId]);
      result.evaluation.computedAt = nowIso();
      const evaluationEvent: Event = {
        id: `evt:${sessionId}:${next}:evaluation_recorded:${result.evaluation.id}`,
        seq: next,
        sessionId,
        branch,
        at: result.evaluation.computedAt,
        actor: 'engine',
        type: 'evaluation_recorded',
        payload: { evaluation: result.evaluation },
      };
      this.store.insertEvent(eventRow(evaluationEvent), sessionId);
      out.push(evaluationEvent);
    }
    return out;
  }

  recordDecision(opts: {
    sessionId: string;
    branch?: string;
    disposition: Disposition;
    targetEvaluationId?: string | null;
    rationale: string;
    candidateId?: string | null;
    conflictsWithDecisionId?: string | null;
  }): Event {
    const branch = opts.branch ?? 'main';
    const seq = this.store.nextSeq(opts.sessionId, branch);
    const frame = project(this.loadEvents(opts.sessionId), undefined, branch);
    const decision: Decision = {
      id: `dec:${opts.sessionId}:${seq}`,
      disposition: opts.disposition,
      targetEvaluationId: opts.targetEvaluationId ?? null,
      rationale: opts.rationale,
      candidateId: opts.candidateId ?? null,
      conflictsWithDecisionId: opts.conflictsWithDecisionId ?? null,
      policyVersion: frame.policy.version,
    };
    const event: Event = {
      id: `evt:${opts.sessionId}:${seq}:decision_recorded:${decision.id}`,
      seq,
      sessionId: opts.sessionId,
      branch,
      at: nowIso(),
      actor: 'reviewer',
      type: 'decision_recorded',
      payload: { decision },
    };
    this.store.insertEvent(eventRow(event), opts.sessionId);
    return event;
  }

  createBranch(
    sessionId: string,
    branch: string,
    reason: string,
    parentBranch = 'main',
  ): Event {
    const events = this.store.getBranchEvents(sessionId, parentBranch);
    const parentSeq = events.length ? events[events.length - 1].seq : 0;
    const seq = parentSeq + 1;
    const event: Event = {
      id: `evt:${sessionId}:${seq}:branch_created:${branch}`,
      seq,
      sessionId,
      branch,
      at: nowIso(),
      actor: 'reviewer',
      type: 'branch_created',
      payload: { branch, parentBranch, parentSeq, reason },
    };
    this.store.insertEvent(eventRow(event), sessionId);
    return event;
  }

  exportBundle(sessionId: string): Bundle {
    const session = this.store.listSessions().find((s) => s.id === sessionId);
    if (!session) throw new Error(`session ${sessionId} 不存在`);
    const events = this.loadEvents(sessionId);
    return createBundle(
      { id: session.id, title: session.title, createdAt: session.createdAt, narrative: session.narrative },
      events,
    );
  }

  importBundle(input: unknown, opts: { crashAfterEventRows?: number; leaveMarker?: boolean } = {}): {
    bundle: Bundle;
    committed: boolean;
  } {
    const bundle = verifyBundle(input);
    const rows = bundle.events.map(eventRow);
    const result = this.store.importBundle(
      bundle.bundleId,
      {
        id: bundle.session.id,
        title: bundle.session.title,
        createdAt: bundle.session.createdAt,
        narrative: bundle.session.narrative,
      },
      rows,
      opts,
    );
    return { bundle, committed: result.committed };
  }

  saveAsset(name: string, bytes: Uint8Array): string {
    if (!this.assetDir) throw new Error('asset dir not configured');
    mkdirSync(this.assetDir, { recursive: true });
    const safe = name.replace(/[^A-Za-z0-9._-]/g, '_');
    writeFileSync(join(this.assetDir, safe), bytes);
    return safe;
  }

  loadAsset(name: string): Uint8Array {
    const safe = name.replace(/[^A-Za-z0-9._-]/g, '_');
    const candidates = this.assetDir
      ? [join(this.assetDir, safe), join(process.cwd(), 'cases', 'images', safe)]
      : [join(process.cwd(), 'cases', 'images', safe)];
    for (const path of candidates) {
      if (existsSync(path)) return new Uint8Array(readFileSync(path));
    }
    return new Uint8Array();
  }

  private resolveImageBytes(hexAsset: string | undefined): Uint8Array {
    if (!hexAsset) return new Uint8Array();
    if (/^[0-9a-f]+$/i.test(hexAsset) && hexAsset.length > 64) return fromHex(hexAsset);
    const safe = hexAsset.replace(/[^A-Za-z0-9._-]/g, '_');
    const paths = [
      ...(this.assetDir ? [join(this.assetDir, safe)] : []),
      join(process.cwd(), 'cases', 'images', safe),
    ];
    for (const path of paths) {
      if (!existsSync(path)) continue;
      const raw = readFileSync(path, 'utf8');
      if (safe.endsWith('.hex')) return fromHex(raw.trim());
      return new Uint8Array(readFileSync(path));
    }
    return new Uint8Array();
  }

  reset(): void {
    this.store.resetAll();
  }

  static inputDigest(bytes: Uint8Array): string {
    return digestHex(bytes);
  }
}
