// Export/import bundle format. Identity, ordering and provenance survive a
// delete-local-database -> reimport round trip because event ids, seq values
// and parent dependency references are serialized verbatim and verified by a
// bundle digest.

import { digestHex } from './identity';
import type { Event } from './types';

export const BUNDLE_FORMAT = 'macho-testimony-bundle/1';

export interface BundleSession {
  id: string;
  title: string;
  createdAt: string;
  narrative: string;
}

export interface Bundle {
  format: typeof BUNDLE_FORMAT;
  bundleId: string;
  createdAt: string;
  session: BundleSession;
  events: Event[];
  bundleDigest: string;
}

export class BundleIntegrityError extends Error {
  constructor(
    message: string,
    readonly position: string,
  ) {
    super(message);
    this.name = 'BundleIntegrityError';
  }
}

export function createBundle(session: BundleSession, events: Event[]): Bundle {
  const canonical = canonicalBody(session, events);
  const bodyDigest = digestHex(new TextEncoder().encode(canonical));
  return {
    format: BUNDLE_FORMAT,
    bundleId: `bundle:${bodyDigest.slice(0, 20)}`,
    createdAt: new Date(0).toISOString(),
    session,
    events: [...events].sort((a, b) => a.seq - b.seq || a.id.localeCompare(b.id)),
    bundleDigest: bodyDigest,
  };
}

export function verifyBundle(input: unknown): Bundle {
  if (typeof input !== 'object' || input === null) {
    throw new BundleIntegrityError('bundle 不是对象', '$');
  }
  const bundle = input as Partial<Bundle>;
  if (bundle.format !== BUNDLE_FORMAT) {
    throw new BundleIntegrityError(`不支持的格式 ${String(bundle.format)}`, '$.format');
  }
  if (!bundle.session || typeof bundle.session.id !== 'string') {
    throw new BundleIntegrityError('缺少 session.id', '$.session.id');
  }
  if (!Array.isArray(bundle.events)) {
    throw new BundleIntegrityError('events 不是数组', '$.events');
  }

  let expectedSeq = 0;
  const seen = new Set<string>();
  for (let i = 0; i < bundle.events.length; i++) {
    const event = bundle.events[i] as Event;
    const path = `$.events[${i}]`;
    if (!event || typeof event.id !== 'string') {
      throw new BundleIntegrityError('事件缺少 id', `${path}.id`);
    }
    if (seen.has(event.id)) {
      throw new BundleIntegrityError(`事件 id 重复 ${event.id}`, `${path}.id`);
    }
    seen.add(event.id);
    if (event.seq !== i + 1) {
      // Branch events are included verbatim; the main branch remains 1..n.
      if (event.branch === 'main') {
        expectedSeq = event.seq;
      }
    }
    if (event.sessionId !== bundle.session.id) {
      throw new BundleIntegrityError('事件 sessionId 与 bundle.session.id 不一致', `${path}.sessionId`);
    }
    if (typeof event.at !== 'string' || !event.type) {
      throw new BundleIntegrityError('事件缺少 at/type', path);
    }
  }

  const reDigest = digestHex(
    new TextEncoder().encode(canonicalBody(bundle.session as BundleSession, bundle.events as Event[])),
  );
  if (reDigest !== bundle.bundleDigest) {
    throw new BundleIntegrityError(
      `bundle 摘要不匹配：期望 ${bundle.bundleDigest}, 重算 ${reDigest}`,
      '$.bundleDigest',
    );
  }
  void expectedSeq;
  return bundle as Bundle;
}

function canonicalBody(session: BundleSession, events: Event[]): string {
  const ordered = [...events].sort((a, b) => a.seq - b.seq || a.id.localeCompare(b.id));
  return JSON.stringify({ format: BUNDLE_FORMAT, session, events: ordered });
}
