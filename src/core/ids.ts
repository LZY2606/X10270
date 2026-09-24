/** Deterministic stable identities. These survive export/import and never
 * depend on insertion order or random values. */

import { createHash } from 'node:crypto';

export function sha256Hex(data: Uint8Array | string): string {
  return createHash('sha256').update(data).digest('hex');
}

export function sha256Bytes(data: Uint8Array): Uint8Array {
  return new Uint8Array(createHash('sha256').update(data).digest());
}

function b64Url(input: Uint8Array): string {
  return Buffer.from(input)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

/** Content-addressed id with a domain prefix. */
export function contentId(kind: string, parts: Array<string | number>): string {
  const h = createHash('sha256').update(parts.join('|')).digest();
  return `${kind}_${b64Url(h.subarray(0, 15))}`;
}

export function materialId(bytes: Uint8Array): string {
  return contentId('mat', ['fat-v1', sha256Hex(bytes)]);
}

export function sliceId(materialDigest: string, index: number): string {
  return contentId('slc', [materialDigest, String(index)]);
}

export function commandId(materialDigest: string, sliceIndex: number, commandIndex: number): string {
  return contentId('lc', [materialDigest, String(sliceIndex), String(commandIndex)]);
}

export function sigBlobId(materialDigest: string, sliceIndex: number, slot: number): string {
  return contentId('sigb', [materialDigest, String(sliceIndex), String(slot)]);
}

export function codeSlotId(materialDigest: string, sliceIndex: number, page: number): string {
  return contentId('slot', [materialDigest, String(sliceIndex), String(page)]);
}

export function findingId(code: string, parts: Array<string | number>): string {
  return contentId('find', [code, ...parts.map(String)]);
}

export function candidateId(code: string, parts: Array<string | number>): string {
  return contentId('cand', [code, ...parts.map(String)]);
}

export function eventId(kind: string, projectId: string, seq: number): string {
  return contentId('evt', [projectId, kind, String(seq)]);
}
