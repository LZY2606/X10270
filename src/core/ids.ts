// Stable identity + content hashing. Ids are deterministic over the *material*
// coordinates (not array positions beyond the source ordinal that is itself
// on-disk data), so export -> delete -> import restores identical identity,
// ordering and provenance.

import { createHash } from 'node:crypto';

export function sha256Hex(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}

export function sha1Hex(bytes: Uint8Array): string {
  return createHash('sha1').update(bytes).digest('hex');
}

export function digestHex(algorithm: string, bytes: Uint8Array): string {
  return createHash(algorithm).update(bytes).digest('hex');
}

export function shortHash(parts: (string | number)[]): string {
  return createHash('sha256').update(parts.join('|')).digest('hex').slice(0, 12);
}

export const ids = {
  file: (importId: string) => `file_${shortHash([importId])}`,
  slice: (fileId: string, arch: string, ordinal: number, offset: number) =>
    `slice_${shortHash([fileId, arch, ordinal, offset])}`,
  command: (sliceId: string, ordinal: number, cmd: number, cmdsize: number) =>
    `cmd_${shortHash([sliceId, ordinal, cmd, cmdsize])}`,
  signature: (sliceId: string, dataoff: number) =>
    `sig_${shortHash([sliceId, dataoff])}`,
  blob: (sigId: string, slot: number, offset: number) =>
    `blob_${shortHash([sigId, slot, offset])}`,
  slot: (sigId: string, slot: number, pageStart: number | undefined) =>
    `slot_${shortHash([sigId, slot, pageStart ?? 'special'])}`,
};

// An event id commits over the parent chain, making the event log tamper-evident.
export function eventId(parentId: string | null, type: string, payloadDigest: string, at: string): string {
  return `evt_${shortHash([parentId ?? 'genesis', type, payloadDigest, at])}`;
}
