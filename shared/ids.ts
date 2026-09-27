import { createHash } from "node:crypto";

/** Canonical JSON: object keys sorted, undefined dropped. Used for every content hash. */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortValue(value));
}

function sortValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortValue);
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      const v = (value as Record<string, unknown>)[key];
      if (v !== undefined) out[key] = sortValue(v);
    }
    return out;
  }
  return value;
}

export function sha256Hex(data: Uint8Array | string): string {
  return createHash("sha256").update(data).digest("hex");
}

/** Content-addressed identity: <prefix>_<sha256(canonicalJson(payload))[:32]> */
export function contentId(prefix: string, payload: unknown): string {
  return `${prefix}_${sha256Hex(canonicalJson(payload)).slice(0, 32)}`;
}

/** Role-based stable node identity (survives recompute and export/import). */
export function nodeId(kind: string, ...coords: (string | number)[]): string {
  return `node:${kind}:${coords.join(":")}`;
}
