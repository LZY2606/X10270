export async function getJson<T>(path: string): Promise<T> {
  const r = await fetch(path);
  if (!r.ok) throw new Error(`${path} -> ${r.status}`);
  return r.json() as Promise<T>;
}
export async function postJson<T>(path: string, body: unknown): Promise<T> {
  const r = await fetch(path, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await r.json();
  if (!r.ok) throw Object.assign(new Error(data.message ?? r.statusText), { data });
  return data as T;
}

export interface SessionItem {
  id: string;
  title: string;
  created_at: string;
  scenario: {
    scenarioId: string;
    phase: string;
    changedSource: string;
    basis: string;
  } | null;
}

export interface SessionDetail {
  session: { id: string; title: string; created_at: string };
  branches: string[];
  view: {
    material: { id: string; kind: string; source_label: string; basis: string; rawLength: number; input_digest: string } | null;
    derivation: any | null;
    events: any[];
    decision: { value: string; target: string; note: string } | null;
    policy: any;
  };
}
