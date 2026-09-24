// 材料身份层：不可变材料的身份由内容（原始字节 + 名称 + slice 引用）确定性派生，
// 使“删除数据库再导入”与“导出再导入”后身份完全一致。
import { createHash } from 'node:crypto';
import { toBase64, type ParsedFile, type RawMaterial } from './macho.js';

export interface KeyedMaterial {
  id: string;
  key: string;
  kind: RawMaterial['kind'];
  sliceId?: string;
  name: string;
  rawB64: string;
  meta: Record<string, unknown>;
  digest: string;
}

function keyFor(m: RawMaterial, kindIndex: number): { id: string; key: string } {
  const key =
    m.kind === 'fat_header' ? 'fat_header'
    : m.kind === 'file_digest' ? 'file_digest'
    : m.kind === 'slice' ? `slice:${m.sliceRef}`
    : m.kind === 'code_slot' ? `slot:${m.sliceRef}:${m.meta.slot_index}`
    : m.kind === 'signature_blob' && m.name.startsWith('super_blob')
      ? `superblob:${m.sliceRef}`
    : m.kind === 'signature_blob'
      ? `blob:${m.sliceRef}:${m.meta.slot_type}`
    : `command:${m.sliceRef}:${kindIndex === 0 ? 'mach_header' : 'lc'}`;
  const digest = createHash('sha256')
    .update(Buffer.from(m.raw))
    .update('\0')
    .update(m.name)
    .digest('hex');
  return { id: `mat:${key}:${digest.slice(0, 12)}`, key };
}

export function buildMaterials(parsed: ParsedFile): {
  materials: KeyedMaterial[];
  idByKey: Record<string, string>;
} {
  const out: KeyedMaterial[] = [];
  const idByKey: Record<string, string> = {};
  const cmdSeen: Record<string, number> = {};
  for (const m of parsed.materials) {
    const sliceRef = m.sliceRef;
    let kindIndex = 0;
    if (m.kind === 'load_command' && sliceRef) {
      kindIndex = cmdSeen[sliceRef] ?? 0;
      cmdSeen[sliceRef] = kindIndex + 1;
    }
    // mach_header 是每个 slice 的第一份 load_command 类材料
    let { id, key } = keyFor(m, kindIndex);
    if (m.kind === 'load_command') {
      if (kindIndex === 0) key = `mach_header:${sliceRef}`;
      else {
        const cmds = parsed.slices.find((s) => s.ref === sliceRef)?.commands ?? [];
        const ci = kindIndex - 1;
        const cmd = cmds[ci];
        key = `command:${sliceRef}:${cmd?.index ?? ci}`;
      }
      id = `mat:${key}:${id.split(':').pop()}`;
    }
    idByKey[key] = id;
    out.push({
      id,
      key,
      kind: m.kind,
      sliceId: sliceRef,
      name: m.name,
      rawB64: toBase64(m.raw),
      meta: m.meta,
      digest: createHash('sha256').update(Buffer.from(m.raw)).digest('hex'),
    });
  }
  return { materials: out, idByKey };
}
