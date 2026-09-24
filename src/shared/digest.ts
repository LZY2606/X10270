import { createHash } from 'node:crypto'

export function sha256hex(data: Uint8Array | string): string {
  const h = createHash('sha256')
  h.update(typeof data === 'string' ? Buffer.from(data, 'utf8') : data)
  return h.digest('hex')
}

export function sha1hex(data: Uint8Array): string {
  return createHash('sha1').update(data).digest('hex')
}

/** 稳定 JSON 序列化（键排序），等价输入得到等价摘要与稳定顺序。 */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortDeep(value))
}

function sortDeep(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortDeep)
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {}
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      out[key] = sortDeep((value as Record<string, unknown>)[key])
    }
    return out
  }
  return value
}

export function contentId(prefix: string, value: unknown): string {
  return `${prefix}_${sha256hex(canonicalJson(value)).slice(0, 16)}`
}

export function bytesToB64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64')
}

export function b64ToBytes(b64: string): Uint8Array {
  return new Uint8Array(Buffer.from(b64, 'base64'))
}

export function toHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('hex')
}
