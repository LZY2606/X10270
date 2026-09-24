// Mach-O / 通用二进制解析层。
// 原则：导入时保留原始表示（raw hex / 原始字节），派生层才做规范化；
// 无法转换的值留在原位置并附诊断，不用空值或默认值伪装成功。

export type Endian = 'big' | 'little'

export interface Qty {
  value: number
  unit: 'byte' | 'log2-byte' | 'count'
  basis: 'file' | 'slice'
  raw: string
}

export interface Diagnostic {
  code: string
  message: string
  severity: 'fatal' | 'error' | 'warning'
  position?: { basis: 'file' | 'slice'; offset: number }
}

export type ParseStatus = 'ok' | 'format-corrupt' | 'resource-exhausted'

export interface ParseBudget {
  maxFileBytes: number
  maxSlices: number
  maxCommands: number
}

export const DEFAULT_BUDGET: ParseBudget = {
  maxFileBytes: 64 * 1024 * 1024,
  maxSlices: 32,
  maxCommands: 512,
}

export const RULE_VERSION = 'rules-v1'

const CPU_NAMES: Record<number, string> = {
  0x01000007: 'x86_64',
  0x0100000c: 'arm64',
  0x00000007: 'x86',
  0x0000000c: 'arm',
}

export const LC_NAMES: Record<number, string> = {
  0x1: 'LC_SEGMENT',
  0x2: 'LC_SYMTAB',
  0xb: 'LC_DYSYMTAB',
  0xc: 'LC_LOAD_DYLIB',
  0x19: 'LC_SEGMENT_64',
  0x1b: 'LC_UUID',
  0x1d: 'LC_CODE_SIGNATURE',
  0x21: 'LC_ENCRYPTION_INFO',
  0x24: 'LC_VERSION_MIN_MACOSX',
  0x26: 'LC_FUNCTION_STARTS',
  0x29: 'LC_DATA_IN_CODE',
  0x2a: 'LC_SOURCE_VERSION',
  0x2c: 'LC_ENCRYPTION_INFO_64',
  0x32: 'LC_BUILD_VERSION',
}

export function hex(bytes: Uint8Array, start: number, len: number): string {
  const end = Math.min(start + len, bytes.length)
  let out = ''
  for (let i = start; i < end; i++) out += bytes[i].toString(16).padStart(2, '0')
  return out
}

function readU32(view: DataView, off: number, endian: Endian): number {
  return view.getUint32(off, endian === 'little')
}

export interface SliceRef {
  index: number
  objectId: string
  cputype: number
  cpusubtype: number
  archName: string | null // 无法转换时保留 null，诊断说明原因，raw 字段仍在
  offset: Qty
  size: Qty
  align: Qty
  rawHex: string
}

export interface ContainerParse {
  status: ParseStatus
  kind: 'fat' | 'thin'
  endian: Endian
  diagnostics: Diagnostic[]
  nfatArch: number
  slices: SliceRef[]
  headerRawHex: string
  fileSize: Qty
}

export interface LoadCommandInfo {
  index: number
  objectId: string
  cmd: number
  cmdName: string
  cmdsize: number
  offset: Qty
  rawHex: string
  outOfBounds: boolean
}

export interface MachOHeader {
  magic: number
  magicRaw: string
  endian: Endian
  is64: boolean
  cputype: number
  cpusubtype: number
  filetype: number
  ncmds: number
  sizeofcmds: number
  rawHex: string
}

export interface MachOParse {
  status: ParseStatus
  diagnostics: Diagnostic[]
  header: MachOHeader | null
  commands: LoadCommandInfo[]
  truncated: boolean // command 越界时列表在此处截断，不伪造后续命令
}

function qty(value: number, unit: Qty['unit'], basis: Qty['basis']): Qty {
  return { value, unit, basis, raw: '0x' + value.toString(16).padStart(8, '0') }
}

const THIN_MAGICS: Record<string, { endian: Endian; is64: boolean }> = {
  feedface: { endian: 'big', is64: false },
  feedfacf: { endian: 'big', is64: true },
  cefaedfe: { endian: 'little', is64: false },
  cffaedfe: { endian: 'little', is64: true },
}

export function parseContainer(
  bytes: Uint8Array,
  budget: ParseBudget = DEFAULT_BUDGET,
): ContainerParse {
  const diagnostics: Diagnostic[] = []
  const fileSize = qty(bytes.length, 'byte', 'file')
  if (bytes.length > budget.maxFileBytes) {
    return {
      status: 'resource-exhausted', kind: 'thin', endian: 'big', diagnostics: [
        { code: 'budget.file-bytes', message: `文件 ${bytes.length} 字节超出预算 ${budget.maxFileBytes}`, severity: 'fatal' },
      ], nfatArch: 0, slices: [], headerRawHex: '', fileSize,
    }
  }
  if (bytes.length < 4) {
    return {
      status: 'format-corrupt', kind: 'thin', endian: 'big', diagnostics: [
        { code: 'format.truncated', message: '文件不足 4 字节，无法读取 magic', severity: 'fatal', position: { basis: 'file', offset: 0 } },
      ], nfatArch: 0, slices: [], headerRawHex: '', fileSize,
    }
  }
  const magicHex = hex(bytes, 0, 4)
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)

  if (magicHex === 'cafebabe' || magicHex === 'bebafeca') {
    const endian: Endian = magicHex === 'cafebabe' ? 'big' : 'little'
    if (bytes.length < 8) {
      return {
        status: 'format-corrupt', kind: 'fat', endian, diagnostics: [
          { code: 'format.truncated', message: 'fat header 不足 8 字节', severity: 'fatal', position: { basis: 'file', offset: 0 } },
        ], nfatArch: 0, slices: [], headerRawHex: magicHex, fileSize,
      }
    }
    const nfat = readU32(view, 4, endian)
    if (nfat > budget.maxSlices) {
      return {
        status: 'resource-exhausted', kind: 'fat', endian, diagnostics: [
          { code: 'budget.slices', message: `nfat_arch=${nfat} 超出预算 ${budget.maxSlices}`, severity: 'fatal', position: { basis: 'file', offset: 4 } },
        ], nfatArch: nfat, slices: [], headerRawHex: hex(bytes, 0, 8), fileSize,
      }
    }
    if (8 + nfat * 20 > bytes.length) {
      return {
        status: 'format-corrupt', kind: 'fat', endian, diagnostics: [
          { code: 'format.truncated', message: `fat arch 表需要 ${8 + nfat * 20} 字节，文件仅 ${bytes.length}`, severity: 'fatal', position: { basis: 'file', offset: 8 } },
        ], nfatArch: nfat, slices: [], headerRawHex: hex(bytes, 0, 8), fileSize,
      }
    }
    const slices: SliceRef[] = []
    for (let i = 0; i < nfat; i++) {
      const base = 8 + i * 20
      const cputype = readU32(view, base, endian)
      const cpusubtype = readU32(view, base + 4, endian)
      const offset = readU32(view, base + 8, endian)
      const size = readU32(view, base + 12, endian)
      const align = readU32(view, base + 16, endian)
      const archName = CPU_NAMES[cputype] ?? null
      if (archName === null) {
        diagnostics.push({
          code: 'convert.unknown-cputype',
          message: `cputype 0x${cputype.toString(16)} 无已知架构名，原值保留`,
          severity: 'warning',
          position: { basis: 'file', offset: base },
        })
      }
      slices.push({
        index: i,
        objectId: `slice[${i}]`,
        cputype,
        cpusubtype,
        archName,
        offset: qty(offset, 'byte', 'file'),
        size: qty(size, 'byte', 'file'),
        align: qty(align, 'log2-byte', 'file'),
        rawHex: hex(bytes, base, 20),
      })
    }
    return { status: 'ok', kind: 'fat', endian, diagnostics, nfatArch: nfat, slices, headerRawHex: hex(bytes, 0, 8 + nfat * 20), fileSize }
  }

  const thin = THIN_MAGICS[magicHex]
  if (thin) {
    return {
      status: 'ok', kind: 'thin', endian: thin.endian, diagnostics, nfatArch: 1,
      slices: [{
        index: 0, objectId: 'slice[0]', cputype: 0, cpusubtype: 0, archName: null,
        offset: qty(0, 'byte', 'file'), size: qty(bytes.length, 'byte', 'file'), align: qty(0, 'log2-byte', 'file'),
        rawHex: magicHex,
      }],
      headerRawHex: magicHex, fileSize,
    }
  }

  return {
    status: 'format-corrupt', kind: 'thin', endian: 'big', diagnostics: [
      { code: 'format.bad-magic', message: `未知 magic 0x${magicHex}，既不是 fat 也不是 Mach-O`, severity: 'fatal', position: { basis: 'file', offset: 0 } },
    ], nfatArch: 0, slices: [], headerRawHex: magicHex, fileSize,
  }
}

export function parseMachO(
  bytes: Uint8Array,
  sliceObjectId: string,
  budget: ParseBudget = DEFAULT_BUDGET,
): MachOParse {
  const diagnostics: Diagnostic[] = []
  const empty = { status: 'ok' as ParseStatus, diagnostics, header: null, commands: [], truncated: false }
  if (bytes.length < 28) {
    diagnostics.push({ code: 'format.truncated', message: `slice 不足 28 字节（${bytes.length}），无法读取 Mach-O header`, severity: 'fatal', position: { basis: 'slice', offset: 0 } })
    return { ...empty, status: 'format-corrupt' }
  }
  const magicHex = hex(bytes, 0, 4)
  const thin = THIN_MAGICS[magicHex]
  if (!thin) {
    diagnostics.push({ code: 'format.bad-magic', message: `slice magic 0x${magicHex} 不是 Mach-O`, severity: 'fatal', position: { basis: 'slice', offset: 0 } })
    return { ...empty, status: 'format-corrupt' }
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
  const le = thin.endian === 'little'
  const headerSize = thin.is64 ? 32 : 28
  if (bytes.length < headerSize) {
    diagnostics.push({ code: 'format.truncated', message: 'Mach-O 64 位 header 不足 32 字节', severity: 'fatal', position: { basis: 'slice', offset: 0 } })
    return { ...empty, status: 'format-corrupt' }
  }
  const ncmds = view.getUint32(16, le)
  const sizeofcmds = view.getUint32(20, le)
  const header: MachOHeader = {
    magic: view.getUint32(0, le),
    magicRaw: magicHex,
    endian: thin.endian,
    is64: thin.is64,
    cputype: view.getUint32(4, le),
    cpusubtype: view.getUint32(8, le),
    filetype: view.getUint32(12, le),
    ncmds,
    sizeofcmds,
    rawHex: hex(bytes, 0, headerSize),
  }
  if (ncmds > budget.maxCommands) {
    diagnostics.push({ code: 'budget.commands', message: `ncmds=${ncmds} 超出预算 ${budget.maxCommands}`, severity: 'fatal', position: { basis: 'slice', offset: 16 } })
    return { status: 'resource-exhausted', diagnostics, header, commands: [], truncated: false }
  }
  const commands: LoadCommandInfo[] = []
  let off = headerSize
  let truncated = false
  for (let i = 0; i < ncmds; i++) {
    if (off + 8 > bytes.length || off + 8 > headerSize + sizeofcmds) {
      diagnostics.push({ code: 'lc.out-of-bounds', message: `load command #${i} 头部越界（offset=${off}）`, severity: 'error', position: { basis: 'slice', offset: off } })
      truncated = true
      break
    }
    const cmd = view.getUint32(off, le)
    const cmdsize = view.getUint32(off + 4, le)
    const outOfBounds = cmdsize < 8 || off + cmdsize > headerSize + sizeofcmds || off + cmdsize > bytes.length
    if (outOfBounds) {
      diagnostics.push({
        code: 'lc.out-of-bounds',
        message: `load command #${i} (${LC_NAMES[cmd] ?? '0x' + cmd.toString(16)}) cmdsize=${cmdsize} 越界（声明区 ${sizeofcmds} 字节）`,
        severity: 'error',
        position: { basis: 'slice', offset: off },
      })
      commands.push({
        index: i, objectId: `${sliceObjectId}/lc[${i}]`, cmd,
        cmdName: LC_NAMES[cmd] ?? `LC_UNKNOWN(0x${cmd.toString(16)})`,
        cmdsize, offset: qty(off, 'byte', 'slice'), rawHex: hex(bytes, off, Math.min(8, bytes.length - off)),
        outOfBounds: true,
      })
      truncated = true
      break
    }
    commands.push({
      index: i, objectId: `${sliceObjectId}/lc[${i}]`, cmd,
      cmdName: LC_NAMES[cmd] ?? `LC_UNKNOWN(0x${cmd.toString(16)})`,
      cmdsize, offset: qty(off, 'byte', 'slice'), rawHex: hex(bytes, off, Math.min(cmdsize, 32)),
      outOfBounds: false,
    })
    off += cmdsize
  }
  return { status: 'ok', diagnostics, header, commands, truncated }
}

export interface CodeSignatureRef {
  dataoff: number
  datasize: number
  commandObjectId: string
}

export function findCodeSignature(commands: LoadCommandInfo[], bytes: Uint8Array): CodeSignatureRef | null {
  for (const c of commands) {
    if (c.cmd !== 0x1d || c.outOfBounds) continue
    const off = c.offset.value
    if (off + 16 > bytes.length) return null
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
    return {
      dataoff: view.getUint32(off + 8, true),
      datasize: view.getUint32(off + 12, true),
      commandObjectId: c.objectId,
    }
  }
  return null
}
