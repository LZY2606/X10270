/**
 * Mach-O fat 容器解析器（容错）。
 * 设计约束：
 *  - 原始表示完整保留：每个字段保存原始字节、宽度、来源字节序与文件坐标。
 *  - 不因单个损坏而丢弃其余材料：能解析多少保留多少，诊断带位置。
 *  - 不做“四舍五入/吸附”式修正：对齐、重叠只报告，不改写 offset。
 */
import { ByteView, hex32 } from './bytes.js';
import { CS, LC, MAGIC, SEG_LINKEDIT } from './constants.js';
import { fieldSid, sid } from './ids.js';
import { sha256 } from './hash.js';
import type {
  ByteWidth,
  CodeSlot,
  Endian,
  FatArchEntry,
  FatHeader,
  Finding,
  LoadCommand,
  MachSlice,
  ParsedContainer,
  RawField,
  SignatureBlob,
  Unit,
} from './types.js';

const FAT_HEADER_SIZE = 8;
const FAT_ARCH_SIZE = 20;
const MH64_HEADER_SIZE = 32;
const MH32_HEADER_SIZE = 28;

function f(
  parentSid: string,
  view: ByteView,
  name: string,
  off: number,
  widthBytes: number,
  endian: Endian,
  unit: Unit,
  basis: string,
): RawField {
  const value = view.read(off, widthBytes, endian);
  return {
    sid: fieldSid(parentSid, name, off),
    name,
    qty: {
      value,
      unit,
      basis,
      raw: { repr: value === null ? '<unreadable>' : hex32(value), widthBytes, endian },
    },
    fileRange: { start: off, end: off + widthBytes },
  };
}

function finding(init: Finding): Finding {
  return init;
}

function archLabel(cputype: number | null, cpusubtype: number | null): string {
  if (cputype === 0x0100000c && cpusubtype === 0) return 'arm64';
  if (cputype === 0x0100000c && cpusubtype === 2) return 'arm64e';
  if (cputype === 0x01000007 && cpusubtype === 3) return 'x86_64';
  return `cpu(${hex32(cputype ?? 0)},${cpusubtype ?? '?'})`;
}

function parseFatHeader(view: ByteView, out: Finding[]): FatHeader | null {
  const psid = sid('fathdr', view.length);
  const magicBe = view.read(0, 4, 'be');
  let sourceEndian: Endian | null = null;
  let declaredEndian: Endian = 'be';
  if (magicBe === MAGIC.FAT_MAGIC) sourceEndian = 'be';
  else if (magicBe === MAGIC.FAT_CIGAM) {
    sourceEndian = 'le';
    declaredEndian = 'le';
  }
  if (sourceEndian === null) {
    out.push(
      finding({
        code: 'FAT_MAGIC_UNKNOWN',
        severity: 'fatal',
        verdict: 'corrupt',
        message: `fat magic 无法识别：${magicBe === null ? '<unreadable>' : hex32(magicBe)}（既非 0xCAFEBABE 也非字节交换形式）`,
        subjects: [psid],
        evidence: [{ start: 0, end: 4, basis: 'file-base0', hex: view.hex(0, 4) ?? '<oob>' }],
        position: { at: 0, path: 'fat_header.magic' },
        rationale: 'magic ∉ {0xCAFEBABE, 0xBEBAFECA} ⇒ 非通用二进制容器，格式损坏',
      }),
    );
    return null;
  }
  if (sourceEndian === 'le') {
    out.push(
      finding({
        code: 'FAT_MAGIC_SWAPPED',
        severity: 'warning',
        verdict: 'rejected',
        message: 'fat header 整体字节序交换（CIGAM）：声明 little-endian，按平台策略 canonical fat 应为 big-endian',
        subjects: [psid],
        evidence: [{ start: 0, end: 8, basis: 'file-base0', hex: view.hex(0, 8) ?? '<oob>' }],
        position: { at: 0, path: 'fat_header' },
        rationale: 'magic == FAT_CIGAM ⇒ 来源字节序=le；平台 canonical 要求 be，记录但不静默重排字节',
      }),
    );
  }
  const magic = f(psid, view, 'magic', 0, 4, sourceEndian, 'hex16', 'file-base0');
  const nfatArch = f(psid, view, 'nfat_arch', 4, 4, sourceEndian, 'byte', 'file-base0');
  return {
    sid: psid,
    magic,
    nfatArch,
    declaredEndian,
    sourceEndian,
    fields: [magic, nfatArch],
    range: { start: 0, end: FAT_HEADER_SIZE },
  };
}

function parseArchEntries(
  view: ByteView,
  fat: FatHeader,
  maxSlices: number,
  maxFatArchBytes: number,
  out: Finding[],
): FatArchEntry[] {
  const n = fat.nfatArch.qty.value ?? 0;
  const entries: FatArchEntry[] = [];
  const tableBytes = n * FAT_ARCH_SIZE;
  if (n > maxSlices || tableBytes > maxFatArchBytes) {
    out.push(
      finding({
        code: 'FAT_NFAT_OVERFLOW',
        severity: 'fatal',
        verdict: 'budget_exhausted',
        message: `nfat_arch=${n} 超出资源预算（maxSlices=${maxSlices}，fat 表预算=${maxFatArchBytes} 字节）`,
        subjects: [fat.sid],
        evidence: [{ start: 4, end: 8, basis: 'file-base0', hex: view.hex(4, 4) ?? '<oob>' }],
        position: { at: 4, path: 'fat_header.nfat_arch' },
        rationale: `n(${n}) > maxSlices(${maxSlices}) ∨ n*20(${tableBytes}) > maxFatArchBytes(${maxFatArchBytes}) ⇒ 资源预算耗尽`,
      }),
    );
    return entries;
  }
  for (let i = 0; i < n; i++) {
    const base = FAT_HEADER_SIZE + i * FAT_ARCH_SIZE;
    const esid = sid('farch', view.length, i);
    if (!view.has(base, FAT_ARCH_SIZE)) {
      out.push(
        finding({
          code: 'FAT_ARCH_ENTRY_OOB',
          severity: 'fatal',
          verdict: 'corrupt',
          message: `fat_arch[${i}] 条目超出文件（${base}..${base + FAT_ARCH_SIZE}）`,
          subjects: [esid],
          position: { at: base, path: `fat_arch[${i}]` },
          rationale: `[${base},${base + 20}) ⊄ [0,${view.length}) ⇒ 格式损坏`,
        }),
      );
      continue;
    }
    const e = fat.sourceEndian;
    const cputype = f(esid, view, 'cputype', base + 0, 4, e, 'hex16', 'file-base0');
    const cpusubtype = f(esid, view, 'cpusubtype', base + 4, 4, e, 'hex16', 'file-base0');
    const offset = f(esid, view, 'offset', base + 8, 4, e, 'byte', 'file-base0');
    const size = f(esid, view, 'size', base + 12, 4, e, 'byte', 'file-base0');
    const align = f(esid, view, 'align', base + 16, 4, e, 'pow2-unit', 'file-base0');
    const reserved = f(esid, view, 'reserved', base + 16 + 4, 4, e, 'hex16', 'file-base0');
    entries.push({
      sid: esid,
      index: i,
      cputype,
      cpusubtype,
      offset,
      size,
      align,
      reserved,
      range: { start: base, end: base + FAT_ARCH_SIZE },
    });
  }
  return entries;
}

function parseCommands(
  view: ByteView,
  sliceSid: string,
  sliceStart: number,
  lcStart: number,
  ncmds: number,
  sizeofcmds: number,
  endian: Endian,
  out: Finding[],
): LoadCommand[] {
  const cmds: LoadCommand[] = [];
  const tableEndSlice = lcStart - sliceStart + sizeofcmds;
  if (lcStart + sizeofcmds > sliceStart + (view.length - sliceStart) || lcStart - sliceStart + sizeofcmds > view.length - sliceStart) {
    out.push(
      finding({
        code: 'LC_RANGE_TRUNCATED',
        severity: 'error',
        verdict: 'corrupt',
        message: `load command 表声明区间超出切片（slice+${lcStart - sliceStart} 起 ${sizeofcmds} 字节）`,
        subjects: [sliceSid],
        position: { at: lcStart, path: `${sliceSid}.load_commands` },
        rationale: 'header_size + sizeofcmds > slice.size ⇒ load command 范围越界，格式损坏',
      }),
    );
  }
  let cursor = lcStart;
  for (let i = 0; i < ncmds; i++) {
    const csid = sid('lc', sliceSid, i);
    if (!view.has(cursor, 8)) {
      out.push(
        finding({
          code: 'CMD_OUT_OF_BOUNDS',
          severity: 'error',
          verdict: 'corrupt',
          message: `load command[${i}] 头部 8 字节越界（file ${cursor}）`,
          subjects: [csid, sliceSid],
          position: { at: cursor, path: `${sliceSid}.lc[${i}]` },
          rationale: 'cursor + 8 > lc_table_end ⇒ command 越界',
        }),
      );
      break;
    }
    const cmdVal = view.read(cursor, 4, endian);
    const cmdsize = view.read(cursor + 4, 4, endian);
    const cmd = f(csid, view, 'cmd', cursor, 4, endian, 'hex16', 'file-base0');
    const cmdsizeF = f(csid, view, 'cmdsize', cursor + 4, 4, endian, 'byte', 'file-base0');
    if (!cmdsize || cmdsize < 8) {
      out.push(
        finding({
          code: cmdsize === 0 ? 'CMD_ZERO_SIZE' : 'CMD_OUT_OF_BOUNDS',
          severity: 'error',
          verdict: 'corrupt',
          message: `load command[${i}] cmdsize=${cmdsize} 非法（< 8）`,
          subjects: [csid, sliceSid],
          evidence: [{ start: cursor + 4, end: cursor + 8, basis: 'file-base0', hex: view.hex(cursor + 4, 4) ?? '' }],
          position: { at: cursor + 4, path: `${sliceSid}.lc[${i}].cmdsize` },
          rationale: 'cmdsize < 8 ⇒ 格式损坏（不做截断式“修复”）',
        }),
      );
      cmds.push({
        sid: csid, index: i, cmd, cmdsize: cmdsizeF, kind: null,
        sliceRange: { start: cursor - sliceStart, end: cursor - sliceStart + (cmdsize ?? 0) },
        fileRange: { start: cursor, end: cursor + (cmdsize ?? 0) },
      });
      break;
    }
    if (cursor - lcStart + cmdsize > sizeofcmds || !view.has(cursor, cmdsize)) {
      out.push(
        finding({
          code: 'CMD_OUT_OF_BOUNDS',
          severity: 'error',
          verdict: 'corrupt',
          message: `load command[${i}]（cmd=${hex32(cmdVal ?? 0)} size=${cmdsize}）越过 command 表/切片边界`,
          subjects: [csid, sliceSid],
          evidence: [{ start: cursor, end: Math.min(cursor + cmdsize, view.length), basis: 'file-base0', hex: view.hex(cursor, Math.min(8, view.length - cursor)) ?? '' }],
          position: { at: cursor, path: `${sliceSid}.lc[${i}]` },
          rationale: 'cursor + cmdsize > lc_table_end（不靠四舍五入修正）⇒ command 越界',
        }),
      );
    }
    let kind: LoadCommand['kind'] = 'LC_UNKNOWN';
    let segmentName: string | undefined;
    let signature: LoadCommand['signature'];
    let segment: LoadCommand['segment'];
    if (cmdVal === LC.LC_SEGMENT_64) {
      kind = 'LC_SEGMENT_64';
      const nameBytes = view.slice(cursor + 8, 16);
      segmentName = nameBytes ? new TextDecoder().decode(nameBytes).replace(/\0.*$/, '') : undefined;
      segment = {
        vmaddr: f(csid, view, 'vmaddr', cursor + 24, 8, endian, 'byte', `slice-base0:${sliceSid}`),
        vmsize: f(csid, view, 'vmsize', cursor + 32, 8, endian, 'byte', `slice-base0:${sliceSid}`),
        fileoff: f(csid, view, 'fileoff', cursor + 40, 8, endian, 'byte', `slice-base0:${sliceSid}`),
        filesize: f(csid, view, 'filesize', cursor + 48, 8, endian, 'byte', `slice-base0:${sliceSid}`),
      };
      if (segmentName === SEG_LINKEDIT) kind = 'LC_SEGMENT_64';
    } else if (cmdVal === LC.LC_SEGMENT) {
      kind = 'LC_SEGMENT';
    } else if (cmdVal === LC.LC_CODE_SIGNATURE) {
      kind = 'LC_CODE_SIGNATURE';
      signature = {
        dataoff: f(csid, view, 'dataoff', cursor + 8, 4, endian, 'byte', `slice-base0:${sliceSid}`),
        datasize: f(csid, view, 'datasize', cursor + 12, 4, endian, 'byte', `slice-base0:${sliceSid}`),
      };
    } else if (cmdVal === LC.LC_SYMTAB) kind = 'LC_SYMTAB';
    else if (cmdVal === LC.LC_DYSYMTAB) kind = 'LC_DYSYMTAB';
    else if (cmdVal === LC.LC_UUID) kind = 'LC_UUID';
    cmds.push({
      sid: csid, index: i, cmd, cmdsize: cmdsizeF, kind, segmentName, signature, segment,
      sliceRange: { start: cursor - sliceStart, end: cursor - sliceStart + cmdsize },
      fileRange: { start: cursor, end: cursor + cmdsize },
    });
    cursor += cmdsize;
  }
  void tableEndSlice;
  return cmds;
}

function parseSignature(
  view: ByteView,
  sliceSid: string,
  sliceStart: number,
  sliceEnd: number,
  dataoff: number,
  datasize: number,
  endian: Endian,
  out: Finding[],
): SignatureBlob | null {
  const ssid = sid('sig', sliceSid, dataoff, datasize);
  const start = sliceStart + dataoff;
  const end = start + datasize;
  if (dataoff < 0 || datasize <= 0 || end > sliceEnd) {
    out.push(
      finding({
        code: 'SIG_BLOB_TRUNCATED',
        severity: 'error',
        verdict: 'corrupt',
        message: `LC_CODE_SIGNATURE 区间越界（slice+${dataoff} 起 ${datasize} 字节，切片长 ${sliceEnd - sliceStart}）`,
        subjects: [ssid],
        position: { at: start, path: `${sliceSid}.code_signature` },
        rationale: 'sigoff + sigsize > slice.size ⇒ 签名 blob 截断，格式损坏',
      }),
    );
    return null;
  }
  const magicVal = view.read(start, 4, 'be');
  const magic = f(ssid, view, 'signature_magic', start, 4, 'be', 'hex16', `slice-base0:${sliceSid}`);
  const length = f(ssid, view, 'signature_length', start + 4, 4, 'be', 'byte', `slice-base0:${sliceSid}`);
  const count = f(ssid, view, 'signature_count', start + 8, 4, 'be', 'byte', `slice-base0:${sliceSid}`);
  const blobType = f(ssid, view, 'blob_type_0', start + 12, 4, 'be', 'hex16', `slice-base0:${sliceSid}`);
  const base: SignatureBlob = {
    sid: ssid, magic, length, count, blobType,
    sliceRange: { start: dataoff, end: dataoff + datasize },
    fileRange: { start, end },
    codeDirectory: null,
    slots: [],
    known: magicVal === CS.CSMAGIC_EMBEDDED_SIGNATURE,
  };
  if (magicVal !== CS.CSMAGIC_EMBEDDED_SIGNATURE) {
    const known = magicVal === CS.CSMAGIC_CODEDIRECTORY;
    out.push(
      finding({
        code: known ? 'SIG_BLOB_UNSUPPORTED_TYPE' : 'SIG_BLOB_UNKNOWN_MAGIC',
        severity: 'error',
        verdict: 'corrupt',
        message: known
          ? `孤立 CodeDirectory magic ${hex32(magicVal ?? 0)}：缺少 SuperBlob 包裹，不支持的签名格式`
          : `未知签名 blob magic ${magicVal === null ? '<unreadable>' : hex32(magicVal)}，无法解释后续槽位`,
        subjects: [ssid],
        evidence: [{ start, end: Math.min(start + 16, end), basis: 'file-base0', hex: view.hex(start, Math.min(16, end - start)) ?? '' }],
        position: { at: start, path: `${sliceSid}.code_signature.magic` },
        candidates: known
          ? [{ sid: ssid, label: 'CSMAGIC_CODEDIRECTORY（孤立 CodeDirectory，需 SuperBlob）' }]
          : [{ sid: ssid, label: 'unknown-blob：保留原始字节，等待规则/人工决定' }],
        rationale: known
          ? 'magic == CSMAGIC_CODEDIRECTORY 但无 EMBEDDED_SIGNATURE 外层 ⇒ 不支持格式（区别于覆盖缺口/hash 不匹配）'
          : 'magic ∉ 受支持集合 ⇒ 未知 blob，保留为候选，不伪造解析',
      }),
    );
    return base;
  }
  // SuperBlob：首个索引项（type, offset, big-endian）
  const idxType = view.read(start + 12, 4, 'be');
  const cdOffRel = view.read(start + 16, 4, 'be');
  void idxType;
  if (cdOffRel === null || !view.has(start + cdOffRel, 44)) {
    out.push(
      finding({
        code: 'SIG_BLOB_TRUNCATED',
        severity: 'error',
        verdict: 'corrupt',
        message: 'CodeDirectory 索引偏移越界或目录头不足 44 字节',
        subjects: [ssid],
        rationale: 'cd_offset + 44 > sig_end ⇒ blob 截断',
      }),
    );
    return base;
  }
  const cd = start + cdOffRel;
  const cdsid = sid('cdir', ssid);
  const cdMagic = f(cdsid, view, 'cd_magic', cd + 0, 4, 'be', 'hex16', `slice-base0:${sliceSid}`);
  const cdLength = f(cdsid, view, 'cd_length', cd + 4, 4, 'be', 'byte', `slice-base0:${sliceSid}`);
  const cdVersion = f(cdsid, view, 'cd_version', cd + 8, 4, 'be', 'hex16', `slice-base0:${sliceSid}`);
  const cdFlags = f(cdsid, view, 'cd_flags', cd + 12, 4, 'be', 'hex16', `slice-base0:${sliceSid}`);
  const hashType = f(cdsid, view, 'hashType', cd + 16, 4, 'be', 'hex16', `slice-base0:${sliceSid}`);
  const hashOffset = f(cdsid, view, 'hashOffset', cd + 28, 4, 'be', 'byte', `slice-base0:${sliceSid}`);
  const identOffset = f(cdsid, view, 'identOffset', cd + 24, 4, 'be', 'byte', `slice-base0:${sliceSid}`);
  const nSpecialSlots = f(cdsid, view, 'nSpecialSlots', cd + 32, 4, 'be', 'byte', `slice-base0:${sliceSid}`);
  const nCodeSlots = f(cdsid, view, 'nCodeSlots', cd + 36, 4, 'be', 'byte', `page`, `slice-base0:${sliceSid}`);
  const codeLimit = f(cdsid, view, 'codeLimit', cd + 40, 4, 'be', 'byte', `slice-base0:${sliceSid}`);
  const pageSizeExp = f(cdsid, view, 'pageSize', cd + 44, 1, 'be', 'pow2-unit', `slice-base0:${sliceSid}`);
  void cdVersion; void cdFlags; void nSpecialSlots; void endian;
  base.codeDirectory = {
    sid: cdsid, magic: cdMagic, length: cdLength, hashType, pageSize: pageSizeExp, hashOffset, identOffset,
    codeLimit,
    rawFields: [cdMagic, cdLength, cdVersion, cdFlags, hashType, identOffset, hashOffset, nSpecialSlots, nCodeSlots, codeLimit, pageSizeExp],
    sliceRange: { start: cd - sliceStart, end: cd - sliceStart + (cdLength.qty.value ?? 0) },
  };
  // code slots（存储的原始摘要保留）
  const nSlots = nCodeSlots.qty.value ?? 0;
  const hashBytes = hashType.qty.value === CS.CS_HASHTYPE_SHA256 ? 32 : hashType.qty.value === CS.CS_HASHTYPE_SHA256_TRUNCATED ? 20 : 20;
  const hashesStart = cd + (hashOffset.qty.value ?? 0);
  for (let i = 0; i < nSlots; i++) {
    const hOff = hashesStart + i * hashBytes;
    const hex = view.hex(hOff, hashBytes);
    base.slots.push({
      sid: sid('cslot', cdsid, i),
      index: i,
      pageStart: i * 4096,
      pageEnd: (i + 1) * 4096,
      storedDigest: {
        sid: fieldSid(cdsid, `hash[${i}]`, hOff),
        name: `codeSlot[${i}].storedDigest`,
        qty: { value: null, unit: 'sha256-hex', basis: `slice-base0:${sliceSid}`, raw: { repr: hex ?? '<oob>', widthBytes: hashBytes, endian: 'be' } },
        fileRange: { start: hOff, end: hOff + hashBytes },
      },
      computedDigestHex: null,
      match: null,
    });
  }
  return base;
}

function parseSlice(view: ByteView, entry: FatArchEntry, idx: number, out: Finding[]): MachSlice | null {
  const start = entry.offset.qty.value;
  const size = entry.size.qty.value;
  const ssid = sid('slice', entry.sid, start, size);
  if (start === null || size === null || !view.has(start, Math.max(size ?? 0, 4))) {
    out.push(
      finding({
        code: 'SLICE_OUT_OF_FILE',
        severity: 'fatal',
        verdict: 'corrupt',
        message: `slice[${idx}] 数据区间越出文件（offset=${start} size=${size}，文件 ${view.length} 字节）`,
        subjects: [ssid, entry.sid],
        evidence: [{ start: start ?? 0, end: Math.min((start ?? 0) + 8, view.length), basis: 'file-base0', hex: view.hex(start ?? 0, Math.min(8, view.length - (start ?? 0))) ?? '' }],
        position: { at: start ?? 0, path: `fat_arch[${idx}].offset` },
        rationale: '[offset, offset+size) ⊄ [0,file_size) ⇒ 格式损坏',
      }),
    );
    return null;
  }
  const sliceEnd = start + size;
  const magicBe = view.read(start, 4, 'be');
  let width: ByteWidth | null = null;
  let endian: Endian = 'le';
  if (magicBe === MAGIC.MH_MAGIC_64) { width = 64; endian = 'le'; }
  else if (magicBe === MAGIC.MH_CIGAM_64) { width = 64; endian = 'be'; }
  else if (magicBe === MAGIC.MH_MAGIC) { width = 32; endian = 'le'; }
  else if (magicBe === MAGIC.MH_CIGAM) { width = 32; endian = 'be'; }
  const machMagic = f(ssid, view, 'mach_magic', start, 4, 'be', 'hex16', `slice-base0:${ssid}`);
  if (width === null) {
    out.push(
      finding({
        code: 'MACHO_MAGIC_UNKNOWN',
        severity: 'fatal',
        verdict: 'corrupt',
        message: `slice[${idx}] Mach-O magic 未知：${magicBe === null ? '<unreadable>' : hex32(magicBe)}`,
        subjects: [ssid],
        evidence: [{ start, end: Math.min(start + 4, view.length), basis: 'file-base0', hex: view.hex(start, 4) ?? '' }],
        position: { at: start, path: `slice[${idx}].mach_header.magic` },
        rationale: 'magic ∉ {MH_MAGIC[_64], MH_CIGAM[_64]} ⇒ 格式损坏',
      }),
    );
    return null;
  }
  const headerSize = width === 64 ? MH64_HEADER_SIZE : MH32_HEADER_SIZE;
  const ncmds = f(ssid, view, 'ncmds', start + 16, 4, endian, 'byte', `slice-base0:${ssid}`);
  const sizeofcmds = f(ssid, view, 'sizeofcmds', start + 20, 4, endian, 'byte', `slice-base0:${ssid}`);
  if (headerSize + (sizeofcmds.qty.value ?? 0) > size) {
    out.push(
      finding({
        code: 'LC_RANGE_TRUNCATED',
        severity: 'error',
        verdict: 'corrupt',
        message: `slice[${idx}] header(${headerSize}) + sizeofcmds(${sizeofcmds.qty.value}) > slice.size(${size})：load command 范围越界`,
        subjects: [ssid],
        evidence: [{ start: start + 20, end: start + 24, basis: 'file-base0', hex: view.hex(start + 20, 4) ?? '' }],
        position: { at: start + 20, path: `slice[${idx}].mach_header.sizeofcmds` },
        rationale: 'mach_header.size + sizeofcmds > slice.size ⇒ load command 不越界规则被破坏',
      }),
    );
  }
  const commands = parseCommands(
    view, ssid, start, start + headerSize,
    ncmds.qty.value ?? 0, sizeofcmds.qty.value ?? 0, endian, out,
  );
  let signature: SignatureBlob | null = null;
  const csCmd = commands.find((c) => c.kind === 'LC_CODE_SIGNATURE');
  if (csCmd?.signature) {
    signature = parseSignature(
      view, ssid, start, sliceEnd,
      csCmd.signature.dataoff.qty.value ?? 0,
      csCmd.signature.datasize.qty.value ?? 0,
      endian, out,
    );
  } else {
    out.push(
      finding({
        code: 'LC_CODE_SIGNATURE_MISSING',
        severity: 'error',
        verdict: 'rejected',
        message: `slice[${idx}] 缺少 LC_CODE_SIGNATURE load command`,
        subjects: [ssid],
        rationale: 'requireCodeSignature ∧ ∄ LC_CODE_SIGNATURE ⇒ 拒绝',
      }),
    );
  }
  const cputype = entry.cputype.qty.value;
  const cpusubtype = entry.cpusubtype.qty.value;
  return {
    sid: ssid,
    fatIndex: idx,
    arch: { cputype: cputype ?? 0, cpusubtype: cpusubtype ?? 0, label: archLabel(cputype, cpusubtype) },
    machMagic, declaredEndian: endian, sourceEndian: endian, width,
    ncmds, sizeofcmds,
    lcTableRange: { start: headerSize, end: headerSize + (sizeofcmds.qty.value ?? 0) },
    commands, signature,
    sliceRange: { start, end: sliceEnd },
    fields: [machMagic, ncmds, sizeofcmds],
  };
}

export function parseContainer(
  bytes: Uint8Array,
  opts: { maxSlices: number; maxFatArchBytes: number },
): ParsedContainer {
  const view = new ByteView(bytes);
  const out: Finding[] = [];
  const csid = sid('container', sha256(bytes));
  const fat = parseFatHeader(view, out);
  const archEntries: FatArchEntry[] = fat
    ? parseArchEntries(view, fat, opts.maxSlices, opts.maxFatArchBytes, out)
    : [];
  const slices: MachSlice[] = [];
  archEntries.forEach((entry, i) => {
    const start = entry.offset.qty.value;
    const size = entry.size.qty.value;
    if (start !== null && size !== null && start >= 0 && size >= 0 && start + size <= view.length) {
      const s = parseSlice(view, entry, i, out);
      if (s) slices.push(s);
    } else if (fat) {
      // SLICE_OUT_OF_FILE 在 parseSlice 内统一产出；此处确保条目仍被保留为材料
      parseSlice(view, entry, i, out);
    }
  });
  const fields: RawField[] = [];
  if (fat) fields.push(...fat.fields);
  for (const e of archEntries) fields.push(e.cputype, e.cpusubtype, e.offset, e.size, e.align, e.reserved);
  for (const s of slices) {
    fields.push(...s.fields);
    for (const c of s.commands) {
      fields.push(c.cmd, c.cmdsize);
      if (c.signature) fields.push(c.signature.dataoff, c.signature.datasize);
      if (c.segment) fields.push(c.segment.fileoff, c.segment.filesize);
    }
    if (s.signature) {
      fields.push(s.signature.magic, s.signature.length, s.signature.count, s.signature.blobType);
      if (s.signature.codeDirectory) fields.push(...s.signature.codeDirectory.rawFields);
      for (const slot of s.signature.slots) fields.push(slot.storedDigest);
    }
  }
  return { sid: csid, byteLength: bytes.length, fat: fat as FatHeader, archEntries, slices, findings: out, fields };
}

