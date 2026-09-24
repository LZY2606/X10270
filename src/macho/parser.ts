import type {
  ByteEvidence,
  Candidate,
  CoverageBand,
  Coordinate,
  DerivedSnapshot,
  Finding,
  FindingKind,
  LoadCommandView,
  ParseStatus,
  PolicyParams,
  Severity,
  SignatureBlobView,
  SliceView,
  CodeSlotView,
} from '../../shared/types.js';
import { hexFromBytes, sha256Hex, stableId } from '../../shared/bytes.js';
import { ByteReader } from './reader.js';
import {
  archKey,
  archName,
  csMagicName,
  hashAlgorithmName,
  LC,
  loadCommandName,
  MAGIC,
  slotTypeName,
  supportedHashType,
} from './constants.js';
import { CD, SUPERBLOB } from './codedirectory.js';
import { PAGE } from './builder.js';

interface Ctx {
  projectId: string;
  materialId: string;
  params: PolicyParams;
  findings: Finding[];
  severities: SeverityTable;
}

export interface SeverityTable {
  tailGap: Severity;
  hashMismatch: Severity;
  unknownBlob: Severity;
  endianSwap: Severity;
  sliceOverlap: Severity;
  duplicateArch: Severity;
  alignmentOverflow: Severity;
}

export function severityTableFor(params: PolicyParams): SeverityTable {
  const map = { 'allow-as-warning': 'warning', block: 'blocking' } as const;
  return {
    tailGap: map[params.tailGap],
    hashMismatch: map[params.hashMismatch],
    unknownBlob: map[params.unknownBlob],
    endianSwap: 'info',
    sliceOverlap: 'blocking',
    duplicateArch: 'blocking',
    alignmentOverflow: 'blocking',
  };
}

function finding(
  ctx: Ctx,
  kind: FindingKind,
  severity: Severity,
  message: string,
  coordinate: Coordinate,
  extra: Partial<Finding> = {},
): Finding {
  const f: Finding = {
    id: stableId('find', ctx.projectId, ctx.materialId, kind, coordinate.space, coordinate.range.offset, coordinate.range.length, ctx.findings.length),
    kind,
    severity,
    ruleId: `rule:${kind}@${ctx.params.version}`,
    message,
    coordinate,
    ...extra,
  };
  ctx.findings.push(f);
  return f;
}

function evidenceAt(
  bytes: Uint8Array,
  coord: Coordinate,
  expected?: string,
): ByteEvidence {
  const r = coord.range;
  const start = Math.max(0, r.offset - 4);
  return {
    coordinate: coord,
    expectedHex: expected,
    actualHex: hexFromBytes(bytes, r.offset, Math.min(r.length, 32)),
    contextBeforeHex: hexFromBytes(bytes, start, r.offset - start),
    contextAfterHex: hexFromBytes(bytes, r.offset + r.length, 4),
  };
}

interface FatInfo {
  endian: 'big' | 'little';
  swappedMagic: boolean;
  nfat: number;
}

function readFatHeader(reader: ByteReader): FatInfo | null {
  if (reader.length < 8) return null;
  const magic = reader.u32BE(0);
  if (magic === MAGIC.FAT_MAGIC) return { endian: 'big', swappedMagic: false, nfat: reader.u32BE(4) };
  if (magic === MAGIC.FAT_CIGAM) return { endian: 'little', swappedMagic: true, nfat: reader.u32LE(4) };
  return null;
}

function isThinMagic(magic: number): { thin: true; endian: 'big' | 'little' } | null {
  if (magic === MAGIC.MH_MAGIC_64 || magic === MAGIC.MH_MAGIC) return { thin: true, endian: 'big' };
  if (magic === MAGIC.MH_CIGAM_64 || magic === MAGIC.MH_CIGAM) return { thin: true, endian: 'little' };
  return null;
}

export interface ParseInput {
  bytes: Uint8Array;
  materialId: string;
  projectId: string;
  params: PolicyParams;
  eventId: string;
  inputDigest: string;
  adopted: boolean;
}

export function parseUniversal(input: ParseInput): DerivedSnapshot {
  const { bytes, params } = input;
  const severities = severityTableFor(params);
  const ctx: Ctx = {
    projectId: input.projectId,
    materialId: input.materialId,
    params,
    findings: [],
    severities,
  };

  const containerCoord = (offset: number, length: number): Coordinate => ({
    space: 'container',
    range: { offset, length },
    unit: 'byte',
  });

  // Resource budget: three distinct failure classes start here.
  if (bytes.length > params.maxContainerBytes) {
    finding(
      ctx,
      'budget-exhausted',
      'blocking',
      `container ${bytes.length} bytes exceeds resource budget ${params.maxContainerBytes} bytes`,
      containerCoord(params.maxContainerBytes, bytes.length - params.maxContainerBytes),
      {
        failureClass: 'unsupported-format',
        diagnosedValue: `${bytes.length} byte`,
        validRange: `0..${params.maxContainerBytes} byte`,
        evidence: evidenceAt(bytes, containerCoord(params.maxContainerBytes, 4)),
      },
    );
    return finish(input, 'budget-exhausted', ctx, [], [], [], [], []);
  }

  const fat = readFatHeader(new ByteReader(bytes));
  const thin = fat ? null : isThinMagic(new ByteReader(bytes).u32BE(0));

  let slices: SliceView[] = [];
  let commands: LoadCommandView[] = [];
  let signatures: SignatureBlobView[] = [];
  let codeSlots: CodeSlotView[] = [];
  let coverage: CoverageBand[] = [];
  let status: ParseStatus = 'ok';
  let fatHeader: DerivedSnapshot['fat'];

  if (thin) {
    const single = parseSlice(ctx, bytes, 0, bytes.length, {
      cputype: 0,
      cpusubtype: 0,
      declaredAlignment: null,
      forcedEndian: thin.endian,
      index: 0,
      swappedThin: true,
      fromFat: false,
    });
    slices = [single.view];
    commands = single.commands;
    signatures = single.signatures;
    codeSlots = single.codeSlots;
    coverage = single.coverage;
  } else if (fat) {
    const parsed = parseFat(ctx, bytes, fat);
    fatHeader = parsed.fatHeader;
    slices = parsed.slices;
    commands = parsed.commands;
    signatures = parsed.signatures;
    codeSlots = parsed.codeSlots;
    coverage = parsed.coverage;
    status = parsed.status;
  } else {
    finding(
      ctx,
      'format-corrupt',
      'blocking',
      'no fat or Mach-O magic recognized at container offset 0',
      containerCoord(0, 4),
      {
        failureClass: 'unsupported-format',
        evidence: evidenceAt(bytes, containerCoord(0, 4)),
      },
    );
    status = 'format-corrupt';
  }

  status = escalateStatus(ctx, status);
  return finish(input, status, ctx, slices, commands, signatures, codeSlots, coverage, fatHeader);
}

interface SliceParse {
  view: SliceView;
  commands: LoadCommandView[];
  signatures: SignatureBlobView[];
  codeSlots: CodeSlotView[];
  coverage: CoverageBand[];
}

interface FatParse {
  fatHeader: DerivedSnapshot['fat'];
  status: ParseStatus;
  slices: SliceView[];
  commands: LoadCommandView[];
  signatures: SignatureBlobView[];
  codeSlots: CodeSlotView[];
  coverage: CoverageBand[];
}

interface SliceLocation {
  index: number;
  cputype: number;
  cpusubtype: number;
  offset: number;
  size: number;
  alignShift: number;
  fromFat: boolean;
  declaredAlignment: number | null;
  forcedEndian?: 'big' | 'little';
}

function parseFat(
  ctx: Ctx,
  bytes: Uint8Array,
  fat: FatInfo,
): FatParse {
  const reader = new ByteReader(bytes);
  const endian = fat.endian;
  let status: ParseStatus = 'ok';

  if (fat.swappedMagic) {
    finding(
      ctx,
      'endian-fat-swapped',
      ctx.severities.endianSwap,
      'fat header uses FAT_CIGAM (little-endian byte order); entries were decoded in reversed byte order',
      { space: 'container', range: { offset: 0, length: 4 }, unit: 'byte' },
      {
        evidence: evidenceAt(bytes, {
          space: 'container',
          range: { offset: 0, length: 4 },
          unit: 'byte',
        }),
        diagnosedValue: '0xbebafeca (little-endian fat header)',
      },
    );
  }

  if (fat.nfat > ctx.params.maxFatArchs || fat.nfat === 0) {
    finding(
      ctx,
      'format-corrupt',
      'blocking',
      `nfat_arch=${fat.nfat} is zero or exceeds the supported limit ${ctx.params.maxFatArchs}`,
      { space: 'container', range: { offset: 4, length: 4 }, unit: 'byte' },
      {
        failureClass: 'unsupported-format',
        diagnosedValue: `nfat_arch=${fat.nfat}`,
        validRange: `1..${ctx.params.maxFatArchs}`,
      },
    );
    return {
      fatHeader: buildFatHeader(ctx, bytes.length, fat, 8 + fat.nfat * 20),
      slices: [],
      commands: [],
      signatures: [],
      codeSlots: [],
      coverage: [],
      status: 'format-corrupt',
    };
  }

  const archEntryEnd = 8 + fat.nfat * 20;
  if (archEntryEnd > bytes.length) {
    finding(
      ctx,
      'truncated-input',
      'blocking',
      `fat_arch table needs ${archEntryEnd} bytes but container has ${bytes.length}`,
      { space: 'container', range: { offset: bytes.length, length: archEntryEnd - bytes.length }, unit: 'byte' },
      {
        failureClass: 'unsupported-format',
        diagnosedValue: `container=${bytes.length} byte`,
        validRange: `>= ${archEntryEnd} byte`,
      },
    );
    status = 'format-corrupt';
  }

  const locations: SliceLocation[] = [];
  for (let i = 0; i < fat.nfat; i++) {
    const entry = 8 + i * 20;
    const cputype = reader.u32(entry, endian);
    const cpusubtype = reader.u32(entry + 4, endian);
    const offset = reader.u32(entry + 8, endian);
    const size = reader.u32(entry + 12, endian);
    const alignShift = reader.u32(entry + 16, endian);
    locations.push({
      index: i,
      cputype,
      cpusubtype,
      offset,
      size,
      alignShift,
      fromFat: true,
      declaredAlignment: alignShift,
    });
  }

  detectFatGeometries(ctx, bytes, locations);

  const fatHeader = buildFatHeader(ctx, bytes.length, fat, archEntryEnd);
  const collected = deepParseLocations(ctx, bytes, locations);

  // semantic-undecidable can be produced by geometry checks.
  if (hasBlocking(ctx, ['slice-overlap', 'duplicate-arch'])) status = 'semantic-undecidable';
  if (hasBlocking(ctx, ['alignment-overflow', 'slice-out-of-bounds', 'truncated-input', 'command-out-of-bounds', 'sig-unsupported-format', 'format-corrupt'])) {
    status = 'format-corrupt';
  }
  if (collected.anySliceDeepFormatError) status = 'format-corrupt';

  return {
    fatHeader,
    slices: collected.slices,
    commands: collected.commands,
    signatures: collected.signatures,
    codeSlots: collected.codeSlots,
    coverage: collected.coverage,
    status,
  };
}

function buildFatHeader(ctx: Ctx, byteLength: number, fat: FatInfo, archEntryEnd: number): DerivedSnapshot['fat'] {
  const magic = fat.swappedMagic ? MAGIC.FAT_CIGAM : MAGIC.FAT_MAGIC;
  return {
    id: stableId('fathdr', ctx.projectId, ctx.materialId),
    magicHex: `0x${magic.toString(16).padStart(8, '0')}`,
    magicName: fat.swappedMagic ? 'FAT_CIGAM' : 'FAT_MAGIC',
    endianness: fat.endian,
    nfatArch: fat.nfat,
    headerRange: { offset: 0, length: 8 },
    archEntryRange: { offset: 8, length: archEntryEnd - 8 },
    byteLength,
  };
}

function archEntryCoord(index: number, fieldOffset: number, length: number): Coordinate {
  return {
    space: 'container',
    range: { offset: 8 + index * 20 + fieldOffset, length },
    unit: 'byte',
  };
}

function detectFatGeometries(ctx: Ctx, bytes: Uint8Array, locs: SliceLocation[]): void {
  const byArch = new Map<string, SliceLocation[]>();

  locs.forEach((loc) => {
    // alignment: shift values that cannot be converted stay in place.
    if (loc.alignShift >= 32) {
      finding(
        ctx,
        'alignment-overflow',
        ctx.severities.alignmentOverflow,
        `slice #${loc.index} fat_arch align=2^${loc.alignShift} overflows the 32-bit address space; alignment is not rounded away`,
        archEntryCoord(loc.index, 16, 4),
        {
          failureClass: 'unsupported-format',
          diagnosedValue: `align=2^${loc.alignShift} byte`,
          validRange: 'align exponent 0..31',
        },
      );
    } else if (Number.isSafeInteger(loc.offset)) {
      const alignment = 1 << loc.alignShift;
      if (loc.offset % alignment !== 0) {
        finding(
          ctx,
          'slice-misaligned',
          'warning',
          `slice #${loc.index} offset 0x${loc.offset.toString(16)} is not a multiple of declared 2^${loc.alignShift}=${alignment} bytes`,
          archEntryCoord(loc.index, 16, 4),
          {
            diagnosedValue: `offset=${loc.offset} byte, align=${alignment} byte, remainder=${loc.offset % alignment} byte`,
            validRange: `offset mod ${alignment} = 0`,
          },
        );
      }
    }

    // slice must be fully inside the container.
    if (loc.offset + loc.size > bytes.length || loc.size === 0) {
      finding(
        ctx,
        'slice-out-of-bounds',
        'blocking',
        `slice #${loc.index} [0x${loc.offset.toString(16)}, +0x${loc.size.toString(16)}) exceeds container length ${bytes.length} bytes`,
        archEntryCoord(loc.index, 8, 12),
        {
          failureClass: 'unsupported-format',
          diagnosedValue: `end=${loc.offset + loc.size} byte`,
          validRange: `end <= ${bytes.length} byte`,
        },
      );
    }

    const key = archKey(loc.cputype, loc.cpusubtype);
    const list = byArch.get(key) ?? [];
    list.push(loc);
    byArch.set(key, list);
  });

  // overlap: undecidable geometry, keep all legal candidate slices.
  for (let a = 0; a < locs.length; a++) {
    for (let b = a + 1; b < locs.length; b++) {
      const x = locs[a]!;
      const y = locs[b]!;
      const start = Math.max(x.offset, y.offset);
      const end = Math.min(x.offset + x.size, y.offset + y.size);
      if (start < end) {
        const candidates: Candidate[] = [x, y].map((s) => ({
          sliceId: stableId('slice', ctx.projectId, ctx.materialId, s.index),
          archKey: archKey(s.cputype, s.cpusubtype),
          reason: `slice #${s.index} @0x${s.offset.toString(16)} is a legal container range but overlaps the other slice`,
        }));
        finding(
          ctx,
          'slice-overlap',
          ctx.severities.sliceOverlap,
          `slices #${x.index} and #${y.index} overlap on [0x${start.toString(16)}, 0x${end.toString(16)}); no unique mapping exists`,
          { space: 'container', range: { offset: start, length: end - start }, unit: 'byte' },
          {
            candidates,
            diagnosedValue: `overlap=${end - start} byte`,
            validRange: 'slice ranges must be disjoint',
          },
        );
      }
    }
  }

  // duplicate architecture: ambiguous policy target.
  for (const [key, list] of byArch) {
    if (list.length > 1) {
      finding(
        ctx,
        'duplicate-arch',
        ctx.severities.duplicateArch,
        `architecture ${archName(list[0]!.cputype, list[0]!.cpusubtype)} (${key}) appears in ${list.length} slices; target policy cannot choose one`,
        archEntryCoord(list[0]!.index, 0, 8),
        {
          failureClass: 'unsupported-format',
          candidates: list.map((s) => ({
            sliceId: stableId('slice', ctx.projectId, ctx.materialId, s.index),
            archKey: key,
            reason: `slice #${s.index} @0x${s.offset.toString(16)} claims the same cputype/cpusubtype`,
          })),
          diagnosedValue: key,
          validRange: 'one slice per target architecture',
        },
      );
    }
  }
}

interface DeepCollection {
  slices: SliceView[];
  commands: LoadCommandView[];
  signatures: SignatureBlobView[];
  codeSlots: CodeSlotView[];
  coverage: CoverageBand[];
  anySliceDeepFormatError: boolean;
}

function deepParseLocations(
  ctx: Ctx,
  bytes: Uint8Array,
  locs: SliceLocation[],
): DeepCollection {
  const out: DeepCollection = {
    slices: [],
    commands: [],
    signatures: [],
    codeSlots: [],
    coverage: [],
    anySliceDeepFormatError: false,
  };
  const overlapping = new Set<number>();
  ctx.findings
    .filter((f) => f.kind === 'slice-overlap')
    .forEach((f) => f.candidates?.forEach((c) => {
      const match = c.sliceId.match(/-(\d+)$/);
      if (match) overlapping.add(Number(match[1]));
    }));

  for (const loc of locs) {
    // When slices overlap, parsing the shared bytes as a header is not unique;
    // the geometry finding already carries all legal candidates.
    const blocked = overlapping.has(loc.index) || loc.offset + loc.size > bytes.length;
    if (blocked) {
      out.slices.push(buildSliceView(ctx, bytes, loc, { unparseable: true }));
      continue;
    }
    const sliceBytes = bytes.subarray(loc.offset, loc.offset + loc.size);
    const parsed = parseSlice(ctx, sliceBytes, loc.offset, loc.size, {
      cputype: loc.cputype,
      cpusubtype: loc.cpusubtype,
      declaredAlignment: loc.alignShift,
      index: loc.index,
      swappedThin: false,
      fromFat: true,
    });
    out.slices.push(parsed.view);
    out.commands.push(...parsed.commands);
    out.signatures.push(...parsed.signatures);
    out.codeSlots.push(...parsed.codeSlots);
    out.coverage.push(...parsed.coverage);
    if (ctx.findings.some((f) =>
      f.severity === 'blocking' &&
      ['command-out-of-bounds', 'sig-unsupported-format', 'format-corrupt', 'truncated-input'].includes(f.kind) &&
      f.coordinate.sliceId === parsed.view.id,
    )) {
      out.anySliceDeepFormatError = true;
    }
  }
  return out;
}

function sliceId(ctx: Ctx, index: number): string {
  return stableId('slice', ctx.projectId, ctx.materialId, index);
}

function sliceCoord(sid: string, offset: number, length: number): Coordinate {
  return { space: 'slice', sliceId: sid, range: { offset, length }, unit: 'byte' };
}

function buildSliceView(
  ctx: Ctx,
  bytes: Uint8Array,
  loc: SliceLocation,
  flags: { unparseable?: boolean } = {},
): SliceView {
  const sid = sliceId(ctx, loc.index);
  const overflow = loc.fromFat && loc.alignShift >= 32;
  const alignBytes = loc.fromFat && !overflow ? 1 << loc.alignShift : null;
  const magicHex =
    loc.offset + 4 <= bytes.length
      ? `0x${new ByteReader(bytes).hex(loc.offset, 4)}`
      : '(unavailable)';
  return {
    id: sid,
    archKey: archKey(loc.cputype, loc.cpusubtype),
    cputype: loc.cputype,
    cpusubtype: loc.cpusubtype,
    archName: archName(loc.cputype, loc.cpusubtype),
    endianness: loc.forcedEndian ?? 'big',
    offset: loc.offset,
    declaredSize: loc.size,
    actualSize: Math.max(0, Math.min(loc.size, bytes.length - loc.offset)),
    alignmentShift: loc.alignShift,
    alignmentBytes: alignBytes,
    alignmentOverflow: overflow,
    magicHex,
    machHeaderRange: { offset: 0, length: 32 },
    unconvertible: flags.unparseable
      ? {
          field: 'slice-header',
          rawValue: magicHex,
          reason: 'slice bytes not uniquely addressable (overlap or out of bounds)',
        }
      : undefined,
  };
}

interface SliceMeta {
  cputype: number;
  cpusubtype: number;
  declaredAlignment: number | null;
  forcedEndian?: 'big' | 'little';
  index: number;
  swappedThin: boolean;
  fromFat: boolean;
}

function parseSlice(
  ctx: Ctx,
  sliceBytes: Uint8Array,
  containerOffset: number,
  declaredSize: number,
  meta: SliceMeta,
): SliceParse {
  const reader = new ByteReader(sliceBytes);
  const sid = sliceId(ctx, meta.index);
  const commands: LoadCommandView[] = [];
  const signatures: SignatureBlobView[] = [];
  const codeSlots: CodeSlotView[] = [];
  const coverage: CoverageBand[] = [];

  const magic = reader.length >= 4 ? reader.u32BE(0) : 0;
  const thinInfo = isThinMagic(magic);
  const endian: 'big' | 'little' = thinInfo?.endian ?? (meta.forcedEndian ?? 'big');
  const is64 = magic === MAGIC.MH_MAGIC_64 || magic === MAGIC.MH_CIGAM_64;

  const view: SliceView = {
    id: sid,
    archKey: archKey(meta.cputype, meta.cpusubtype),
    cputype: meta.cputype,
    cpusubtype: meta.cpusubtype,
    archName: meta.fromFat ? archName(meta.cputype, meta.cpusubtype) : `thin:${archName(meta.cputype, meta.cpusubtype)}`,
    endianness: endian,
    offset: containerOffset,
    declaredSize,
    actualSize: sliceBytes.length,
    alignmentShift: meta.declaredAlignment ?? 0,
    alignmentBytes: meta.declaredAlignment === null ? null : 1 << (meta.declaredAlignment ?? 0),
    magicHex: reader.length >= 4 ? `0x${reader.hex(0, 4)}` : '(truncated)',
    machHeaderRange: { offset: 0, length: is64 ? 32 : 28 },
  };

  if (!thinInfo) {
    finding(
      ctx,
      'format-corrupt',
      'blocking',
      `slice #${meta.index} does not begin with a Mach-O magic`,
      sliceCoord(sid, 0, Math.min(4, reader.length)),
      { failureClass: 'unsupported-format', evidence: evidenceAt(sliceBytes, sliceCoord(sid, 0, 4)) },
    );
    return { view, commands, signatures, codeSlots, coverage };
  }

  if (endian === 'little') {
    finding(
      ctx,
      'endian-slice-swapped',
      ctx.severities.endianSwap,
      `slice #${meta.index} (${view.archName}) uses reverse byte order magic ${view.magicHex}; header fields decoded little-endian`,
      sliceCoord(sid, 0, 4),
      { diagnosedValue: view.magicHex },
    );
  }

  if (!is64) {
    finding(
      ctx,
      'format-corrupt',
      'blocking',
      `slice #${meta.index} is a 32-bit Mach-O (0x${magic.toString(16)}); this reviewer supports 64-bit slices only`,
      sliceCoord(sid, 0, 4),
      { failureClass: 'unsupported-format' },
    );
    return { view, commands, signatures, codeSlots, coverage };
  }

  if (reader.length < 32) {
    finding(
      ctx,
      'truncated-input',
      'blocking',
      `slice #${meta.index} header needs 32 bytes, has ${reader.length}`,
      sliceCoord(sid, reader.length, 32 - reader.length),
      { failureClass: 'unsupported-format' },
    );
    return { view, commands, signatures, codeSlots, coverage };
  }

  // Prefer the header's own cputype when available.
  const headerCpu = reader.u32(4, endian);
  const headerSub = reader.u32(8, endian);
  if (!meta.fromFat || meta.swappedThin) {
    view.cputype = headerCpu;
    view.cpusubtype = headerSub;
    view.archKey = archKey(headerCpu, headerSub);
    view.archName = archName(headerCpu, headerSub);
  }

  const ncmds = reader.u32(16, endian);
  const sizeofcmds = reader.u32(20, endian);
  parseLoadCommands(ctx, reader, sid, endian, ncmds, sizeofcmds, sliceBytes.length, commands);

  const codesig = commands.find((c) => c.cmd === LC.LC_CODE_SIGNATURE);
  if (codesig && codesig.details) {
    const dataoff = Number(codesig.details.dataoff);
    const datasize = Number(codesig.details.datasize);
    parseSignature(ctx, sliceBytes, sid, dataoff, datasize, signatures, codeSlots, coverage);
  } else {
    // No code signature at all: whole slice is a coverage gap.
    coverage.push({
      id: stableId('band', sid, 'gap', 0),
      sliceId: sid,
      kind: 'uncovered-tail',
      offset: 0,
      length: sliceBytes.length,
      label: 'unsigned slice: no LC_CODE_SIGNATURE',
    });
    finding(
      ctx,
      'sig-tail-uncovered',
      ctx.severities.tailGap,
      `slice #${meta.index} (${view.archName}) has no LC_CODE_SIGNATURE; nothing attests the bytes`,
      sliceCoord(sid, 0, sliceBytes.length),
      { failureClass: 'coverage-gap', diagnosedValue: 'attested=0 byte', validRange: `attested=${sliceBytes.length} byte` },
    );
  }

  return { view, commands, signatures, codeSlots, coverage };
}

function parseLoadCommands(
  ctx: Ctx,
  reader: ByteReader,
  sid: string,
  endian: 'big' | 'little',
  ncmds: number,
  sizeofcmds: number,
  sliceLength: number,
  commands: LoadCommandView[],
): void {
  const headerSize = 32;
  const claimedEnd = headerSize + sizeofcmds;

  if (ncmds > ctx.params.maxLoadCommandsPerSlice) {
    finding(
      ctx,
      'command-out-of-bounds',
      'blocking',
      `slice declares ${ncmds} load commands, limit is ${ctx.params.maxLoadCommandsPerSlice}`,
      sliceCoord(sid, 16, 4),
      { failureClass: 'unsupported-format', diagnosedValue: `ncmds=${ncmds}` },
    );
  }

  // The declared load-command region itself must stay inside the slice.
  if (claimedEnd > sliceLength) {
    finding(
      ctx,
      'command-out-of-bounds',
      'blocking',
      `load command region ends at ${claimedEnd} bytes, beyond slice length ${sliceLength} bytes`,
      sliceCoord(sid, sliceLength, claimedEnd - sliceLength),
      {
        failureClass: 'unsupported-format',
        diagnosedValue: `region-end=${claimedEnd} byte`,
        validRange: `<= ${sliceLength} byte`,
        evidence: evidenceAt(reader.bytes, sliceCoord(sid, sliceLength, Math.min(8, claimedEnd - sliceLength))),
      },
    );
  }

  let cursor = headerSize;
  for (let i = 0; i < ncmds; i++) {
    if (cursor + 8 > Math.min(claimedEnd, sliceLength)) {
      finding(
        ctx,
        'command-out-of-bounds',
        'blocking',
        `load command #${i} header would start at ${cursor} bytes outside the declared command region [32, ${claimedEnd})`,
        sliceCoord(sid, cursor, Math.max(0, claimedEnd - cursor)),
        {
          failureClass: 'unsupported-format',
          diagnosedValue: `offset=${cursor} byte`,
          validRange: `< ${claimedEnd} byte`,
          evidence: evidenceAt(reader.bytes, sliceCoord(sid, Math.min(cursor, sliceLength), 8)),
        },
      );
      break;
    }
    const cmd = reader.u32(cursor, endian);
    const cmdsize = reader.u32(cursor + 4, endian);
    const cmdEnd = cursor + cmdsize;
    if (cmdsize < 8 || cmdEnd > claimedEnd) {
      finding(
        ctx,
        'command-out-of-bounds',
        'blocking',
        `load command #${i} (${loadCommandName(cmd)}) claims ${cmdsize} bytes at offset ${cursor}, crossing the declared region end ${claimedEnd}`,
        sliceCoord(sid, cursor, Math.max(8, Math.min(cmdsize, claimedEnd - cursor))),
        {
          failureClass: 'unsupported-format',
          diagnosedValue: `cmdsize=${cmdsize} byte, region-end=${claimedEnd} byte`,
          validRange: `cmd-end <= ${claimedEnd} byte`,
          evidence: evidenceAt(reader.bytes, sliceCoord(sid, cursor, 8)),
        },
      );
      break;
    }
    const view: LoadCommandView = {
      id: stableId('lc', sid, i),
      sliceId: sid,
      index: i,
      cmd,
      cmdName: loadCommandName(cmd),
      cmdsize,
      offset: cursor,
      range: { offset: cursor, length: cmdsize },
    };
    if (cmd === LC.LC_CODE_SIGNATURE && cmdsize >= 16) {
      view.details = {
        dataoff: String(reader.u32(cursor + 8, endian)),
        datasize: String(reader.u32(cursor + 12, endian)),
      };
    }
    if (cmd === LC.LC_SEGMENT_64 && cmdsize >= 56) {
      const nameBytes = reader.bytes.subarray(cursor + 8, cursor + 24);
      const nul = nameBytes.indexOf(0);
      const dv = new DataView(reader.bytes.buffer, reader.bytes.byteOffset + cursor, 72);
      view.details = {
        segname: new TextDecoder().decode(nameBytes.subarray(0, nul < 0 ? 16 : nul)),
        fileoff: String(dv.getBigUint64(40, endian === 'little')),
        filesize: String(dv.getBigUint64(48, endian === 'little')),
      };
    }
    commands.push(view);
    cursor = cmdEnd;
  }
}

function parseSignature(
  ctx: Ctx,
  sliceBytes: Uint8Array,
  sid: string,
  dataoff: number,
  datasize: number,
  signatures: SignatureBlobView[],
  codeSlots: CodeSlotView[],
  coverage: CoverageBand[],
): void {
  if (dataoff + datasize > sliceBytes.length) {
    finding(
      ctx,
      'command-out-of-bounds',
      'blocking',
      `LC_CODE_SIGNATURE data [${dataoff}, +${datasize}) exceeds slice length ${sliceBytes.length} bytes`,
      sliceCoord(sid, dataoff, Math.min(datasize, sliceBytes.length - dataoff)),
      { failureClass: 'unsupported-format' },
    );
    return;
  }

  const sig = sliceBytes.subarray(dataoff, dataoff + datasize);
  const sigReader = new ByteReader(sig);
  if (sig.length < 12) {
    finding(
      ctx,
      'sig-unsupported-format',
      'blocking',
      `signature region is only ${sig.length} bytes (SuperBlob header needs 12)`,
      sliceCoord(sid, dataoff, datasize),
      { failureClass: 'unsupported-format' },
    );
    return;
  }

  const magic = sigReader.u32BE(SUPERBLOB.magic);
  const length = sigReader.u32BE(SUPERBLOB.length);
  const count = sigReader.u32BE(SUPERBLOB.count);

  if (magic !== 0xfade0cc0) {
    finding(
      ctx,
      'sig-unsupported-format',
      'blocking',
      `signature magic 0x${magic.toString(16).padStart(8, '0')} is not CSMAGIC_EMBEDDED_SIGNATURE (0xfade0cc0)`,
      sliceCoord(sid, dataoff, 4),
      {
        failureClass: 'unsupported-format',
        diagnosedValue: `magic=0x${magic.toString(16)}`,
        validRange: 'magic=0xfade0cc0',
        evidence: {
          coordinate: sliceCoord(sid, dataoff, 4),
          actualHex: hexFromBytes(sig, 0, 4),
        },
      },
    );
    return;
  }
  if (length !== datasize) {
    finding(
      ctx,
      'command-out-of-bounds',
      'blocking',
      `SuperBlob length ${length} disagrees with LC_CODE_SIGNATURE datasize ${datasize}`,
      sliceCoord(sid, dataoff + 4, 4),
      { failureClass: 'unsupported-format', diagnosedValue: `length=${length} byte, datasize=${datasize} byte` },
    );
  }

  if (12 + count * 8 > datasize) {
    finding(
      ctx,
      'sig-unsupported-format',
      'blocking',
      `SuperBlob index claims ${count} blobs needing ${12 + count * 8} bytes inside a ${datasize}-byte region`,
      sliceCoord(sid, dataoff + 8, 4),
      { failureClass: 'unsupported-format' },
    );
    return;
  }

  let codeDirectory: { offset: number; blobLength: number } | null = null;

  for (let i = 0; i < count; i++) {
    const entry = SUPERBLOB.entriesStart + i * SUPERBLOB.entrySize;
    const slotType = sigReader.u32BE(entry);
    const blobOffset = sigReader.u32BE(entry + 4);
    if (blobOffset + 8 > datasize) {
      finding(
        ctx,
        'sig-unsupported-format',
        'blocking',
        `blob index #${i} points at offset ${blobOffset} outside the ${datasize}-byte signature`,
        sliceCoord(sid, dataoff + entry, 8),
        { failureClass: 'unsupported-format' },
      );
      continue;
    }
    const blobMagic = sigReader.u32BE(blobOffset);
    const blobLength = sigReader.u32BE(blobOffset + 4);
    const known = isKnownCsMagic(blobMagic);
    const magicName = csMagicName(blobMagic);
    signatures.push({
      id: stableId('blob', sid, i, blobOffset),
      sliceId: sid,
      magicHex: `0x${blobMagic.toString(16).padStart(8, '0')}`,
      magicName,
      slotType,
      blobOffset,
      length: blobLength,
      range: { offset: blobOffset, length: Math.min(blobLength, datasize - blobOffset) },
      supported: known,
    });

    if (!known) {
      finding(
        ctx,
        'sig-unknown-blob',
        ctx.severities.unknownBlob,
        `blob slot ${slotType} (${slotTypeName(slotType)}) at signature offset ${blobOffset} has unknown magic 0x${blobMagic.toString(16).padStart(8, '0')}`,
        sliceCoord(sid, dataoff + blobOffset, 8),
        {
          failureClass: 'unsupported-format',
          diagnosedValue: `magic=0x${blobMagic.toString(16)}, slot=${slotType}`,
          evidence: {
            coordinate: sliceCoord(sid, dataoff + blobOffset, 8),
            actualHex: hexFromBytes(sig, blobOffset, 8),
          },
        },
      );
    }

    if (blobMagic === 0xfade0c02) codeDirectory = { offset: blobOffset, blobLength };
  }

  if (!codeDirectory) {
    finding(
      ctx,
      'sig-unsupported-format',
      'blocking',
      'SuperBlob contains no CSMAGIC_CODEDIRECTORY blob; code slots cannot be evaluated',
      sliceCoord(sid, dataoff, datasize),
      { failureClass: 'unsupported-format' },
    );
    coverageForSlice(sliceBytes, sid, dataoff, 0, coverage);
    pushSignatureBand(sid, dataoff, datasize, coverage);
    return;
  }

  evaluateCodeDirectory(ctx, sliceBytes, sig, sid, codeDirectory.offset, codeDirectory.blobLength, signatures, codeSlots, coverage, dataoff, datasize);
}

function pushSignatureBand(sid: string, dataoff: number, datasize: number, coverage: CoverageBand[]): void {
  coverage.push({
    id: stableId('band', sid, 'sig', dataoff),
    sliceId: sid,
    kind: 'signature',
    offset: dataoff,
    length: datasize,
    label: `embedded code signature (${datasize} byte)`,
  });
}

function isKnownCsMagic(magic: number): boolean {
  return new Set<number>([
    0xfade0c01, 0xfade0c02, 0xfade0c05, 0xfade7171, 0xfade7172, 0xfade0b01,
  ]).has(magic);
}

function evaluateCodeDirectory(
  ctx: Ctx,
  sliceBytes: Uint8Array,
  sig: Uint8Array,
  sid: string,
  cdOffset: number,
  cdLength: number,
  signatures: SignatureBlobView[],
  codeSlots: CodeSlotView[],
  coverage: CoverageBand[],
  sigDataoff: number,
  sigDatasize: number,
): void {
  const reader = new ByteReader(sig);
  if (cdOffset + 40 > sig.length) {
    finding(ctx, 'sig-unsupported-format', 'blocking', 'CodeDirectory header truncated', sliceCoord(sid, sigDataoff + cdOffset, cdLength), { failureClass: 'unsupported-format' });
    return;
  }
  const hashOffset = reader.u32BE(cdOffset + CD.hashOffset);
  const identOffset = reader.u32BE(cdOffset + CD.identOffset);
  const nSpecial = reader.u32BE(cdOffset + CD.nSpecialSlots);
  const nCodeSlots = reader.u32BE(cdOffset + CD.nCodeSlots);
  const codeLimit = reader.u32BE(cdOffset + CD.codeLimit);
  const hashSize = sig[cdOffset + CD.hashSize]!;
  const hashType = sig[cdOffset + CD.hashType]!;
  const pageLog = sig[cdOffset + CD.pageSize]!;
  const pageSize = 1 << pageLog;

  const blob = signatures.find((b) => b.blobOffset === cdOffset);
  if (blob) {
    blob.codeLimit = codeLimit;
    blob.pageSize = pageSize;
    blob.nCodeSlots = nCodeSlots;
    blob.hashSize = hashSize;
    blob.hashType = hashType;
  }
  void identOffset;
  void nSpecial;
  void cdLength;

  if (!supportedHashType(hashType, hashSize)) {
    finding(
      ctx,
      'sig-unsupported-format',
      'blocking',
      `CodeDirectory hash ${hashAlgorithmName(hashType, hashSize)} (type=${hashType}, size=${hashSize}) is not supported by this reviewer`,
      sliceCoord(sid, sigDataoff + cdOffset + CD.hashSize, 2),
      { failureClass: 'unsupported-format', diagnosedValue: `hashType=${hashType}, hashSize=${hashSize} byte` },
    );
    coverageForSlice(sliceBytes, sid, sigDataoff, codeLimit, coverage);
    pushSignatureBand(sid, sigDataoff, sigDatasize, coverage);
    return;
  }

  const slotStart = cdOffset + hashOffset;
  let mismatch = false;
  for (let i = 0; i < nCodeSlots; i++) {
    const slotPos = slotStart + i * hashSize;
    const recorded = hexFromBytes(sig, slotPos, hashSize);
    const codeStart = i * pageSize;
    const len = Math.min(pageSize, codeLimit - codeStart);
    const actual = len > 0 ? sha256Hex(sliceBytes.subarray(codeStart, codeStart + len)) : '';
    const matches = hashType === 3 ? actual === recorded : truncate(actual, hashSize) === recorded;
    if (!matches) mismatch = true;
    codeSlots.push({
      id: stableId('slot', sid, i),
      sliceId: sid,
      index: i,
      offset: codeStart,
      length: len,
      recordedDigestHex: recorded,
      actualDigestHex: actual,
      digestAlgorithm: hashAlgorithmName(hashType, hashSize),
      matches,
    });
    if (!matches) {
      finding(
        ctx,
        'sig-hash-mismatch',
        ctx.severities.hashMismatch,
        `code slot ${i} @slice+0x${codeStart.toString(16)} actual ${hashAlgorithmName(hashType, hashSize)} does not match the recorded CodeDirectory digest`,
        sliceCoord(sid, codeStart, len),
        {
          failureClass: 'hash-mismatch',
          diagnosedValue: `expected=${recorded.slice(0, 16)}… actual=${actual.slice(0, 16)}…`,
          evidence: {
            coordinate: sliceCoord(sid, codeStart, Math.min(len, 32)),
            expectedHex: recorded.slice(0, 32),
            actualHex: hexFromBytes(sliceBytes, codeStart, 32),
          },
        },
      );
    }
  }

  coverageForSlice(sliceBytes, sid, sigDataoff, codeLimit, coverage);
  pushSignatureBand(sid, sigDataoff, sigDatasize, coverage);

  // Tail gap: bytes between the attested region and the signature blob.
  if (codeLimit < sigDataoff) {
    const gap = sigDataoff - codeLimit;
    finding(
      ctx,
      'sig-tail-uncovered',
      ctx.severities.tailGap,
      `code signature covers [0, 0x${codeLimit.toString(16)}); ${gap} bytes of non-signature tail before the blob are not covered by any code slot`,
      sliceCoord(sid, codeLimit, gap),
      {
        failureClass: 'coverage-gap',
        diagnosedValue: `uncovered=${gap} byte @slice+0x${codeLimit.toString(16)}`,
        validRange: 'codeLimit must equal signature dataoff',
        evidence: {
          coordinate: sliceCoord(sid, codeLimit, Math.min(gap, 32)),
          actualHex: hexFromBytes(sliceBytes, codeLimit, Math.min(gap, 32)),
        },
      },
    );
  }
  void mismatch;
}

function truncate(hex: string, hashSize: number): string {
  return hex.slice(0, hashSize * 2);
}

function coverageForSlice(
  sliceBytes: Uint8Array,
  sid: string,
  sigDataoff: number,
  codeLimit: number,
  coverage: CoverageBand[],
): void {
  const n = Math.ceil(codeLimit / PAGE);
  for (let i = 0; i < n; i++) {
    const start = i * PAGE;
    const len = Math.min(PAGE, codeLimit - start);
    coverage.push({
      id: stableId('band', sid, 'code', i),
      sliceId: sid,
      kind: 'hashed-code',
      offset: start,
      length: len,
      label: `code slot ${i} (${len} byte)`,
    });
  }
  if (codeLimit < sigDataoff) {
    coverage.push({
      id: stableId('band', sid, 'gap', codeLimit),
      sliceId: sid,
      kind: 'uncovered-tail',
      offset: codeLimit,
      length: sigDataoff - codeLimit,
      label: `uncovered tail (${sigDataoff - codeLimit} byte)`,
    });
  }
}

function hasBlocking(ctx: Ctx, kinds: FindingKind[]): boolean {
  return ctx.findings.some((f) => f.severity === 'blocking' && kinds.includes(f.kind));
}

function escalateStatus(ctx: Ctx, current: ParseStatus): ParseStatus {
  if (current !== 'ok') return current;
  if (hasBlocking(ctx, ['budget-exhausted'])) return 'budget-exhausted';
  if (hasBlocking(ctx, ['slice-overlap', 'duplicate-arch'])) return 'semantic-undecidable';
  if (
    hasBlocking(ctx, [
      'alignment-overflow',
      'slice-out-of-bounds',
      'command-out-of-bounds',
      'sig-unsupported-format',
      'format-corrupt',
      'truncated-input',
    ])
  ) {
    return 'format-corrupt';
  }
  if (hasBlocking(ctx, ['sig-tail-uncovered'])) return 'format-corrupt';
  if (hasBlocking(ctx, ['sig-hash-mismatch', 'sig-unknown-blob'])) return 'format-corrupt';
  return 'ok';
}

function finish(
  input: ParseInput,
  status: ParseStatus,
  ctx: Ctx,
  slices: SliceView[],
  commands: LoadCommandView[],
  signatures: SignatureBlobView[],
  codeSlots: CodeSlotView[],
  coverage: CoverageBand[],
  fat?: DerivedSnapshot['fat'],
): DerivedSnapshot {
  return {
    id: stableId('snap', input.projectId, input.materialId, input.params.version, input.eventId),
    eventId: input.eventId,
    materialId: input.materialId,
    paramsVersion: input.params.version,
    inputDigest: input.inputDigest,
    status,
    adopted: input.adopted,
    fat,
    slices,
    commands,
    signatures,
    codeSlots,
    coverage,
    findings: sortFindings(ctx.findings),
  };
}

export function sortFindings(findings: Finding[]): Finding[] {
  // Equivalent inputs get a stable order: space, offset, kind, id.
  const spaceRank = { container: 0, slice: 1, signature: 2 };
  return [...findings].sort((a, b) => {
    const sa = spaceRank[a.coordinate.space];
    const sb = spaceRank[b.coordinate.space];
    if (sa !== sb) return sa - sb;
    if (a.coordinate.range.offset !== b.coordinate.range.offset) {
      return a.coordinate.range.offset - b.coordinate.range.offset;
    }
    if (a.kind !== b.kind) return a.kind.localeCompare(b.kind);
    return a.id.localeCompare(b.id);
  });
}
