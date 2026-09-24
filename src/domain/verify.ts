import { parseFat, type FatArchEntry } from './fat';
import { parseMacho, type MachCommand } from './macho';
import { verifySignature, type SigView } from './signature';
import { BudgetError } from './errors';
import { canonical, sha256hex } from '../shared/id';
import { q, type Diag, type Policy } from '../shared/types';

export interface SliceView {
  id: string;
  index: number;
  archName: string;
  offset: number;
  size: number;
  alignExp: number;
  endian: 'le' | 'be';
  commands: MachCommand[];
  signature: SigView;
  diags: Diag[];
}

export interface Resolution {
  status: 'unique' | 'ambiguous' | 'none';
  targetArch: string;
  candidates: string[];
}

export interface VerifyOutcome {
  status: 'ok' | 'budget_exceeded' | 'malformed' | 'semantic_unresolvable';
  materialId: string;
  inputDigest: string;
  paramVersion: number;
  fat?: {
    endian: 'le' | 'be';
    is64: boolean;
    magicHex: string;
    nfat: number;
  };
  slices: SliceView[];
  resolution?: Resolution;
  diags: Diag[];
}

export function verifyUniversal(materialId: string, buf: Buffer, policy: Policy): VerifyOutcome {
  const inputDigest = sha256hex(sha256hex(buf) + canonical(policy));
  const base: VerifyOutcome = {
    status: 'ok',
    materialId,
    inputDigest,
    paramVersion: policy.version,
    slices: [],
    diags: [],
  };
  let fat;
  try {
    fat = parseFat(buf, materialId, policy.budget);
  } catch (err) {
    if (err instanceof BudgetError) {
      return { ...base, status: 'budget_exceeded', diags: [err.diag] };
    }
    throw err;
  }
  base.diags.push(...fat.diags);
  if (fat.fatal || !fat.isFat) {
    return { ...base, status: 'malformed' };
  }
  base.fat = {
    endian: fat.endian,
    is64: fat.is64,
    magicHex: fat.magicHex,
    nfat: fat.arches.length,
  };
  const matches = fat.arches.filter((a: FatArchEntry) => a.archName === policy.targetArch);
  base.resolution = {
    status: matches.length === 0 ? 'none' : matches.length === 1 ? 'unique' : 'ambiguous',
    targetArch: policy.targetArch,
    // Ambiguity keeps every legal candidate instead of picking one.
    candidates: matches.map((a) => a.objectId),
  };
  for (const arch of fat.arches) {
    const sliceView: SliceView = {
      id: arch.objectId,
      index: arch.index,
      archName: arch.archName,
      offset: arch.offset,
      size: arch.size,
      alignExp: arch.alignExp,
      endian: 'le',
      commands: [],
      signature: { present: false, verdict: { kind: 'not_signed' }, diags: [] },
      diags: [],
    };
    base.slices.push(sliceView);
    if (arch.offset + arch.size > buf.length) continue;
    const slice = buf.subarray(arch.offset, arch.offset + arch.size);
    try {
      const mach = parseMacho(slice, arch.objectId, arch.offset, policy.budget);
      sliceView.endian = mach.endian;
      sliceView.commands = mach.commands;
      sliceView.diags.push(...mach.diags);
      sliceView.signature = verifySignature(slice, mach.codeSig, arch.objectId);
      sliceView.diags.push(...sliceView.signature.diags);
    } catch (err) {
      if (err instanceof BudgetError) {
        return { ...base, status: 'budget_exceeded', diags: [...base.diags, err.diag] };
      }
      throw err;
    }
  }
  if (base.resolution.status === 'none') {
    base.diags.push({
      code: 'semantic_unresolvable',
      message: `policy targetArch '${policy.targetArch}' matches no slice; cannot uniquely resolve`,
      objectId: materialId,
      position: q(0, 'byte', 'file'),
    });
    base.status = 'semantic_unresolvable';
  }
  return base;
}
