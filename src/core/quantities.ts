import { shortHash } from './ids.js';

export type CoordinateBasis =
  | 'file'
  | 'fat-header'
  | 'fat-entry'
  | 'slice'
  | 'load-command-region'
  | 'linkedit'
  | 'superblob'
  | 'codedirectory'
  | 'blob-index'
  | 'rule';

export type QuantityUnit =
  | 'byte'
  | 'slot'
  | 'page'
  | 'arch-entry'
  | 'load-command'
  | 'bit'
  | 'enum'
  | 'hex'
  | 'text'
  | 'boolean';

export interface QuantityDiagnostic {
  code: 'UNCONVERTIBLE_VALUE' | 'VALUE_OUT_OF_DOMAIN';
  message: string;
  coordinate?: ByteCoordinate;
}

export interface ByteCoordinate {
  basis: CoordinateBasis;
  offset: number;
  length?: number;
  endian?: 'be' | 'le';
}

export interface Quantity {
  uid: string;
  raw: string;
  value: number | string | boolean | null;
  unit: QuantityUnit,
  basis: CoordinateBasis;
  coordinate?: ByteCoordinate;
  convertible: boolean;
  diagnostic?: QuantityDiagnostic;
}

export function makeQuantity(
  raw: string,
  value: number | string | boolean | null,
  unit: QuantityUnit,
  basis: CoordinateBasis,
  coordinate?: ByteCoordinate,
  convertible = true,
  diagnostic?: QuantityDiagnostic,
): Quantity {
  const coordKey = coordinate
    ? `${coordinate.basis}@${coordinate.offset}+${coordinate.length ?? 0}:${coordinate.endian ?? ''}`
    : basis;
  return {
    uid: `q-${shortHash(`${raw}|${unit}|${coordKey}`)}`,
    raw,
    value,
    unit,
    basis,
    coordinate,
    convertible,
    diagnostic,
  };
}
