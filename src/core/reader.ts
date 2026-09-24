// Bounded, budgeted binary reader. Every read is range-checked against the
// enclosing span; an over-read never fabricates zero/undefined values — the
// caller records a positioned diagnostic. A byte/object read budget provides a
// hard resource ceiling independent of declared sizes in untrusted input.

import { DiagnosticCollector } from './diagnostics.js';

export interface Budget {
  maxBytesRead: number;
  maxSlices: number;
  maxCommandsPerSlice: number;
  maxCodeSlots: number;
}

export const DEFAULT_BUDGET: Budget = {
  maxBytesRead: 16 * 1024 * 1024,
  maxSlices: 32,
  maxCommandsPerSlice: 128,
  maxCodeSlots: 64,
};

export class BudgetMeter {
  bytesRead = 0;
  slices = 0;
  commands = 0;
  codeSlots = 0;

  constructor(readonly budget: Budget = DEFAULT_BUDGET) {}

  chargeBytes(n: number, diag: DiagnosticCollector): void {
    this.bytesRead += n;
    if (this.bytesRead > this.budget.maxBytesRead) {
      diag.budgetExhausted(
        `read budget exceeded: ${this.bytesRead} > ${this.budget.maxBytesRead} bytes`,
        this.budget.maxBytesRead,
        this.bytesRead,
      );
    }
  }

  chargeSlice(diag: DiagnosticCollector): void {
    this.slices += 1;
    if (this.slices > this.budget.maxSlices) {
      diag.budgetExhausted(`slice budget exceeded: > ${this.budget.maxSlices}`, this.budget.maxSlices, this.slices);
    }
  }

  chargeCommand(diag: DiagnosticCollector): void {
    this.commands += 1;
    if (this.commands > this.budget.maxCommandsPerSlice * Math.max(1, this.budget.maxSlices)) {
      diag.budgetExhausted('load-command budget exceeded', this.budget.maxCommandsPerSlice, this.commands);
    }
  }

  chargeCodeSlot(diag: DiagnosticCollector): void {
    this.codeSlots += 1;
    if (this.codeSlots > this.budget.maxCodeSlots) {
      diag.budgetExhausted('code-slot budget exceeded', this.budget.maxCodeSlots, this.codeSlots);
    }
  }
}

export type Endian = 'le' | 'be';

// A window over the full file buffer. `start` is the file-absolute byte offset
// corresponding to relative offset 0; lengths stay relative.
export class Span {
  constructor(
    readonly buf: Uint8Array,
    readonly start: number,
    readonly length: number,
  ) {}

  static of(bytes: Uint8Array): Span {
    return new Span(bytes, 0, bytes.length);
  }

  covers(offset: number, n: number): boolean {
    return offset >= 0 && n >= 0 && offset + n <= this.length;
  }

  absolute(relative: number): number {
    return this.start + relative;
  }

  sub(relative: number, length: number): Span | null {
    if (!this.covers(relative, length)) return null;
    return new Span(this.buf, this.start + relative, length);
  }

  readU32(relative: number, endian: Endian): number | null {
    if (!this.covers(relative, 4)) return null;
    const i = this.start + relative;
    const b = this.buf;
    return endian === 'le'
      ? (b[i] | (b[i + 1] << 8) | (b[i + 2] << 16) | (b[i + 3] << 24)) >>> 0
      : (((b[i] << 24) >>> 0) | (b[i + 1] << 16) | (b[i + 2] << 8) | b[i + 3]) >>> 0;
  }

  readU16(relative: number, endian: Endian): number | null {
    if (!this.covers(relative, 2)) return null;
    const i = this.start + relative;
    const b = this.buf;
    return endian === 'le' ? b[i] | (b[i + 1] << 8) : (b[i] << 8) | b[i + 1];
  }

  readBytes(relative: number, n: number): Uint8Array | null {
    if (!this.covers(relative, n)) return null;
    return this.buf.subarray(this.start + relative, this.start + relative + n);
  }

  hexAt(relative: number, n: number): string | null {
    const b = this.readBytes(relative, n);
    return b ? [...b].map((x) => x.toString(16).padStart(2, '0')).join(' ') : null;
  }
}
