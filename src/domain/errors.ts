import type { Diag } from '../shared/types';

/** Thrown when a resource budget is exhausted; distinct from malformed input. */
export class BudgetError extends Error {
  constructor(public readonly diag: Diag) {
    super(diag.message);
    this.name = 'BudgetError';
  }
}
