import { sha256Short } from './hash.js';

/**
 * 稳定身份：对等价输入产生等价 sid（与进程、时间、插入顺序无关）。
 * 域路径前缀保证不同对象空间不碰撞。
 */
export function sid(scope: string, ...parts: (string | number)[]): string {
  const key = parts.join('|');
  return `${scope}_${sha256Short(new TextEncoder().encode(key), 12)}`;
}

export function fieldSid(parent: string, name: string, fileStart: number): string {
  return sid('fld', parent, name, fileStart);
}

/** 规范化稳定排序：slice 先按 offset 再按 cpu（等价输入稳定顺序） */
export function canonicalSliceOrder<T extends { offset: number; cputype: number; cpusubtype: number; index: number }>(
  items: T[],
): T[] {
  return [...items].sort((a, b) =>
    a.offset - b.offset || a.cputype - b.cputype || a.cpusubtype - b.cpusubtype || a.index - b.index,
  );
}
