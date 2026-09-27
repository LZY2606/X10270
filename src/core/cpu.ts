// cputype/cpusubtype -> 稳定架构显示名（Mach-O 常量，离线自带，不依赖系统）。
export interface CpuInfo {
  cputype: number;
  name: string;
  subtypes: Map<number, string>;
}

// 来源：<mach/machine.h> 公开常量
const TABLE: CpuInfo[] = [
  {
    cputype: 0x01000007,
    name: 'x86_64',
    subtypes: new Map([
      [3, 'x86_64-all'],
      [4, 'x86_64-haswell'],
    ]),
  },
  {
    cputype: 0x0100000c,
    name: 'arm64',
    subtypes: new Map([
      [0, 'arm64-all'],
      [1, 'arm64-v8'],
      [2, 'arm64-e'],
    ]),
  },
  {
    cputype: 0x0000000c,
    name: 'arm',
    subtypes: new Map([[0, 'arm-all'], [12, 'arm-v7s']]),
  },
  {
    cputype: 0x00000007,
    name: 'i386',
    subtypes: new Map([[3, 'i386-all']]),
  },
];

export function archName(cputype: number, cpusubtype: number): string {
  const cpu = TABLE.find((c) => c.cputype === cputype);
  if (!cpu) return `unknown-cpu:0x${cputype.toString(16)}`;
  const sub = cpu.subtypes.get(cpusubtype);
  return sub ? `${cpu.name}(${sub})` : `${cpu.name}(sub:${cpusubtype})`;
}

export const KNOWN_ARCHES = TABLE.map((t) => t.name);
