import { LAYOUT, CPU_X86_64 } from './layout';

export const MUTATIONS = [
  'endianness',
  'slice_overlap',
  'align_overflow',
  'command_out_of_bounds',
  'signature_tail_gap',
  'multi_arch_same_name',
  'unknown_blob',
  'hash_mismatch',
] as const;
export type MutationName = (typeof MUTATIONS)[number];

export const MUTATION_LABELS: Record<MutationName, string> = {
  endianness: '大小端：fat header 改写为 CIGAM（小端 arch 表）',
  slice_overlap: 'slice 重叠：arch1 偏移移入 arch0 范围',
  align_overflow: '对齐溢出：arch1 align 指数 = 40，不可规范化',
  command_out_of_bounds: 'command 越界：slice0 首个 command 的 cmdsize 超出 slice',
  signature_tail_gap: '签名未覆盖尾部：arm64 slice 的 code slot 数减一',
  multi_arch_same_name: '多架构同名：两个 slice 都命名为 x86_64',
  unknown_blob: '未知 blob：arm64 签名 superblob magic 改写为未知值',
  hash_mismatch: 'hash 不匹配：arm64 代码区翻转一个字节',
};

/** Applies exactly one mutation to a copy of the baseline fixture. */
export function applyMutation(base: Buffer, name: MutationName): Buffer {
  const buf = Buffer.from(base);
  const L = LAYOUT;
  switch (name) {
    case 'endianness': {
      // Rewrite the fat header as FAT_CIGAM: magic and arch table little-endian.
      const nfat = buf.readUInt32BE(4);
      const entries: number[][] = [];
      for (let i = 0; i < nfat; i++) {
        const b = L.fatArchEntry(i);
        entries.push([
          buf.readUInt32BE(b),
          buf.readUInt32BE(b + 4),
          buf.readUInt32BE(b + 8),
          buf.readUInt32BE(b + 12),
          buf.readUInt32BE(b + 16),
        ]);
      }
      buf.writeUInt32LE(0xcafebabe, 0);
      buf.writeUInt32LE(nfat, 4);
      entries.forEach((fields, i) => {
        const b = L.fatArchEntry(i);
        fields.forEach((v, j) => buf.writeUInt32LE(v, b + j * 4));
      });
      return buf;
    }
    case 'slice_overlap':
      buf.writeUInt32BE(L.slice0 + 0x800, L.fatArchEntry(1) + 8);
      return buf;
    case 'align_overflow':
      buf.writeUInt32BE(40, L.fatArchEntry(1) + 16);
      return buf;
    case 'command_out_of_bounds':
      buf.writeUInt32LE(0x4000, L.slice0 + L.cmd0 + 4);
      return buf;
    case 'signature_tail_gap':
      buf.writeUInt32BE(5, L.slice1 + L.dataoff + L.codeDirectory + L.cdNCodeSlots);
      return buf;
    case 'multi_arch_same_name':
      buf.writeUInt32BE(CPU_X86_64, L.fatArchEntry(1));
      return buf;
    case 'unknown_blob':
      buf.writeUInt32BE(0xdeadbeef, L.slice1 + L.dataoff + L.superBlob);
      return buf;
    case 'hash_mismatch':
      buf[L.slice1 + 0x200] = buf[L.slice1 + 0x200] ^ 0xff;
      return buf;
  }
}
