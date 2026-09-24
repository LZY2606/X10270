export function archName(cputype: number): string {
  const abi = cputype & 0x00ffffff;
  switch (cputype) {
    case 0x01000007:
    case 7:
      return 'x86_64';
    case 0x0100000c:
    case 12:
      return 'arm64';
    case 0x00000007:
      return 'i386';
    case 12:
      return 'arm';
    default:
      return `unknown(${abi})`;
  }
}
