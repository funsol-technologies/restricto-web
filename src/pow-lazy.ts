import type { PowOptions } from './pow';

/** The public `solvePow`: a thin wrapper so the solver itself stays out of the always-loaded core. */
export async function solvePow(challenge: string, keyHashHex: string, bits: number, o?: PowOptions): Promise<string> {
  return (await import('./pow')).solvePow(challenge, keyHashHex, bits, o);
}
