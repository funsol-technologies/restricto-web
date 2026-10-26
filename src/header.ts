export const MAX_HEADER_BYTES = 1024;

export interface SignatureParams {
  id: string;
  ts: string;
  nonce: string;
  bh: string;
  sig: string;
  ext?: string;
}

export type ParsedSignature = { result: 'ok'; v: string; params: SignatureParams } | { result: 'malformed' | 'unsupported_version' };

const RULES: Array<[keyof SignatureParams, RegExp]> = [
  ['id', /^rd_[A-Za-z0-9_.:-]{1,61}$/],
  ['ts', /^[0-9]{1,12}$/],
  ['nonce', /^[A-Za-z0-9_-]{16,64}$/],
  ['bh', /^[A-Za-z0-9_-]{43}$/],
  ['sig', /^[A-Za-z0-9_-]{80,128}$/],
];

/** Strict parser, the mirror of the server's: used to self-check what we are about to send, and by the shared vectors. */
export function parseSignatureHeader(value: string | null | undefined): ParsedSignature {
  const text = value ?? '';
  if (!text || text.length > MAX_HEADER_BYTES || !/^[\x00-\x7f]*$/.test(text)) return { result: 'malformed' };
  const p: Record<string, string> = {};
  for (const item of text.split(',')) {
    const eq = item.indexOf('=');
    const k = item.slice(0, eq);
    const v = item.slice(eq + 1);
    if (eq < 0 || !/^[A-Za-z0-9_]{1,16}$/.test(k) || !/^[A-Za-z0-9_.:-]+$/.test(v) || k in p) return { result: 'malformed' };
    p[k] = v;
  }
  if (!/^[0-9]{1,3}$/.test(p.v ?? '')) return { result: 'malformed' };
  if (Number(p.v) !== 1) return { result: 'unsupported_version' };
  for (const [name, re] of RULES) if (!re.test(p[name] ?? '')) return { result: 'malformed' };
  if ('ext' in p && !/^[A-Za-z0-9_-]{1,512}$/.test(p.ext!)) return { result: 'malformed' };
  return { result: 'ok', v: p.v!, params: p as unknown as SignatureParams };
}

export function formatSignatureHeader(p: SignatureParams): string {
  return `v=1,id=${p.id},ts=${p.ts},nonce=${p.nonce},bh=${p.bh},sig=${p.sig}${p.ext ? `,ext=${p.ext}` : ''}`;
}
