import { b64urlEncode, hex } from './encoding';

const enc = new TextEncoder();

/** WebCrypto wants ArrayBuffer-backed views; our Uint8Arrays always are, TypeScript just cannot see it. */
export const buf = (u8: Uint8Array): BufferSource => u8 as unknown as BufferSource;

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', buf(data)));
}

export async function sha256Hex(data: Uint8Array): Promise<string> {
  return hex(await sha256(data));
}

const isUnreserved = (b: number): boolean =>
  (b >= 0x30 && b <= 0x39) || (b >= 0x41 && b <= 0x5a) || (b >= 0x61 && b <= 0x7a) || b === 0x2d || b === 0x2e || b === 0x5f || b === 0x7e;

/**
 * The server hashes its *decoded* path (Django `request.path`) re-quoted with only unreserved chars and "/" raw, so the
 * client must decode what is on the wire and quote it the same way (an "%2F" or "+" in the path normalises, it is not kept).
 * The query is the opposite: byte-for-byte as sent.
 */
export function requestTarget(url: URL): string {
  const raw = url.pathname || '/';
  const bytes: number[] = [];
  for (let i = 0; i < raw.length; i++) {
    const c = raw.charCodeAt(i);
    if (c === 0x25 && /^[0-9a-fA-F]{2}$/.test(raw.slice(i + 1, i + 3))) {
      bytes.push(parseInt(raw.slice(i + 1, i + 3), 16));
      i += 2;
    } else if (c < 0x80) bytes.push(c);
    else bytes.push(...enc.encode(raw[i]!));
  }
  let path = '';
  for (const b of bytes) path += b === 0x2f || isUnreserved(b) ? String.fromCharCode(b) : '%' + b.toString(16).toUpperCase().padStart(2, '0');
  const query = url.search.startsWith('?') ? url.search.slice(1) : '';
  return query ? `${path}?${query}` : path;
}

export interface CanonicalRequestParts {
  method: string;
  target: string;
  ts: string;
  nonce: string;
  deviceId: string;
  appId: string;
  bodySha256Hex: string;
}

export function canonicalRequest(p: CanonicalRequestParts): string {
  return ['RESTRICTO-SIG-V1', p.method.toUpperCase(), p.target, p.ts, p.nonce, p.deviceId, p.appId, p.bodySha256Hex].join('\n');
}

export interface CanonicalResponseParts {
  status: number;
  nonce: string;
  deviceId: string;
  ts: string;
  bodySha256Hex: string;
}

export function canonicalResponse(p: CanonicalResponseParts): string {
  return ['RESTRICTO-RESP-V1', String(p.status), p.nonce, p.deviceId, p.ts, p.bodySha256Hex].join('\n');
}

/** 16 random bytes -> 22 chars of [A-Za-z0-9_-], inside the server's 16-64 range. */
export function randomNonce(): string {
  return b64urlEncode(crypto.getRandomValues(new Uint8Array(16)));
}
