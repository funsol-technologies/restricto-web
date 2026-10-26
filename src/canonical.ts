import { b64urlEncode, hex, utf8 } from './encoding';

/** WebCrypto wants ArrayBuffer-backed views; our Uint8Arrays always are, TypeScript just cannot see it. */
export const buf = (u8: Uint8Array): BufferSource => u8 as unknown as BufferSource;

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', buf(data)));
}

export async function sha256Hex(data: Uint8Array): Promise<string> {
  return hex(await sha256(data));
}

export async function sha256B64(data: Uint8Array): Promise<string> {
  return b64urlEncode(await sha256(data));
}

const isUnreserved = (b: number): boolean =>
  (b >= 0x30 && b <= 0x39) || (b >= 0x41 && b <= 0x5a) || (b >= 0x61 && b <= 0x7a) || b === 0x2d || b === 0x2e || b === 0x5f || b === 0x7e;

/** Percent-decode to bytes; a "%" not followed by two hex digits is a literal "%"; non-ASCII characters are UTF-8 encoded. */
function decodeBytes(raw: string): number[] {
  const out: number[] = [];
  for (let i = 0; i < raw.length; i++) {
    const c = raw.charCodeAt(i);
    if (c === 0x25 && /^[0-9a-fA-F]{2}$/.test(raw.slice(i + 1, i + 3))) {
      out.push(parseInt(raw.slice(i + 1, i + 3), 16));
      i += 2;
    } else if (c < 0x80) out.push(c);
    else {
      const cp = raw.codePointAt(i)!;
      if (cp > 0xffff) i++;
      out.push(...utf8(String.fromCodePoint(cp)));
    }
  }
  return out;
}

function encodeBytes(bytes: number[], keepSlash: boolean): string {
  let s = '';
  for (const b of bytes) s += isUnreserved(b) || (keepSlash && b === 0x2f) ? String.fromCharCode(b) : '%' + b.toString(16).toUpperCase().padStart(2, '0');
  return s;
}

/** Decode to bytes, then encode everything except `A-Za-z0-9-._~` and "/" (so `%2F` and `/` are the same path - see README). */
export const canonicalPath = (raw: string): string => encodeBytes(decodeBytes(raw || '/'), true);

/** Pairs split on "&" and the first "=", decoded ("+" stays a plus), re-encoded ("/" too), sorted bytewise. */
export function canonicalQuery(raw: string): string {
  const pairs: Array<[string, string]> = [];
  for (const part of (raw.startsWith('?') ? raw.slice(1) : raw).split('&')) {
    if (!part) continue;
    const eq = part.indexOf('=');
    pairs.push([encodeBytes(decodeBytes(eq < 0 ? part : part.slice(0, eq)), false), encodeBytes(decodeBytes(eq < 0 ? '' : part.slice(eq + 1)), false)]);
  }
  // all-ASCII strings: code-unit order is bytewise order
  pairs.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0));
  return pairs.map(([k, v]) => `${k}=${v}`).join('&');
}

/** Lower-case host, ":port" only when it is not the scheme's default; bracketed IPv6 keeps its brackets. */
export function canonicalHost(host: string, scheme = 'https'): string {
  const h = host.trim().toLowerCase();
  const m = /^(\[[0-9a-f:.]+\]|[a-z0-9._~-]+)(?::([0-9]{1,5}))?$/.exec(h);
  if (!m) return h;
  const port = m[2] === undefined ? undefined : Number(m[2]);
  return port === undefined || port === (scheme.toLowerCase().replace(/:$/, '') === 'http' ? 80 : 443) ? m[1]! : `${m[1]}:${port}`;
}

/** What the server sees on the wire is `url.pathname` / `url.search` (URL has already normalised dot segments and spaces). */
export function requestTarget(url: URL): string {
  const query = canonicalQuery(url.search);
  const path = canonicalPath(url.pathname);
  return query ? `${path}?${query}` : path;
}

export const hostLine = (url: URL): string => canonicalHost(url.host, url.protocol);

export interface CanonicalRequestParts {
  method: string;
  host: string;
  target: string;
  ts: string;
  nonce: string;
  deviceId: string;
  appId: string;
  bh: string;
  ext?: string;
}

export function canonicalRequest(p: CanonicalRequestParts): string {
  return ['RESTRICTO-SIG-V1', p.method.toUpperCase(), p.host, p.target, p.ts, p.nonce, p.deviceId, p.appId, p.bh, p.ext ?? ''].join('\n');
}

export interface CanonicalResponseParts {
  status: number;
  nonce: string;
  deviceId: string;
  ts: string;
  bodySha256Hex: string;
  contentType?: string;
  location?: string;
  retryAfter?: string;
}

export function canonicalResponse(p: CanonicalResponseParts): string {
  return ['RESTRICTO-RESP-V1', String(p.status), p.nonce, p.deviceId, p.ts, p.bodySha256Hex, p.contentType ?? '', p.location ?? '', p.retryAfter ?? ''].join('\n');
}

/** 16 random bytes -> 22 chars of [A-Za-z0-9_-], inside the server's 16-64 range. */
export function randomNonce(): string {
  return b64urlEncode(crypto.getRandomValues(new Uint8Array(16)));
}

/** `H = SHA-256("RESTRICTO-BIND-V1" || SHA-256(challenge) || SPKI_DER)`: for hybrid apps that also run a native attestation. */
export async function bindingHash(challenge: string, spkiDer: Uint8Array): Promise<Uint8Array> {
  const label = utf8('RESTRICTO-BIND-V1');
  const c = await sha256(utf8(challenge));
  const all = new Uint8Array(label.length + c.length + spkiDer.length);
  all.set(label, 0);
  all.set(c, label.length);
  all.set(spkiDer, label.length + c.length);
  return sha256(all);
}
