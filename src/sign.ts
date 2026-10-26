import { buf, canonicalRequest, hostLine, randomNonce, requestTarget, sha256B64 } from './canonical';
import type { Clock } from './clock';
import { b64urlEncode, utf8 } from './encoding';
import { RestrictoError } from './errors';
import { formatSignatureHeader, parseSignatureHeader } from './header';

export interface Signer {
  privateKey: CryptoKey;
  deviceId: string;
  appId: string;
  clock: Clock;
}

export interface SignedHeaders {
  'Restricto-Signature': string;
  'X-APP-ID': string;
}

export interface SignResult {
  headers: SignedHeaders;
  nonce: string;
  ts: string;
  canonical: string;
}

/**
 * `bodyBytes` must be exactly what goes on the wire. WebCrypto yields raw r||s, which the server accepts. The header is
 * parsed back with the strict parser before it is returned: an unexpected `device_id` can never become header injection.
 */
export async function signRequest(
  s: Signer,
  method: string,
  url: URL,
  bodyBytes: Uint8Array | undefined,
  fixed?: { ts?: string; nonce?: string; ext?: string },
): Promise<SignResult> {
  const ts = fixed?.ts ?? String(s.clock.now());
  const nonce = fixed?.nonce ?? randomNonce();
  const bh = await sha256B64(bodyBytes ?? new Uint8Array(0));
  const canonical = canonicalRequest({ method, host: hostLine(url), target: requestTarget(url), ts, nonce, deviceId: s.deviceId, appId: s.appId, bh, ext: fixed?.ext });
  const sig = b64urlEncode(new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, s.privateKey, buf(utf8(canonical)))));
  const header = formatSignatureHeader({ id: s.deviceId, ts, nonce, bh, sig, ext: fixed?.ext });
  if (parseSignatureHeader(header).result !== 'ok') throw new RestrictoError('config', 'Could not build a valid Restricto-Signature header (unexpected device id or app id).');
  return { headers: { 'Restricto-Signature': header, 'X-APP-ID': s.appId }, nonce, ts, canonical };
}
