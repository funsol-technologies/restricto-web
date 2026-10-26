import { buf, canonicalRequest, randomNonce, requestTarget, sha256Hex } from './canonical';
import type { Clock } from './clock';
import { b64urlEncode, utf8 } from './encoding';

export interface Signer {
  privateKey: CryptoKey;
  deviceId: string;
  appId: string;
  clock: Clock;
}

export interface SignedHeaders {
  Authorization: string;
  'X-APP-ID': string;
}

export interface SignResult {
  headers: SignedHeaders;
  nonce: string;
  ts: string;
  canonical: string;
}

/** `bodyBytes` must be exactly what goes on the wire. WebCrypto yields raw r||s, which the server accepts. */
export async function signRequest(s: Signer, method: string, url: URL, bodyBytes: Uint8Array | undefined, fixed?: { ts?: string; nonce?: string }): Promise<SignResult> {
  const ts = fixed?.ts ?? String(s.clock.now());
  const nonce = fixed?.nonce ?? randomNonce();
  const canonical = canonicalRequest({
    method,
    target: requestTarget(url),
    ts,
    nonce,
    deviceId: s.deviceId,
    appId: s.appId,
    bodySha256Hex: await sha256Hex(bodyBytes ?? new Uint8Array(0)),
  });
  const sig = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, s.privateKey, buf(utf8(canonical))));
  return {
    headers: {
      Authorization: `Restricto-Sig v1 id=${s.deviceId},ts=${ts},nonce=${nonce},sig=${b64urlEncode(sig)}`,
      'X-APP-ID': s.appId,
    },
    nonce,
    ts,
    canonical,
  };
}
