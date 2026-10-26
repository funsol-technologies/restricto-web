import { buf, canonicalResponse, sha256Hex } from './canonical';
import type { Clock } from './clock';
import { b64urlDecode, utf8 } from './encoding';
import { RestrictoError } from './errors';

export const RESPONSE_SKEW_SECONDS = 300;

let nativeEd25519: boolean | undefined;

/** WebCrypto Ed25519 where the browser has it (Chrome 137+, Firefox 129+, Safari 17+), else lazily-loaded @noble/curves. */
export async function ed25519Verify(publicKey: Uint8Array, signature: Uint8Array, message: Uint8Array, forceFallback = false): Promise<boolean> {
  if (!forceFallback && nativeEd25519 !== false) {
    try {
      const key = await crypto.subtle.importKey('raw', buf(publicKey), { name: 'Ed25519' }, false, ['verify']);
      nativeEd25519 = true;
      return await crypto.subtle.verify({ name: 'Ed25519' }, key, buf(signature), buf(message));
    } catch (e) {
      if (nativeEd25519) return false;
      if (!(e instanceof Error) || (e.name !== 'NotSupportedError' && e.name !== 'SyntaxError' && e.name !== 'TypeError')) return false;
      nativeEd25519 = false;
    }
  }
  const { ed25519 } = await import('@noble/curves/ed25519');
  try {
    return ed25519.verify(signature, message, publicKey);
  } catch {
    return false;
  }
}

export type ResponseKeyMap = Record<string, string>;

export interface KeyResolver {
  get(kid: string): Promise<Uint8Array | undefined>;
}

/**
 * Pinned keys are authoritative: an unknown kid is a failure, nothing is fetched. Without pins the keys come from
 * `GET /restricto/keys/` on first use (trust-on-first-use) and are re-fetched at most once a minute for an unknown kid.
 */
export function createKeyResolver(pinned: ResponseKeyMap | undefined, fetchKeys: () => Promise<ResponseKeyMap>): KeyResolver {
  const keys = new Map<string, Uint8Array>();
  for (const [kid, k] of Object.entries(pinned ?? {})) keys.set(kid, b64urlDecode(k));
  let lastFetch = 0;
  let inflight: Promise<void> | undefined;
  return {
    async get(kid) {
      if (keys.has(kid) || pinned) return keys.get(kid);
      if (Date.now() - lastFetch > 60_000 || keys.size === 0) {
        inflight ??= fetchKeys()
          .then((fresh) => {
            for (const [id, k] of Object.entries(fresh)) keys.set(id, b64urlDecode(k));
          })
          .finally(() => {
            lastFetch = Date.now();
            inflight = undefined;
          });
        await inflight;
      }
      return keys.get(kid);
    },
  };
}

export type VerifyOutcome = { ok: true } | { ok: false; unsigned: boolean; reason: string };

export interface VerifyContext {
  nonce: string;
  deviceId: string;
  clock: Clock;
  keys: KeyResolver;
  forceFallback?: boolean;
}

export async function verifyResponseSignature(res: Response, ctx: VerifyContext): Promise<VerifyOutcome> {
  const kid = res.headers.get('X-Restricto-Resp-Kid');
  const ts = res.headers.get('X-Restricto-Resp-Ts');
  const sig = res.headers.get('X-Restricto-Resp-Sig');
  if (!kid || !ts || !sig)
    return { ok: false, unsigned: true, reason: 'response carries no Restricto signature (if this is a browser, the server must expose X-Restricto-Resp-* via Access-Control-Expose-Headers)' };
  if (!/^\d{1,12}$/.test(ts) || Math.abs(Number(ts) - ctx.clock.now()) > RESPONSE_SKEW_SECONDS)
    return { ok: false, unsigned: false, reason: 'response timestamp outside the accepted window' };
  let key: Uint8Array | undefined;
  try {
    key = await ctx.keys.get(kid);
  } catch (e) {
    return { ok: false, unsigned: false, reason: `response key lookup failed: ${(e as Error).message}` };
  }
  if (!key) return { ok: false, unsigned: false, reason: `unknown response signing key "${kid}"` };
  const body = new Uint8Array(await res.clone().arrayBuffer());
  const message = utf8(
    canonicalResponse({ status: res.status, nonce: ctx.nonce, deviceId: ctx.deviceId, ts, bodySha256Hex: await sha256Hex(body) }),
  );
  let signature: Uint8Array;
  try {
    signature = b64urlDecode(sig);
  } catch {
    return { ok: false, unsigned: false, reason: 'malformed response signature' };
  }
  const ok = await ed25519Verify(key, signature, message, ctx.forceFallback);
  return ok ? { ok: true } : { ok: false, unsigned: false, reason: 'response signature invalid (status, nonce, device or body does not match)' };
}

export function unverified(reason: string): RestrictoError {
  return new RestrictoError('response_unverified', `Rejected response: ${reason}.`);
}
