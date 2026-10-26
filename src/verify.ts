import { buf, canonicalResponse, sha256Hex } from './canonical';
import type { Clock } from './clock';
import { b64urlDecode, utf8 } from './encoding';
import { RestrictoError } from './errors';

/** Spec: the response `ts` must be within this many seconds of the (server-corrected) client clock. */
export const RESPONSE_SKEW_SECONDS = 300;

export const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);
export const int = (v: unknown): number | undefined => (typeof v === 'number' && Number.isFinite(v) ? Math.trunc(v) : undefined);

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

export interface ResponseKey {
  kid: string;
  pub: Uint8Array;
  /** unix seconds: the key signs nothing before this / after this (a response `ts` outside is refused). */
  nbf?: number;
  naf?: number;
}

/** Entries of the config's `resp_keys` / the `/keys/` list: only well-formed Ed25519 keys in a known state are kept. */
export function parseRespKeys(list: unknown): ResponseKey[] {
  const out: ResponseKey[] = [];
  if (!Array.isArray(list)) return out;
  for (const e of list.slice(0, 16)) {
    if (!isObj(e) || e.alg !== 'Ed25519' || typeof e.kid !== 'string' || !/^[A-Za-z0-9_.:-]{1,64}$/.test(e.kid)) continue;
    if (e.state !== 'active' && e.state !== 'next' && e.state !== 'retired') continue;
    let pub: Uint8Array;
    try {
      pub = b64urlDecode(String(e.pub ?? e.public_key ?? ''));
    } catch {
      continue;
    }
    if (pub.length !== 32) continue;
    const key: ResponseKey = { kid: e.kid, pub };
    const nbf = int(e.nbf);
    const naf = int(e.naf);
    if (nbf !== undefined) key.nbf = nbf;
    if (naf !== undefined) key.naf = naf;
    out.push(key);
  }
  return out;
}

export interface KeyResolver {
  get(kid: string): Promise<ResponseKey | undefined>;
}

export interface KeySources {
  /** `pinnedResponseKeys`: authoritative, kid -> base64url Ed25519. */
  pinned?: Record<string, string>;
  /** Keys from the verified config document (undefined when there is none, e.g. none fetched yet). */
  config?: () => ResponseKey[] | undefined;
  /** True when `pinnedConfigKeys` is in use: the config is then the only other source, and an unknown kid triggers a (throttled) refetch. */
  configPinned?: boolean;
  refreshConfig?: () => Promise<void>;
  /** Trust-on-first-use `GET /keys/` (only consulted when neither pins are given). */
  tofu?: () => Promise<ResponseKey[]>;
}

/**
 * Pinned response keys and the keys of the signed config document are authoritative: an unknown kid is a failure (after one throttled
 * config refresh). Only without any pin does it fall back to `GET /restricto/keys/` once (trust on first use, weaker), re-fetched at
 * most once a minute for an unknown kid.
 */
export function createKeyResolver(src: KeySources): KeyResolver {
  const pinned = new Map<string, ResponseKey>();
  for (const [kid, k] of Object.entries(src.pinned ?? {})) pinned.set(kid, { kid, pub: b64urlDecode(k) });
  const learned = new Map<string, ResponseKey>();
  let lastFetch = 0;
  let inflight: Promise<void> | undefined;
  const local = (kid: string): ResponseKey | undefined => pinned.get(kid) ?? src.config?.()?.find((k) => k.kid === kid);
  return {
    async get(kid) {
      const hit = local(kid);
      if (hit) return hit;
      if (src.configPinned) {
        await src.refreshConfig?.();
        return local(kid);
      }
      if (pinned.size || !src.tofu) return undefined;
      if (!learned.has(kid) && (Date.now() - lastFetch > 60_000 || learned.size === 0)) {
        inflight ??= src
          .tofu()
          .then((fresh) => {
            for (const k of fresh) learned.set(k.kid, k);
          })
          .finally(() => {
            lastFetch = Date.now();
            inflight = undefined;
          });
        await inflight;
      }
      return learned.get(kid);
    },
  };
}

export interface ResponseSigField {
  kid: string;
  alg: string;
  ts: string;
  sig: string;
}

/**
 * `Restricto-Response-Signature` may carry several signatures (one field each, `v=1,kid=..,alg=..,ts=..,sig=..`), as separate header
 * lines (which `Headers.get` joins with ", ") or comma-joined. A new field starts at every `v=`; unknown versions are skipped.
 */
export function parseResponseSignatures(header: string | null): ResponseSigField[] {
  const out: ResponseSigField[] = [];
  let cur: Record<string, string> | undefined;
  const flush = (): void => {
    if (cur && cur.v === '1' && cur.kid && cur.alg && cur.ts && cur.sig) out.push({ kid: cur.kid, alg: cur.alg, ts: cur.ts, sig: cur.sig });
    cur = undefined;
  };
  for (const token of (header ?? '').split(',')) {
    const m = /^\s*([A-Za-z0-9_]{1,16})=([A-Za-z0-9_.:-]+)\s*$/.exec(token);
    if (!m) continue;
    if (m[1] === 'v') {
      flush();
      cur = {};
    }
    if (cur && !(m[1]! in cur)) cur[m[1]!] = m[2]!;
  }
  flush();
  return out;
}

export type VerifyOutcome =
  | { ok: true; ts: number }
  | { ok: false; kind: 'unsigned' | 'invalid' | 'window'; reason: string };

export interface VerifyContext {
  nonce: string;
  deviceId: string;
  method: string;
  clock: Clock;
  keys: KeyResolver;
  forceFallback?: boolean;
  /** Skip the ±300 s window (only used for a signed clock-skew rejection, where our clock is the thing that is wrong). */
  ignoreWindow?: boolean;
}

/** Bodies the server signs as empty whatever was produced. */
export const hasNoBody = (method: string, status: number): boolean => method.toUpperCase() === 'HEAD' || status === 204 || status === 304 || (status >= 100 && status < 200);

export async function verifyResponseSignature(res: Response, ctx: VerifyContext): Promise<VerifyOutcome> {
  const fields = parseResponseSignatures(res.headers.get('Restricto-Response-Signature'));
  if (!fields.length)
    return { ok: false, kind: 'unsigned', reason: 'response carries no Restricto signature (in a browser the server must expose Restricto-Response-Signature via Access-Control-Expose-Headers)' };
  let body: Uint8Array | undefined;
  let kind: 'invalid' | 'window' = 'invalid';
  let reason = 'no usable signature in the response';
  for (const f of fields) {
    if (f.alg !== 'Ed25519') continue; // unknown algorithm: ignored, another field may carry one we know
    if (!/^[0-9]{1,12}$/.test(f.ts)) continue;
    const ts = Number(f.ts);
    if (!ctx.ignoreWindow && Math.abs(ts - ctx.clock.now()) > RESPONSE_SKEW_SECONDS) {
      kind = 'window';
      reason = 'response timestamp outside the accepted window';
      continue;
    }
    let key: ResponseKey | undefined;
    try {
      key = await ctx.keys.get(f.kid);
    } catch (e) {
      reason = `response key lookup failed: ${(e as Error).message}`;
      continue;
    }
    if (!key) {
      reason = `unknown response signing key "${f.kid}"`;
      continue;
    }
    if ((key.nbf !== undefined && ts + RESPONSE_SKEW_SECONDS < key.nbf) || (key.naf !== undefined && ts > key.naf + RESPONSE_SKEW_SECONDS)) {
      reason = `response key "${f.kid}" was not valid at the signed time`;
      continue;
    }
    let sig: Uint8Array;
    try {
      sig = b64urlDecode(f.sig);
    } catch {
      continue;
    }
    body ??= hasNoBody(ctx.method, res.status) ? new Uint8Array(0) : new Uint8Array(await res.clone().arrayBuffer());
    const message = utf8(
      canonicalResponse({
        status: res.status,
        nonce: ctx.nonce,
        deviceId: ctx.deviceId,
        ts: f.ts,
        bodySha256Hex: await sha256Hex(body),
        contentType: res.headers.get('Content-Type') ?? '',
        location: res.headers.get('Location') ?? '',
        retryAfter: res.headers.get('Retry-After') ?? '',
      }),
    );
    if (await ed25519Verify(key.pub, sig, message, ctx.forceFallback)) return { ok: true, ts };
    kind = 'invalid';
    reason = 'response signature invalid (status, nonce, device, headers or body does not match)';
  }
  return { ok: false, kind, reason };
}

export function unverified(reason: string, init: { unsigned?: boolean; status?: number } = {}): RestrictoError {
  return new RestrictoError('response_unverified', `Rejected response: ${reason}.`, init);
}
