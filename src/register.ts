import { sha256 } from './canonical';
import type { Clock } from './clock';
import { POW_SDK_MAX_BITS } from './config-defaults';
import { b64urlDecode, hex, utf8 } from './encoding';
import { abortError, parseRetryAfter, readServerCode, RestrictoError } from './errors';
import { fromOrigin } from './net';
import type { PowOptions } from './pow';

export interface Registration {
  deviceId: string;
  trustLevel: number;
  /** unix seconds, server clock */
  attestedUntil: number;
  serverTime: number;
  maxClockSkew: number;
  cfgSeq?: number;
}

/** A request signed with the existing device key (renewal): headers to send, and the check for the answer. */
export interface SignedCall {
  headers: Record<string, string>;
  /** Throws `response_unverified` when the answer is not signed by a known response key; returns the signed `action`, if any. */
  verify(res: Response): Promise<string | undefined>;
}

export interface RegisterDeps {
  /** e.g. https://api.example.com/restricto - no trailing slash */
  restrictoUrl: string;
  origin: string;
  appId: string;
  appVersion: string;
  fetch: typeof fetch;
  clock: Clock;
  getTurnstileToken?: () => Promise<string | undefined>;
  pow?: Pick<PowOptions, 'useWorker' | 'createWorker' | 'budgetMs'>;
  /** From the signed config: the base puzzle size, and the most this SDK will work for. */
  powBits?: number;
  powMaxBits?: number;
  /** `cfg` of `caps`: the config sequence number we hold. */
  cfgSeq: number;
  onProgress?: (attempts: number) => void;
  /** Aborts the HTTP calls and the proof of work (close() / reset()). */
  signal?: AbortSignal;
  /** Called with what the (unsigned) challenge reported. Only advisory except through the signed config. */
  onChallenge?: (c: { sigVersions?: number[]; cfgSeq?: number }) => void;
  /** When set the register call is a renewal: `renew:true`, signed with the existing key. */
  signed?: (url: URL, body: Uint8Array) => Promise<SignedCall>;
}

type Failure = 'challenge_failed' | 'register_failed';

async function post(d: RegisterDeps, path: string, body: unknown, failure: Failure, signed?: SignedCall | Promise<SignedCall>): Promise<Record<string, unknown>> {
  let res: Response;
  const call = await signed;
  try {
    res = await d.fetch(`${d.restrictoUrl}/device/${path}/`, {
      method: 'POST',
      headers: { 'X-APP-ID': d.appId, ...(body === undefined ? {} : { 'Content-Type': 'application/json' }), ...call?.headers },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: d.signal,
      credentials: 'omit',
      redirect: 'error',
    });
  } catch (e) {
    if (d.signal?.aborted) throw abortError();
    throw new RestrictoError(failure, `Could not reach ${path} endpoint: ${(e as Error).message}`, { cause: e });
  }
  if (!fromOrigin(res, d.origin)) throw new RestrictoError(failure, `The ${path} reply did not come from ${d.origin}.`, { unsigned: true });
  const action = call ? await call.verify(res) : undefined; // throws for unsigned / unverifiable answers: never acted upon
  if (!res.ok) {
    throw new RestrictoError(failure, `Server refused ${path} (HTTP ${res.status}).`, {
      status: res.status,
      serverCode: await readServerCode(res),
      retryAfter: parseRetryAfter(res.headers.get('Retry-After')),
      action,
    });
  }
  const json: unknown = await res.json().catch(() => undefined);
  if (!json || typeof json !== 'object') throw new RestrictoError(failure, `Malformed ${path} response.`, { status: res.status });
  return json as Record<string, unknown>;
}

const num = (v: unknown): number | undefined => (typeof v === 'number' && Number.isFinite(v) ? v : undefined);

/** challenge -> proof of work bound to the key -> register (or, with `signed`, a signed `renew:true`). */
export async function registerDevice(d: RegisterDeps, publicKeySpki: string): Promise<Registration> {
  // the Turnstile token is fetched first: it may need user interaction and the challenge lives only ~2 minutes
  const turnstile = d.getTurnstileToken ? await d.getTurnstileToken() : undefined;
  const ch = await post(d, 'challenge', undefined, 'challenge_failed');
  if (typeof ch.challenge !== 'string') throw new RestrictoError('challenge_failed', 'Challenge response has no challenge.');
  const serverTime = num(ch.server_time);
  if (serverTime) d.clock.sync(serverTime);
  d.onChallenge?.({
    sigVersions: Array.isArray(ch.sig_versions) ? ch.sig_versions.filter((v): v is number => typeof v === 'number') : undefined,
    cfgSeq: num(ch.cfg_seq),
  });
  const powInfo = ch.pow && typeof ch.pow === 'object' ? (ch.pow as { alg?: unknown; bits?: unknown }) : undefined;
  if (powInfo && powInfo.alg !== undefined && powInfo.alg !== 'sha256-lz')
    throw new RestrictoError('register_failed', `The server asks for an unknown proof-of-work algorithm "${String(powInfo.alg)}"; update @funsol/restricto-web.`);
  // The puzzle size is whatever the server announces (it may be scaled up for a busy network) but never above the signed config's
  // max_bits and never above the SDK's own ceiling: a hostile challenge cannot make the browser burn CPU for long.
  const announced = Math.max(0, Math.trunc(num(powInfo?.bits) ?? 0), d.powBits ?? 0);
  const bits = Math.min(announced, d.powMaxBits ?? POW_SDK_MAX_BITS, POW_SDK_MAX_BITS);
  const spki = b64urlDecode(publicKeySpki);
  // the proof of work is the heaviest code in the SDK and runs once per registration: loaded on demand
  const { solvePow } = await import('./pow');
  const solution = await solvePow(ch.challenge, hex(await sha256(spki)), bits, { ...d.pow, signal: d.signal, onProgress: d.onProgress });
  if (d.signal?.aborted) throw abortError();

  const body = {
    platform: 'web',
    challenge: ch.challenge,
    public_key: publicKeySpki,
    app_version: d.appVersion,
    caps: { sig: [1], cfg: d.cfgSeq },
    web: turnstile ? { pow: solution, turnstile_token: turnstile } : { pow: solution },
    renew: !!d.signed,
  };
  const bytes = utf8(JSON.stringify(body));
  const call = d.signed ? d.signed(new URL(`${d.restrictoUrl}/device/register/`), bytes) : undefined;
  const reg = await post(d, 'register', body, 'register_failed', call);
  const deviceId = reg.device_id;
  const until = num(reg.attested_until);
  if (typeof deviceId !== 'string' || !/^rd_[A-Za-z0-9_.:-]{1,61}$/.test(deviceId) || until === undefined)
    throw new RestrictoError('register_failed', 'Malformed register response.');
  const now = num(reg.server_time);
  if (now && !d.signed) d.clock.sync(now);
  return {
    deviceId,
    trustLevel: num(reg.trust_level) ?? 0,
    attestedUntil: until,
    serverTime: now ?? d.clock.now(),
    maxClockSkew: num(reg.max_clock_skew) ?? 90,
    cfgSeq: num(reg.cfg_seq),
  };
}
