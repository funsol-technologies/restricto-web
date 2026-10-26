import type { Clock } from './clock';
import { abortError, readServerCode, RestrictoError } from './errors';
import { solvePow, type PowOptions } from './pow';

export interface Registration {
  deviceId: string;
  trustLevel: number;
  /** unix seconds, server clock */
  attestedUntil: number;
  serverTime: number;
  maxClockSkew: number;
}

export interface RegisterDeps {
  /** e.g. https://api.example.com/restricto - no trailing slash */
  restrictoUrl: string;
  appId: string;
  appVersion: string;
  fetch: typeof fetch;
  clock: Clock;
  getTurnstileToken?: () => Promise<string | undefined>;
  pow?: Pick<PowOptions, 'useWorker' | 'createWorker'>;
  onProgress?: (attempts: number) => void;
  signal?: AbortSignal;
}

async function post(d: RegisterDeps, path: string, body: unknown, failure: 'challenge_failed' | 'register_failed'): Promise<Record<string, unknown>> {
  let res: Response;
  try {
    res = await d.fetch(`${d.restrictoUrl}/device/${path}/`, {
      method: 'POST',
      headers: { 'X-APP-ID': d.appId, ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: d.signal,
      credentials: 'omit',
    });
  } catch (e) {
    if (d.signal?.aborted) throw abortError();
    throw new RestrictoError(failure, `Could not reach ${path} endpoint: ${(e as Error).message}`, { cause: e });
  }
  if (!res.ok) {
    const retry = Number(res.headers.get('Retry-After'));
    throw new RestrictoError(failure, `Server refused ${path} (HTTP ${res.status}).`, {
      status: res.status,
      serverCode: await readServerCode(res),
      retryAfter: Number.isFinite(retry) && retry > 0 ? retry : undefined,
    });
  }
  const json: unknown = await res.json().catch(() => undefined);
  if (!json || typeof json !== 'object') throw new RestrictoError(failure, `Malformed ${path} response.`, { status: res.status });
  return json as Record<string, unknown>;
}

/** challenge -> proof of work -> register. The same key and a fresh challenge renews an existing registration. */
export async function registerDevice(d: RegisterDeps, publicKeySpki: string): Promise<Registration> {
  // the Turnstile token is fetched first: it may need user interaction and the challenge lives only ~2 minutes
  const turnstile = d.getTurnstileToken ? await d.getTurnstileToken() : undefined;
  const ch = await post(d, 'challenge', undefined, 'challenge_failed');
  if (typeof ch.challenge !== 'string') throw new RestrictoError('challenge_failed', 'Challenge response has no challenge.');
  if (typeof ch.server_time === 'number') d.clock.sync(ch.server_time);
  const bits = typeof ch.pow_bits === 'number' ? ch.pow_bits : 0;
  const pow = await solvePow(ch.challenge, bits, { ...d.pow, signal: d.signal, onProgress: d.onProgress });

  const reg = await post(
    d,
    'register',
    {
      platform: 'web',
      challenge: ch.challenge,
      public_key: publicKeySpki,
      app_version: d.appVersion,
      web: turnstile ? { pow, turnstile_token: turnstile } : { pow },
    },
    'register_failed',
  );
  if (typeof reg.device_id !== 'string' || typeof reg.attested_until !== 'number')
    throw new RestrictoError('register_failed', 'Malformed register response.');
  if (typeof reg.server_time === 'number') d.clock.sync(reg.server_time);
  return {
    deviceId: reg.device_id,
    trustLevel: typeof reg.trust_level === 'number' ? reg.trust_level : 0,
    attestedUntil: reg.attested_until,
    serverTime: typeof reg.server_time === 'number' ? reg.server_time : d.clock.now(),
    maxClockSkew: typeof reg.max_clock_skew === 'number' ? reg.max_clock_skew : 90,
  };
}
