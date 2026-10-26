import { DEFAULT_MAX_BODY_BYTES, prepareBody, type PreparedBody } from './body';
import { Clock } from './clock';
import { b64urlEncode } from './encoding';
import { readServerCode, RestrictoError, ServerCode } from './errors';
import { defaultKeyStore, type StoredDevice } from './key-store';
import { withLock } from './lock';
import { registerDevice, type Registration } from './register';
import { signRequest } from './sign';
import type { RestrictoClient, RestrictoConfig, RestrictoState, SignedRequest, SignInput } from './types';
import { createKeyResolver, unverified, verifyResponseSignature, type ResponseKeyMap } from './verify';

const IDLE: RestrictoState = { status: 'idle', deviceId: null, trustLevel: null, attestedUntil: null, error: null };
const MAX_TIMEOUT = 2 ** 31 - 1;
const REQUEST_PROPS = ['credentials', 'mode', 'cache', 'redirect', 'referrer', 'referrerPolicy', 'integrity', 'keepalive', 'signal'] as const;

type Renew = { stale?: number } | { fresh: true };

interface Prepared {
  url: URL;
  method: string;
  headers: Headers;
  body: PreparedBody;
  rest: RequestInit;
}

export function createRestricto(config: RestrictoConfig): RestrictoClient {
  if (!config.baseUrl || !config.appId) throw new RestrictoError('config', '`baseUrl` and `appId` are required.');
  if (config.pinnedResponseKeys && Object.keys(config.pinnedResponseKeys).length === 0)
    throw new RestrictoError('config', '`pinnedResponseKeys` is empty; omit it to fetch keys from the server instead.');
  const base = new URL(config.baseUrl);
  const origin = base.origin;
  const restrictoUrl = origin + (config.restrictoPath ?? '/restricto').replace(/\/+$/, '');
  const appId = config.appId;
  const namespace = `${appId}|${origin}`;
  const mode = config.verifyResponses ?? 'strict';
  const maxBody = config.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES;
  const cooldown = config.registerCooldownMs ?? 5000;
  const warn = config.onWarning ?? ((m: string) => console.warn(`[restricto] ${m}`));
  const store = config.keyStore ?? defaultKeyStore();
  const clock = new Clock();
  const rawFetch: typeof fetch = config.fetch ?? ((input, init) => globalThis.fetch(input, init));
  const verified = new WeakSet<Response>();

  let state = IDLE;
  const listeners = new Set<(s: RestrictoState) => void>();
  const setState = (patch: Partial<RestrictoState>): void => {
    state = { ...state, ...patch };
    listeners.forEach((l) => l(state));
  };

  let device: StoredDevice | undefined;
  let generation = 0;
  let validity = 0;
  let registering: Promise<StoredDevice> | undefined;
  let failure: { at: number; error: RestrictoError } | undefined;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let backgroundRenewAt = 0;

  const keys = createKeyResolver(config.pinnedResponseKeys, async () => {
    const res = await rawFetch(`${restrictoUrl}/keys/`, { headers: { 'X-APP-ID': appId }, credentials: 'omit' });
    if (!res.ok) throw new RestrictoError('keys_unavailable', `Could not fetch response keys (HTTP ${res.status}).`, { status: res.status });
    const body = (await res.json()) as { keys?: Array<{ kid?: string; public_key?: string }> };
    const out: ResponseKeyMap = {};
    for (const k of body.keys ?? []) if (k.kid && k.public_key) out[k.kid] = k.public_key;
    return out;
  });

  const marginFor = (): number => Math.min(config.refreshMarginSeconds ?? 6 * 3600, validity > 0 ? validity / 4 : Infinity);
  const isFresh = (d: StoredDevice | undefined): d is StoredDevice & { deviceId: string; attestedUntil: number } =>
    !!d && !!d.deviceId && !!d.attestedUntil && d.attestedUntil > clock.now();

  function requireCrypto(): void {
    if (typeof crypto === 'undefined' || !crypto.subtle)
      throw new RestrictoError('unsupported_environment', 'WebCrypto is unavailable; browsers expose it only on https:// pages and localhost.');
  }

  async function generateKey(): Promise<StoredDevice> {
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
    const spki = new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey));
    return { privateKey: pair.privateKey, publicKey: b64urlEncode(spki) };
  }

  function applyDevice(d: StoredDevice, reg?: Registration): void {
    device = d;
    generation++;
    if (reg) validity = Math.max(0, reg.attestedUntil - reg.serverTime);
    failure = undefined;
    setState({ status: 'ready', deviceId: d.deviceId ?? null, trustLevel: d.trustLevel ?? null, attestedUntil: d.attestedUntil ?? null, error: null });
    scheduleRenewal();
  }

  function scheduleRenewal(): void {
    if (timer) clearTimeout(timer);
    timer = undefined;
    if (config.autoRefresh === false || !device?.attestedUntil) return;
    const ms = Math.min(MAX_TIMEOUT, Math.max(1000, (device.attestedUntil - marginFor() - clock.now()) * 1000));
    timer = setTimeout(() => void renewInBackground(), ms);
    (timer as { unref?: () => void }).unref?.();
  }

  async function renewInBackground(): Promise<void> {
    if (registering || Date.now() < backgroundRenewAt) return;
    try {
      await ensureReady({ stale: device?.attestedUntil });
    } catch (e) {
      backgroundRenewAt = Date.now() + 60_000;
      warn(`background renewal failed: ${(e as Error).message}`);
    }
  }

  async function register(renew: Renew | undefined): Promise<StoredDevice> {
    requireCrypto();
    setState({ status: 'registering', error: null });
    const done = await withLock(
      `restricto:${namespace}`,
      async () => {
        let rec = await store.get(namespace);
        if (renew && 'fresh' in renew) {
          await store.delete(namespace);
          rec = undefined;
        } else if (isFresh(rec) && (!renew || rec.attestedUntil !== renew.stale) && rec.attestedUntil - clock.now() > marginFor()) {
          return { rec, reg: undefined }; // another tab finished while we waited for the lock
        }
        if (!rec) {
          rec = await generateKey();
          await store.put(namespace, rec);
        }
        const reg = await registerDevice(
          {
            restrictoUrl,
            appId,
            appVersion: config.appVersion ?? 'web-1.0.0',
            fetch: rawFetch,
            clock,
            getTurnstileToken: config.getTurnstileToken,
            pow: config.pow,
            onProgress: config.onPowProgress,
          },
          rec.publicKey,
        );
        rec = { ...rec, deviceId: reg.deviceId, trustLevel: reg.trustLevel, attestedUntil: reg.attestedUntil };
        await store.put(namespace, rec);
        return { rec, reg };
      },
      config.useWebLocks !== false,
    );
    applyDevice(done.rec, done.reg);
    return done.rec;
  }

  /** Single-flight: every concurrent caller in this page awaits the same registration. */
  function ensureReady(renew?: Renew): Promise<StoredDevice> {
    if (registering) return registering;
    if (!renew) {
      if (device && isFresh(device)) {
        if (device.attestedUntil! - clock.now() < marginFor()) void renewInBackground();
        return Promise.resolve(device);
      }
    }
    if (failure && Date.now() - failure.at < (failure.error.retryAfter ? failure.error.retryAfter * 1000 : cooldown)) return Promise.reject(failure.error);
    const p = register(renew).catch((e: unknown) => {
      const err = e instanceof RestrictoError ? e : new RestrictoError('register_failed', (e as Error).message, { cause: e });
      failure = { at: Date.now(), error: err };
      setState({ status: 'error', error: err });
      throw err;
    });
    registering = p;
    const clear = (): void => {
      if (registering === p) registering = undefined;
    };
    p.then(clear, clear);
    return p;
  }

  function resolveUrl(input: RequestInfo | URL): URL {
    const raw = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    return new URL(raw, typeof location !== 'undefined' ? location.href : base.href);
  }

  async function prepare(input: RequestInfo | URL, init: RequestInit | undefined, url: URL): Promise<Prepared> {
    const req = typeof Request !== 'undefined' && input instanceof Request ? input : undefined;
    const headers = new Headers(req?.headers);
    if (init?.headers) new Headers(init.headers).forEach((v, k) => headers.set(k, v));
    if (headers.has('authorization'))
      throw new RestrictoError('authorization_conflict', 'Restricto-Sig uses the Authorization header; send your own credentials in another header.');
    let body: PreparedBody;
    if (init?.body !== undefined && init.body !== null) body = await prepareBody(init.body, maxBody);
    else if (req && req.body) {
      if ((req.headers.get('content-type') ?? '').startsWith('multipart/form-data'))
        throw new RestrictoError('unsupported_body', 'Multipart bodies cannot be signed; sign uploads via presigned URLs.');
      const bytes = new Uint8Array(await req.clone().arrayBuffer());
      body = await prepareBody(bytes, maxBody);
    } else body = { bytes: undefined, send: undefined };
    const rest: RequestInit = {};
    if (req) for (const k of REQUEST_PROPS) (rest as Record<string, unknown>)[k] = req[k];
    if (init) for (const [k, v] of Object.entries(init)) if (k !== 'body' && k !== 'headers' && k !== 'method') (rest as Record<string, unknown>)[k] = v;
    return { url, method: (init?.method ?? req?.method ?? 'GET').toUpperCase(), headers, body, rest };
  }

  async function signNow(method: string, url: URL, bytes: Uint8Array | undefined) {
    const dev = await ensureReady();
    const gen = generation;
    const signed = await signRequest({ privateKey: dev.privateKey, deviceId: dev.deviceId!, appId, clock }, method, url, bytes);
    return { signed, dev, gen };
  }

  function toSignedRequest(s: Awaited<ReturnType<typeof signNow>>): SignedRequest & { gen: number; attestedUntil: number | undefined } {
    return {
      headers: s.signed.headers,
      nonce: s.signed.nonce,
      ts: s.signed.ts,
      deviceId: s.dev.deviceId!,
      gen: s.gen,
      attestedUntil: s.dev.attestedUntil,
      verify: (response) => checkResponse(response, s.signed.nonce, s.dev.deviceId!),
    };
  }

  const isRejection = (status: number, code: number | undefined): boolean => status >= 400 && code !== undefined && code >= 458000 && code < 459000;

  /** Returns after verifying (or deliberately tolerating) a response; throws in strict mode. */
  async function checkResponse(res: Response, nonce: string, deviceId: string): Promise<void> {
    if (mode === 'off') return;
    const out = await verifyResponseSignature(res, { nonce, deviceId, clock, keys, forceFallback: config.forceEd25519Fallback });
    if (out.ok) {
      verified.add(res);
      return;
    }
    // The server cannot sign rejections that happen before the device is identified (skew, unknown device, ...): those
    // carry only an opaque denial, so they are handed back flagged as unverified instead of failing the caller.
    if (out.unsigned && isRejection(res.status, await readServerCode(res))) return;
    if (mode === 'strict') throw unverified(out.reason);
    warn(`response not verified: ${out.reason}`);
  }

  async function recover(res: Response, ctx: { gen: number; attestedUntil: number | undefined }): Promise<boolean> {
    if (res.status !== 401 && res.status !== 403) return false;
    const code = await readServerCode(res);
    switch (code) {
      case ServerCode.ClockSkew: {
        const t = Number(res.headers.get('X-Restricto-Server-Time'));
        if (!Number.isFinite(t) || t <= 0) return false;
        clock.sync(t);
        return true;
      }
      case ServerCode.Replay:
        return true;
      case ServerCode.UnknownDevice:
      case ServerCode.AttestationExpired:
        // another call may already have renewed since this request was signed
        if (generation === ctx.gen) await ensureReady({ stale: ctx.attestedUntil });
        return true;
      case ServerCode.DeviceRevoked:
        if (generation === ctx.gen) {
          await store.delete(namespace);
          device = undefined;
          await ensureReady({ fresh: true });
        }
        return true;
      default:
        return false;
    }
  }

  async function signedFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    const url = resolveUrl(input);
    if (url.origin !== origin) return rawFetch(input, init);
    const p = await prepare(input, init, url);
    for (let attempt = 0; ; attempt++) {
      const s = await signNow(p.method, p.url, p.body.bytes);
      const headers = new Headers(p.headers);
      await config.onRequest?.(headers, { method: p.method, url: p.url });
      for (const [k, v] of Object.entries(s.signed.headers)) headers.set(k, v);
      const res = await rawFetch(p.url.href, { ...p.rest, method: p.method, headers, body: p.body.send });
      if (attempt === 0 && (await recover(res, { gen: s.gen, attestedUntil: s.dev.attestedUntil }))) continue;
      await checkResponse(res, s.signed.nonce, s.dev.deviceId!);
      return res;
    }
  }

  const client: RestrictoClient = {
    appId,
    fetch: signedFetch,
    async sign(input: SignInput) {
      const url = resolveUrl(input.url);
      if (url.origin !== origin) throw new RestrictoError('config', `Refusing to sign for ${url.origin}: only ${origin} is configured.`);
      const body = await prepareBody(input.body, maxBody);
      return toSignedRequest(await signNow((input.method ?? 'GET').toUpperCase(), url, body.bytes));
    },
    recover: (res, signed) => recover(res, signed as unknown as { gen: number; attestedUntil: number | undefined }),
    async ready() {
      await ensureReady();
      return state;
    },
    getState: () => state,
    subscribe(l) {
      listeners.add(l);
      return () => void listeners.delete(l);
    },
    isVerified: (res) => verified.has(res),
    async reset() {
      await store.delete(namespace);
      device = undefined;
      failure = undefined;
      if (timer) clearTimeout(timer);
      setState({ ...IDLE });
    },
    close() {
      if (timer) clearTimeout(timer);
      timer = undefined;
    },
  };

  if (config.autoRegister && typeof window !== 'undefined') void client.ready().catch(() => undefined);
  return client;
}
