import { DEFAULT_MAX_BODY_BYTES, prepareBody, type PreparedBody } from './body';
import { Clock } from './clock';
import { compareVersions, DEFAULTS, type ConfigDocument, type ConfigValues } from './config-defaults';
import { b64urlEncode } from './encoding';
import { abortError, parseRetryAfter, RestrictoError } from './errors';
import { defaultKeyStore, type StoredConfig, type StoredDevice } from './key-store';
import { withLock } from './lock';
import { fromOrigin } from './net';
import { registerDevice, type Registration, type SignedCall } from './register';
import { signRequest } from './sign';
import type { ConfigStatus, RestrictoClient, RestrictoConfig, RestrictoState, SignedRequest, SignInput, UpgradeInfo, VerifyMode } from './types';
import { SDK_VERSION } from './version';
import { createKeyResolver, parseRespKeys, unverified, verifyResponseSignature } from './verify';

const NO_CONFIG: ConfigStatus = { source: 'none', seq: null, exp: null, relaxed: false, lastError: null };
const IDLE: RestrictoState = { status: 'idle', deviceId: null, trustLevel: null, attestedUntil: null, error: null, config: NO_CONFIG, upgrade: null };
const MAX_TIMEOUT = 2 ** 31 - 1;
/** A grant shorter than this is treated as "already expired" (A-3): otherwise every call would re-register. */
const MIN_VALIDITY_SECONDS = 30;
const MAX_RTT_FOR_CLOCK_SECONDS = 10;
const REQUEST_PROPS = ['credentials', 'mode', 'cache', 'referrer', 'referrerPolicy', 'integrity', 'keepalive', 'signal'] as const;
const IDEMPOTENT = new Set(['GET', 'HEAD', 'OPTIONS']);

/** `stale`: the attestation we saw rejected; `wipe`: the public key that was told to be discarded (so a second tab does not mint another). */
type Renew = { stale?: number } | { wipe: string };

interface Prepared {
  url: URL;
  method: string;
  headers: Headers;
  body: PreparedBody;
  rest: RequestInit;
}

interface SignCtx {
  nonce: string;
  deviceId: string;
  method: string;
  sentAt: number;
  gen: number;
  publicKey: string;
  attestedUntil: number | undefined;
}

interface ErrBody {
  action?: string;
  errorCode: number;
  serverTime?: number;
  cfgSeq?: number;
}

interface Assessment {
  verified: boolean;
  kind?: 'unsigned' | 'invalid' | 'redirect' | 'off';
  reason: string;
  body?: ErrBody;
}

interface Budget {
  replay: number;
  unknown: number;
  transient: number;
  clock: number;
}

const finite = (v: unknown): number | undefined => (typeof v === 'number' && Number.isFinite(v) ? v : undefined);

export function createRestricto(config: RestrictoConfig): RestrictoClient {
  if (!config.baseUrl || !config.appId) throw new RestrictoError('config', '`baseUrl` and `appId` are required.');
  if (config.pinnedResponseKeys && Object.keys(config.pinnedResponseKeys).length === 0)
    throw new RestrictoError('config', '`pinnedResponseKeys` is empty; omit it to use the signed config or `/keys/` instead.');
  if (config.pinnedConfigKeys && Object.keys(config.pinnedConfigKeys).length === 0)
    throw new RestrictoError('config', '`pinnedConfigKeys` is empty; omit it to run without a signed config document.');
  const base = new URL(config.baseUrl);
  const origin = base.origin;
  const restrictoUrl = origin + (config.restrictoPath ?? '/restricto').replace(/\/+$/, '');
  const appId = config.appId;
  const namespace = `${appId}|${origin}`;
  const lockName = `restricto:${namespace}`;
  const userMode: VerifyMode = config.verifyResponses ?? 'strict';
  const maxBody = config.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES;
  const warn = config.onWarning ?? ((m: string) => console.warn(`[restricto] ${m}`));
  const store = config.keyStore ?? defaultKeyStore();
  const clock = new Clock();
  const rawFetch: typeof fetch = config.fetch ?? ((input, init) => globalThis.fetch(input, init));
  const redirectMode = config.redirect ?? 'manual';
  const pins = config.pinnedConfigKeys;
  const verified = new WeakSet<Response>();
  const assessments = new WeakMap<Response, Assessment>();
  const contexts = new WeakMap<SignedRequest, SignCtx>();

  let state: RestrictoState = pins ? { ...IDLE, config: { ...NO_CONFIG, source: 'defaults' } } : IDLE;
  const listeners = new Set<(s: RestrictoState) => void>();
  const setState = (patch: Partial<RestrictoState>): void => {
    state = { ...state, ...patch };
    listeners.forEach((l) => l(state));
  };

  let device: StoredDevice | undefined;
  let generation = 0;
  let epoch = 0;
  let life = new AbortController();
  let validity = 0;
  let registering: Promise<StoredDevice> | undefined;
  let failure: { at: number; error: RestrictoError } | undefined;
  let failures = 0;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let notBefore = 0;

  // ---- signed config document (spec section 6) -------------------------------------------------------------------------------
  let cfg: { doc: ConfigDocument; values: ConfigValues } | undefined;
  let highSeq = 0;
  let cfgInit: Promise<void> | undefined;
  let cfgInflight: Promise<void> | undefined;
  let cfgLast = 0;
  let cfgFailures = 0;
  let cfgError: string | null = null;
  let advisory: UpgradeInfo | undefined;
  const v = (): ConfigValues => cfg?.values ?? DEFAULTS;
  const cfgExpired = (): boolean => !!cfg && cfg.values.exp <= clock.now();
  /** `relax` only while the document is valid; a relaxed strict mode is a warn mode, never off. */
  const mode = (): VerifyMode => (userMode === 'strict' && cfg?.values.relaxVerify && !cfgExpired() ? 'warn' : userMode);

  function configStatus(): ConfigStatus {
    if (!pins) return NO_CONFIG;
    if (!cfg) return { source: 'defaults', seq: highSeq || null, exp: null, relaxed: false, lastError: cfgError };
    const expired = cfgExpired();
    return { source: expired ? 'expired' : 'valid', seq: cfg.values.seq, exp: cfg.values.exp, relaxed: mode() !== userMode, lastError: cfgError };
  }

  function configUpgrade(): UpgradeInfo | undefined {
    const c = cfg?.values;
    if (!c) return undefined;
    const url = c.upgrade.url;
    if (c.minSdk && compareVersions(SDK_VERSION, c.minSdk) < 0) return { mode: 'hard', reason: 'min_sdk', url, minSdk: c.minSdk };
    if (!c.sigVersions.includes(1)) return { mode: 'hard', reason: 'sig_version', url };
    if (c.upgrade.mode !== 'none') return { mode: c.upgrade.mode, reason: 'config', url, minSdk: c.minSdk };
    return undefined;
  }

  /** Re-derive everything the UI can see from the config + advisory sources; fires the upgrade event on a change. */
  function syncDerived(): void {
    const status = configStatus();
    const up = configUpgrade() ?? advisory ?? null;
    const prev = state.upgrade;
    const cs = state.config;
    const same = cs.source === status.source && cs.seq === status.seq && cs.exp === status.exp && cs.relaxed === status.relaxed && cs.lastError === status.lastError;
    if (same && prev === up) return;
    setState({ config: status, upgrade: up });
    if (up && (!prev || prev.mode !== up.mode || prev.reason !== up.reason)) config.onUpgradeRequired?.(up);
  }

  async function adoptDocument(raw: unknown, source: 'network' | 'store'): Promise<boolean> {
    // the document parser is only needed (and only loaded) when config keys are pinned
    const { verifyConfigDocument } = await import('./config');
    const check = await verifyConfigDocument(raw, appId, pins!, config.forceEd25519Fallback);
    if (!check.ok) return reject(`config document rejected (${check.reason})`);
    const next = check.values;
    if (next.seq < highSeq) return reject(`config document rejected (seq ${next.seq} < ${highSeq}: rollback)`);
    if (next.exp <= clock.now() && cfg && source === 'network') return reject('config document rejected (expired); keeping the last good one');
    cfg = { doc: raw as ConfigDocument, values: next };
    highSeq = Math.max(highSeq, next.seq);
    cfgError = null;
    if (source === 'network') await store.putConfig?.(namespace, { doc: cfg.doc, seq: highSeq } satisfies StoredConfig).catch(() => undefined);
    scheduleRenewal();
    syncDerived();
    return true;
  }

  function reject(why: string): false {
    cfgError = why;
    warn(why);
    syncDerived();
    return false;
  }

  async function loadStoredConfig(): Promise<void> {
    const saved = await store.getConfig?.(namespace).catch(() => undefined);
    if (!saved) return;
    // the stored document is verified again: a tampered store cannot inject keys; its seq stays the anti-rollback floor either way
    if (Number.isSafeInteger(saved.seq)) highSeq = Math.max(highSeq, saved.seq);
    await adoptDocument(saved.doc, 'store');
  }

  async function fetchConfig(): Promise<void> {
    // a hanging config endpoint must not hold up the first signed call for ever
    const ac = new AbortController();
    const stop = (): void => ac.abort();
    life.signal.addEventListener('abort', stop);
    const timeout = setTimeout(stop, config.configTimeoutMs ?? 8000);
    try {
      const res = await rawFetch(`${restrictoUrl}/config/`, { headers: { 'X-APP-ID': appId }, credentials: 'omit', redirect: 'error', signal: ac.signal });
      if (!res.ok || !fromOrigin(res, origin)) throw new Error(`HTTP ${res.status}`);
      await adoptDocument(await res.json(), 'network');
    } finally {
      clearTimeout(timeout);
      life.signal.removeEventListener('abort', stop);
    }
  }

  /** Throttled, single-flight. `gapMs`: do nothing when an attempt was made more recently than that. */
  function refreshConfigNow(gapMs: number): Promise<void> {
    if (!pins) return Promise.resolve();
    if (cfgInflight) return cfgInflight;
    const wait = cfgFailures ? Math.max(gapMs, v().renew.backoff[Math.min(cfgFailures - 1, v().renew.backoff.length - 1)]! * 1000) : gapMs;
    if (Date.now() - cfgLast < wait) return Promise.resolve();
    cfgLast = Date.now();
    const p = fetchConfig()
      .then(() => void (cfgFailures = 0))
      .catch((e: unknown) => {
        cfgFailures++;
        cfgError = `config document unavailable: ${(e as Error).message}`;
        if (!cfg) warn(cfgError);
        syncDerived();
      })
      .finally(() => {
        cfgInflight = undefined;
      });
    cfgInflight = p;
    return p;
  }

  /** First use: stored document, then the network. Without any document the keys are the pinned response keys, or none (fail closed). */
  function ensureConfig(): Promise<void> {
    if (!pins) return Promise.resolve();
    cfgInit ??= loadStoredConfig()
      .then(() => refreshConfigNow(0))
      .then(() => {
        if (!cfg) cfgInit = undefined; // nothing usable yet: try again on a later call (throttled by the backoff ladder)
      });
    // keep the document fresh in the background: refetch at 3/4 of its lifetime, and whenever it has expired
    if (cfg && cfg.values.exp - clock.now() < Math.max(3600, Math.min(86400, (cfg.values.exp - cfg.values.iat) / 4 || 86400))) void refreshConfigNow(5 * 60_000);
    return cfgInit;
  }

  /** A higher `cfg_seq` reported by a challenge / register / signed error body: refetch (unsigned hints only ever cause a fetch). */
  function noteCfgSeq(n: number | undefined): void {
    if (pins && n !== undefined && n > Math.max(cfg?.values.seq ?? 0, highSeq)) void refreshConfigNow(15_000);
  }

  function noteSigVersions(list: number[] | undefined): void {
    if (list && !list.includes(1) && !configUpgrade()) {
      advisory = { mode: 'soft', reason: 'sig_version', url: '' };
      syncDerived();
    }
  }

  const keys = createKeyResolver({
    pinned: config.pinnedResponseKeys,
    config: () => (cfg ? cfg.values.respKeys : undefined),
    configPinned: !!pins,
    refreshConfig: async () => {
      await ensureConfig();
      await refreshConfigNow(60_000);
      if (!cfg && !config.pinnedResponseKeys) throw new RestrictoError('keys_unavailable', 'The signed config document could not be loaded, so responses cannot be verified.');
    },
    tofu: async () => {
      const res = await rawFetch(`${restrictoUrl}/keys/`, { headers: { 'X-APP-ID': appId }, credentials: 'omit', redirect: 'error' });
      if (!res.ok || !fromOrigin(res, origin)) throw new RestrictoError('keys_unavailable', `Could not fetch response keys (HTTP ${res.status}).`, { status: res.status });
      const body = (await res.json()) as { alg?: string; keys?: unknown[] };
      return parseRespKeys((body.keys ?? []).map((k) => ({ alg: body.alg ?? 'Ed25519', ...(k as object) })));
    },
  });

  // ---- registration ------------------------------------------------------------------------------------------------------------
  const marginFor = (): number => Math.min(config.refreshMarginSeconds ?? v().renew.beforeS, validity > 0 ? validity / 4 : Infinity);
  const isFresh = (d: StoredDevice | undefined): d is StoredDevice & { deviceId: string; attestedUntil: number } =>
    !!d && !!d.deviceId && !!d.attestedUntil && d.attestedUntil > clock.now();
  const ladder = (n: number): number => v().renew.backoff[Math.min(Math.max(n, 1), v().renew.backoff.length) - 1]! * 1000;

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
    if (reg) {
      validity = Math.max(0, reg.attestedUntil - reg.serverTime);
      notBefore = Date.now() + 30_000;
      noteCfgSeq(reg.cfgSeq);
    }
    failure = undefined;
    failures = 0;
    setState({ status: 'ready', deviceId: d.deviceId ?? null, trustLevel: d.trustLevel ?? null, attestedUntil: d.attestedUntil ?? null, error: null });
    scheduleRenewal();
  }

  function scheduleRenewal(delayMs?: number): void {
    if (timer) clearTimeout(timer);
    timer = undefined;
    if (config.autoRefresh === false || !device?.attestedUntil) return;
    const jitter = 1 - v().renew.jitter * Math.random();
    const ms = delayMs ?? Math.max(1000, (device.attestedUntil - marginFor() - clock.now()) * 1000 * jitter);
    timer = setTimeout(() => void renewInBackground(), Math.min(MAX_TIMEOUT, ms));
    (timer as { unref?: () => void }).unref?.();
  }

  async function renewInBackground(): Promise<void> {
    if (registering || Date.now() < notBefore) return;
    try {
      await ensureReady({ stale: device?.attestedUntil });
    } catch (e) {
      if ((e as RestrictoError).code === 'aborted') return;
      warn(`background renewal failed: ${(e as Error).message}`);
      scheduleRenewal(Math.max(ladder(failures), 1000));
    }
  }

  /** A signed `renew:true` request: possession of the existing key, and the answer must verify before anything is adopted. */
  function renewCall(rec: StoredDevice): (url: URL, body: Uint8Array) => Promise<SignedCall> {
    return async (url, body) => {
      const s = await signRequest({ privateKey: rec.privateKey, deviceId: rec.deviceId!, appId, clock }, 'POST', url, body);
      const ctx = { nonce: s.nonce, deviceId: rec.deviceId!, method: 'POST', sentAt: Date.now() };
      return {
        headers: { ...s.headers },
        verify: async (res) => {
          const a = await assess(res, ctx);
          if (!a.verified && mode() !== 'off') throw unverified(a.reason, { unsigned: true, status: res.status });
          return a.body?.action;
        },
      };
    };
  }

  async function register(renew: Renew | undefined): Promise<StoredDevice> {
    requireCrypto();
    const myEpoch = epoch;
    const signal = life.signal;
    setState({ status: 'registering', error: null });
    const done = await withLock(
      lockName,
      async () => {
        if (epoch !== myEpoch) throw abortError();
        let rec = await store.get(namespace);
        if (renew && 'wipe' in renew) {
          // Re-checked under the lock: another tab may already have replaced the key we were told to discard.
          if (rec && rec.publicKey !== renew.wipe) {
            if (isFresh(rec)) return { rec, reg: undefined };
          } else {
            await store.delete(namespace);
            rec = undefined;
          }
        } else if (isFresh(rec) && (!renew || rec.attestedUntil !== renew.stale) && rec.attestedUntil - clock.now() > marginFor()) {
          return { rec, reg: undefined }; // another tab finished while we waited for the lock
        }
        if (!rec) {
          rec = await generateKey();
          await store.put(namespace, rec);
        }
        const deps = (signed?: (url: URL, body: Uint8Array) => Promise<SignedCall>) => ({
          restrictoUrl,
          origin,
          appId,
          appVersion: config.appVersion ?? 'web-1.0.0',
          fetch: rawFetch,
          clock,
          getTurnstileToken: config.getTurnstileToken,
          pow: { ...config.pow, budgetMs: config.powBudgetMs },
          powBits: v().pow.bits,
          powMaxBits: v().pow.maxBits,
          cfgSeq: cfg?.values.seq ?? 0,
          onProgress: config.onPowProgress,
          signal,
          onChallenge: (c: { sigVersions?: number[]; cfgSeq?: number }) => {
            noteSigVersions(c.sigVersions);
            noteCfgSeq(c.cfgSeq);
          },
          signed,
        });
        let reg: Registration;
        if (rec.deviceId && !rec.noRenew && config.signedRenewal !== false) {
          try {
            reg = await registerDevice(deps(renewCall(rec)), rec.publicKey);
          } catch (e) {
            const err = e as RestrictoError;
            // Only a VERIFIED refusal may change what we do. Unsigned / unverifiable answers are network errors: the key and the
            // registration stay exactly as they are and the caller backs off.
            if (!(err instanceof RestrictoError) || err.code !== 'register_failed' || err.unsigned || !err.status || err.status < 400 || err.status >= 500 || err.status === 429) throw err;
            if (err.action === 'backoff' || err.action === 'upgrade') throw err;
            if (err.action === 'wipe') {
              await store.delete(namespace);
              rec = await generateKey();
              await store.put(namespace, rec);
            } else if (err.action !== 'reregister') rec = { ...rec, noRenew: true }; // this server does not do signed web renewals
            reg = await registerDevice(deps(), rec.publicKey);
          }
        } else reg = await registerDevice(deps(), rec.publicKey);
        if (epoch !== myEpoch || signal.aborted) throw abortError();
        // A grant that is already (nearly) expired would make every call re-register (and re-solve the proof of work).
        if (reg.attestedUntil - clock.now() < MIN_VALIDITY_SECONDS)
          throw new RestrictoError('register_failed', 'The server granted an attestation that is already expired or about to; check the server clock and its validity setting.', { retryAfter: 60 });
        rec = { ...rec, deviceId: reg.deviceId, trustLevel: reg.trustLevel, attestedUntil: reg.attestedUntil };
        await store.put(namespace, rec);
        return { rec, reg };
      },
      config.useWebLocks !== false,
    );
    if (epoch !== myEpoch) throw abortError();
    applyDevice(done.rec, done.reg);
    return done.rec;
  }

  /** Single-flight: every concurrent caller in this page awaits the same registration. */
  async function ensureReady(renew?: Renew): Promise<StoredDevice> {
    while (registering) {
      if (!renew || !('wipe' in renew)) return registering;
      await registering.catch(() => undefined); // a wipe must act on the outcome of the registration in flight, not race it
    }
    if (!renew && device && isFresh(device)) {
      if (device.attestedUntil! - clock.now() < marginFor() && Date.now() >= notBefore) void renewInBackground();
      return device;
    }
    const wait = failure && (failure.error.retryAfter ? failure.error.retryAfter * 1000 : (config.registerCooldownMs ?? ladder(failures)));
    if (failure && Date.now() - failure.at < wait!) throw failure.error;
    const myEpoch = epoch;
    const p = register(renew).catch((e: unknown) => {
      const err = e instanceof RestrictoError ? e : new RestrictoError('register_failed', (e as Error).message, { cause: e });
      if (err.code !== 'aborted' && myEpoch === epoch) {
        failure = { at: Date.now(), error: err };
        failures++;
        setState({ status: 'error', error: err });
      }
      throw err;
    });
    registering = p;
    const clear = (): void => {
      if (registering === p) registering = undefined;
    };
    p.then(clear, clear);
    return p;
  }

  // ---- requests ----------------------------------------------------------------------------------------------------------------
  function resolveUrl(input: RequestInfo | URL): URL {
    const raw = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    return new URL(raw, typeof location !== 'undefined' ? location.href : base.href);
  }

  async function prepare(input: RequestInfo | URL, init: RequestInit | undefined, url: URL): Promise<Prepared> {
    const req = typeof Request !== 'undefined' && input instanceof Request ? input : undefined;
    const headers = new Headers(req?.headers);
    if (init?.headers) new Headers(init.headers).forEach((val, k) => headers.set(k, val));
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
    if (init) for (const [k, val] of Object.entries(init)) if (k !== 'body' && k !== 'headers' && k !== 'method' && k !== 'redirect') (rest as Record<string, unknown>)[k] = val;
    return { url, method: (init?.method ?? req?.method ?? 'GET').toUpperCase(), headers, body, rest };
  }

  async function signNow(method: string, url: URL, bytes: Uint8Array | undefined) {
    await ensureConfig();
    if (state.upgrade?.mode === 'hard')
      throw new RestrictoError('upgrade_required', `This version of @funsol/restricto-web is no longer accepted (${state.upgrade.reason}); update the app.`);
    const dev = await ensureReady();
    const gen = generation;
    const signed = await signRequest({ privateKey: dev.privateKey, deviceId: dev.deviceId!, appId, clock }, method, url, bytes);
    return { signed, dev, gen };
  }

  function toSignedRequest(s: Awaited<ReturnType<typeof signNow>>, method: string): SignedRequest {
    const ctx: SignCtx = { nonce: s.signed.nonce, deviceId: s.dev.deviceId!, method, sentAt: Date.now(), gen: s.gen, publicKey: s.dev.publicKey, attestedUntil: s.dev.attestedUntil };
    const req: SignedRequest = {
      headers: s.signed.headers,
      nonce: s.signed.nonce,
      ts: s.signed.ts,
      deviceId: s.dev.deviceId!,
      verify: async (response) => {
        const a = await assess(response, ctx);
        if (a.verified || mode() === 'off') return;
        if (mode() === 'strict') throw unverified(a.reason, { unsigned: a.kind === 'unsigned', status: response.status });
        warn(`response not verified: ${a.reason}`);
      },
    };
    contexts.set(req, ctx);
    return req;
  }

  /** A Restricto denial: `{detail, error_type, error_code, action}`. Only ever read from a body that has been verified (or, for the
   * clock-skew exception below, whose signature is then verified before anything is used). */
  async function readErrBody(res: Response): Promise<ErrBody | undefined> {
    if (res.status < 400) return undefined;
    try {
      const text = await res.clone().text();
      if (text.length > 65_536) return undefined;
      const j: unknown = JSON.parse(text);
      if (!j || typeof j !== 'object' || typeof (j as { error_code?: unknown }).error_code !== 'number') return undefined;
      const o = j as { action?: unknown; error_code: number; server_time?: unknown; cfg_seq?: unknown };
      return { action: typeof o.action === 'string' ? o.action : undefined, errorCode: o.error_code, serverTime: finite(o.server_time), cfgSeq: finite(o.cfg_seq) };
    } catch {
      return undefined;
    }
  }

  /**
   * Decides whether a reply may be believed: same origin, not redirected, and signed by a known response key for THIS request's nonce
   * and device. Only a verified reply is ever acted upon or used for the clock.
   */
  async function assess(res: Response, ctx: Pick<SignCtx, 'nonce' | 'deviceId' | 'method' | 'sentAt'>): Promise<Assessment> {
    const cached = assessments.get(res);
    if (cached) return cached;
    const out = await assessUncached(res, ctx);
    assessments.set(res, out);
    return out;
  }

  async function assessUncached(res: Response, ctx: Pick<SignCtx, 'nonce' | 'deviceId' | 'method' | 'sentAt'>): Promise<Assessment> {
    if (mode() === 'off') return { verified: false, kind: 'off', reason: 'verification is off', body: await readErrBody(res) };
    if (!fromOrigin(res, origin)) return { verified: false, kind: 'redirect', reason: 'the reply was redirected or did not come from the configured origin' };
    const base = { nonce: ctx.nonce, deviceId: ctx.deviceId, method: ctx.method, clock, keys, forceFallback: config.forceEd25519Fallback };
    let out = await verifyResponseSignature(res, base);
    const rtt = (Date.now() - ctx.sentAt) / 1000;
    if (!out.ok && out.kind === 'window' && res.status < 500 && rtt <= MAX_RTT_FOR_CLOCK_SECONDS) {
      // Our own clock may be the thing that is wrong: a signed `resync_clock` rejection is believed even outside the window.
      const hint = await readErrBody(res);
      if (hint?.action === 'resync_clock' && hint.serverTime) out = await verifyResponseSignature(res, { ...base, ignoreWindow: true });
    }
    if (!out.ok) return { verified: false, kind: out.kind === 'unsigned' ? 'unsigned' : 'invalid', reason: out.reason };
    verified.add(res);
    // A signed ts is a trustworthy clock sample, but only for a quick round trip (a delayed reply would carry an old time).
    if (rtt <= MAX_RTT_FOR_CLOCK_SECONDS && Math.abs(out.ts - clock.now()) > Math.max(5, v().maxSkew / 4)) clock.sync(out.ts);
    const body = await readErrBody(res);
    noteCfgSeq(body?.cfgSeq);
    return { verified: true, reason: '', body };
  }

  const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));
  const transientDelay = (n: number): number => Math.min(5000, (config.transientBackoffMs ?? 400) * 2 ** n * (0.5 + Math.random() / 2));

  /** Acts on a VERIFIED signed reply. true = fixed something, re-sign and resend. */
  async function act(res: Response, a: Assessment, ctx: Pick<SignCtx, 'gen' | 'publicKey' | 'attestedUntil' | 'method'>, budget: Budget): Promise<boolean> {
    const e = a.body;
    if (!e) return false;
    switch (e.action) {
      case 'resync_clock':
        if (budget.clock > 0 && e.serverTime) {
          budget.clock--;
          clock.sync(e.serverTime);
          return true;
        }
        return false;
      case 'reregister':
      case 'wipe':
        if (budget.unknown <= 0) return false;
        budget.unknown--;
        // another call may already have renewed / replaced the key since this request was signed
        if (generation === ctx.gen) await ensureReady(e.action === 'wipe' ? { wipe: ctx.publicKey } : { stale: ctx.attestedUntil });
        return true;
      case 'upgrade':
        advisory = { mode: 'soft', reason: 'server', url: '' };
        syncDerived();
        return false;
      case 'backoff':
      case 'none':
      default: {
        // Unknown actions and codes are mapped by HTTP class: a verified 429/503 with a short Retry-After is waited out once more for
        // idempotent calls, everything else goes to the application untouched.
        const wait = parseRetryAfter(res.headers.get('Retry-After'));
        if ((res.status === 429 || res.status === 503) && IDEMPOTENT.has(ctx.method) && wait !== undefined && wait <= 10 && budget.transient > 0) {
          budget.transient--;
          await sleep(wait * 1000);
          return true;
        }
        // The one code the SDK looks at: a replayed nonce is harmless to retry with a new one, bounded by the config's retry.replay.
        if (e.errorCode === 458066 && budget.replay > 0) {
          budget.replay--;
          return true;
        }
        return false;
      }
    }
  }

  const newBudget = (): Budget => ({ replay: v().retry.replay, unknown: v().retry.unknownDevice, transient: v().retry.transient, clock: 1 });

  async function signedFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    const url = resolveUrl(input);
    if (url.origin !== origin) return rawFetch(input, init);
    const p = await prepare(input, init, url);
    const budget = newBudget();
    let tries = 0;
    for (;;) {
      const s = await signNow(p.method, p.url, p.body.bytes);
      const headers = new Headers(p.headers);
      await config.onRequest?.(headers, { method: p.method, url: p.url });
      for (const [k, val] of Object.entries(s.signed.headers)) headers.set(k, val);
      const ctx = { nonce: s.signed.nonce, deviceId: s.dev.deviceId!, method: p.method, sentAt: Date.now() };
      let res: Response;
      try {
        res = await rawFetch(p.url.href, { ...p.rest, method: p.method, headers, body: p.body.send, redirect: redirectMode });
      } catch (e) {
        if (IDEMPOTENT.has(p.method) && budget.transient > 0 && !(p.rest.signal as AbortSignal | undefined)?.aborted && !(e instanceof RestrictoError)) {
          budget.transient--;
          await sleep(transientDelay(tries++));
          continue;
        }
        throw e;
      }
      const a = await assess(res, ctx);
      if (a.verified) {
        if (res.status >= 400 && (await act(res, a, { gen: s.gen, publicKey: s.dev.publicKey, attestedUntil: s.dev.attestedUntil, method: p.method }, budget))) continue;
        return res;
      }
      if (mode() === 'off') return res;
      if (mode() === 'warn') {
        warn(`response not verified: ${a.reason}`);
        return res;
      }
      // Strict: an unsigned (or unverifiable, or redirected) answer is a network error. Bounded retry for idempotent calls, then fail;
      // never wipe a key, never re-register, never adopt a clock from it.
      if (IDEMPOTENT.has(p.method) && budget.transient > 0 && a.kind !== 'redirect') {
        budget.transient--;
        await sleep(transientDelay(tries++));
        continue;
      }
      if (a.kind === 'redirect') throw new RestrictoError('redirect', `Rejected response: ${a.reason}.`, { status: res.status, unsigned: true });
      throw unverified(a.reason, { unsigned: a.kind === 'unsigned', status: res.status });
    }
  }

  const client: RestrictoClient = {
    appId,
    fetch: signedFetch,
    async sign(input: SignInput) {
      const url = resolveUrl(input.url);
      if (url.origin !== origin) throw new RestrictoError('config', `Refusing to sign for ${url.origin}: only ${origin} is configured.`);
      const body = await prepareBody(input.body, maxBody);
      const method = (input.method ?? 'GET').toUpperCase();
      return toSignedRequest(await signNow(method, url, body.bytes), method);
    },
    async recover(res, signed) {
      const ctx = contexts.get(signed);
      if (!ctx) return false;
      const a = await assess(res, ctx);
      return a.verified && res.status >= 400 ? act(res, a, ctx, newBudget()) : false;
    },
    async ready() {
      await ensureConfig();
      await ensureReady();
      return state;
    },
    async refreshConfig() {
      if (pins) {
        await ensureConfig();
        cfgLast = 0;
        cfgFailures = 0; // an explicit request is not held back by the failure backoff
        await refreshConfigNow(0);
      }
      return state.config;
    },
    getState: () => state,
    subscribe(l) {
      listeners.add(l);
      return () => void listeners.delete(l);
    },
    isVerified: (res) => verified.has(res),
    async reset() {
      epoch++;
      life.abort();
      life = new AbortController();
      if (timer) clearTimeout(timer);
      timer = undefined;
      registering = undefined;
      // same lock as register(): an in-flight registration has been told to stop and cannot put its key back afterwards
      await withLock(lockName, () => store.delete(namespace), config.useWebLocks !== false);
      device = undefined;
      generation++;
      failure = undefined;
      failures = 0;
      setState({ ...IDLE, config: configStatus(), upgrade: state.upgrade });
    },
    close() {
      if (timer) clearTimeout(timer);
      timer = undefined;
      life.abort();
      life = new AbortController();
    },
  };

  if (config.autoRegister && typeof window !== 'undefined') void client.ready().catch(() => undefined);
  return client;
}
