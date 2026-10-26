import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createMemoryKeyStore, createRestricto, RestrictoError, restrictoAxios, type RestrictoConfig } from '../src';
import { FakeRestricto } from './helpers/fake-server';

const BASE = 'https://api.example.com';

let server: FakeRestricto;
let rawCalls: Array<{ url: string; headers: Headers }>;

function make(over: Partial<RestrictoConfig> = {}, srv = server) {
  const store = over.keyStore ?? createMemoryKeyStore();
  const client = createRestricto({
    baseUrl: BASE,
    appId: srv.appId,
    keyStore: store,
    pow: { useWorker: false },
    useWebLocks: false,
    registerCooldownMs: 0,
    pinnedResponseKeys: { k1: srv.publicKeyB64 },
    onWarning: () => undefined,
    fetch: (async (input: RequestInfo | URL, init?: RequestInit) => {
      rawCalls.push({ url: typeof input === 'string' ? input : String(input), headers: new Headers(init?.headers) });
      return srv.fetch(input, init);
    }) as typeof fetch,
    ...over,
  });
  return { client, store };
}

beforeEach(() => {
  server = new FakeRestricto();
  rawCalls = [];
});
afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe('register + signed fetch', () => {
  it('registers once (challenge -> PoW -> register), then signs; response verified; key is non-extractable', async () => {
    const { client, store } = make();
    expect(client.getState().status).toBe('idle');
    const res = await client.fetch(`${BASE}/api/hello/?a=1`);
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ ok: true, method: 'GET', target: '/api/hello/?a=1' });
    expect(client.isVerified(res)).toBe(true);
    expect(server.counts).toMatchObject({ challenge: 1, register: 1, api: 1 });
    expect(server.registeredBodies[0]).toMatchObject({ platform: 'web', app_version: 'web-1.0.0' });
    expect(server.registeredBodies[0]!.web).toEqual({ pow: expect.stringMatching(/^\d+$/) });
    const state = client.getState();
    expect(state).toMatchObject({ status: 'ready', trustLevel: 1, error: null });
    expect(state.deviceId).toMatch(/^rd_[0-9a-f]{32}$/);

    const rec = (await store.get(`${server.appId}|${BASE}`))!;
    expect(rec.privateKey.extractable).toBe(false);
    await expect(crypto.subtle.exportKey('pkcs8', rec.privateKey)).rejects.toThrow();
    expect(JSON.stringify(rec)).not.toContain('PRIVATE');
  });

  it('signs paths with spaces, plus, unicode, encoded slashes and odd queries the way the server canonicalises them', async () => {
    const { client } = make();
    for (const p of ['/api/a b/c/', '/api/a+b/', '/api/ü/', '/api/x%2Fy/', '/api/%7Etilde/', '/api/q/?x=a%20b&y=%C3%BC&z=a+b&e=']) {
      const res = await client.fetch(BASE + p);
      expect(res.status, p).toBe(200);
    }
  });

  it('handles methods and body types: string, URLSearchParams, Blob, ArrayBuffer, typed array, Request object', async () => {
    const { client } = make();
    const post = async (body: BodyInit, extra: RequestInit = {}) => {
      const r = await client.fetch(`${BASE}/api/post/`, { method: 'post', body, ...extra });
      expect(r.status).toBe(200);
      return (await r.json()) as { body: string; method: string };
    };
    expect((await post('{"a":"é"}', { headers: { 'content-type': 'application/json' } })).body).toBe('{"a":"é"}');
    expect((await post(new URLSearchParams({ q: 'a b' }))).body).toBe('q=a+b');
    expect((await post(new Blob(['blob-data']))).body).toBe('blob-data');
    expect((await post(new TextEncoder().encode('bytes').buffer as ArrayBuffer)).body).toBe('bytes');
    expect((await post(new TextEncoder().encode('xxviewxx').subarray(2, 6))).body).toBe('view');
    const viaRequest = await client.fetch(new Request(`${BASE}/api/req/`, { method: 'PUT', body: 'from-request', headers: { 'x-extra': '1' } }));
    expect(await viaRequest.json()).toMatchObject({ method: 'PUT', body: 'from-request' });
    expect(rawCalls.at(-1)!.headers.get('x-extra')).toBe('1');
  });

  it('refuses FormData, streams, oversize bodies and a caller Authorization header, before anything is sent', async () => {
    const { client } = make();
    const calls = () => server.counts.api;
    await expect(client.fetch(`${BASE}/api/up/`, { method: 'POST', body: new FormData() })).rejects.toMatchObject({ code: 'unsupported_body' });
    const stream = new ReadableStream();
    await expect(client.fetch(`${BASE}/api/up/`, { method: 'POST', body: stream, duplex: 'half' } as RequestInit)).rejects.toMatchObject({ code: 'unsupported_body' });
    await expect(client.fetch(`${BASE}/api/up/`, { method: 'POST', body: new Uint8Array(5 * 1024 * 1024 + 1) })).rejects.toMatchObject({ code: 'body_too_large' });
    await expect(client.fetch(`${BASE}/api/up/`, { headers: { Authorization: 'Bearer x' } })).rejects.toMatchObject({ code: 'authorization_conflict' });
    const multipart = new Request(`${BASE}/api/up/`, { method: 'POST', body: new FormData() });
    await expect(client.fetch(multipart)).rejects.toMatchObject({ code: 'unsupported_body' });
    expect(calls()).toBe(0);
    // exactly the limit is fine
    const ok = await client.fetch(`${BASE}/api/up/`, { method: 'POST', body: new Uint8Array(5 * 1024 * 1024) });
    expect(ok.status).toBe(200);
  });

  it('works when the browser clock is an hour off (clock follows the server)', async () => {
    const real = Date.now;
    const { client } = make();
    // server believes real time; the "browser" is an hour fast only for the SDK's calls
    server.now = () => Math.floor(real() / 1000);
    vi.spyOn(Date, 'now').mockImplementation(() => real() + 3600_000);
    const res = await client.fetch(`${BASE}/api/hello/`);
    expect(res.status).toBe(200);
  });

  it('exposes sign() for custom stacks, only for the configured origin', async () => {
    const { client } = make();
    const signed = await client.sign({ method: 'post', url: `${BASE}/api/custom/?x=1`, body: '{"k":1}' });
    expect(signed.headers.Authorization).toMatch(/^Restricto-Sig v1 id=rd_[0-9a-f]{32},ts=\d+,nonce=[A-Za-z0-9_-]{16,64},sig=[A-Za-z0-9_-]{86}$/);
    expect(signed.headers['X-APP-ID']).toBe(server.appId);
    const res = await server.fetch(`${BASE}/api/custom/?x=1`, { method: 'POST', body: '{"k":1}', headers: signed.headers });
    expect(res.status).toBe(200);
    await signed.verify(res); // does not throw
    await expect(client.sign({ url: 'https://evil.example/x' })).rejects.toMatchObject({ code: 'config' });
  });

  it('onRequest hook can add headers (step-up extension point)', async () => {
    const { client } = make({ onRequest: (h) => h.set('X-Step-Up', 'assertion') });
    await client.fetch(`${BASE}/api/x/`);
    expect(rawCalls.at(-1)!.headers.get('x-step-up')).toBe('assertion');
  });

  it('sends the Turnstile token from the user callback', async () => {
    server.requireTurnstile = true;
    const { client } = make({ getTurnstileToken: async () => 'ts-ok' });
    expect((await client.fetch(`${BASE}/api/x/`)).status).toBe(200);
    expect(server.registeredBodies[0]!.web).toMatchObject({ turnstile_token: 'ts-ok' });
    const { client: bad } = make({ getTurnstileToken: async () => 'nope', keyStore: createMemoryKeyStore() });
    await expect(bad.fetch(`${BASE}/api/x/`)).rejects.toMatchObject({ code: 'register_failed', serverCode: 458118 });
  });
});

describe('cross-origin safety', () => {
  it('never signs, registers for, or leaks headers to another origin', async () => {
    const { client } = make();
    const other = vi.fn(async () => new Response('ok'));
    const { client: c2 } = make({ fetch: other as unknown as typeof fetch });
    const res = await c2.fetch('https://cdn.other.example/lib.js', { headers: { 'x-a': 'b' } });
    expect(await res.text()).toBe('ok');
    const [, init] = other.mock.calls[0] as unknown as [string, RequestInit];
    expect(new Headers(init.headers).get('authorization')).toBeNull();
    expect(new Headers(init.headers).get('x-app-id')).toBeNull();
    expect(other).toHaveBeenCalledTimes(1); // no challenge/register traffic either
    expect(c2.getState().status).toBe('idle');
    // lookalike origins (port, scheme, subdomain)
    for (const u of ['http://api.example.com/x', 'https://api.example.com:8443/x', 'https://x.api.example.com/x', 'https://api.example.com.evil.io/x']) {
      other.mockClear();
      await c2.fetch(u);
      const [, i2] = other.mock.calls[0] as unknown as [string, RequestInit | undefined];
      expect(new Headers(i2?.headers).get('authorization'), u).toBeNull();
    }
    void client;
  });
});

describe('recoverable errors: exactly one re-signed retry', () => {
  it('clock skew (458052): resyncs from X-Restricto-Server-Time and retries with a NEW nonce', async () => {
    const { client } = make();
    await client.fetch(`${BASE}/api/a/`);
    server.seen.length = 0;
    // the server's clock jumps 10 min; the SDK still believes the old one
    server.now = (() => {
      const base = Math.floor(Date.now() / 1000);
      return () => base + 600;
    })();
    const res = await client.fetch(`${BASE}/api/b/`);
    expect(res.status).toBe(200);
    expect(server.seen).toHaveLength(2);
    expect(server.seen[0]!.nonce).not.toBe(server.seen[1]!.nonce);
    expect(client.isVerified(res)).toBe(true);
  });

  it('replay (458066): new nonce, one retry; a second failure is surfaced, not looped', async () => {
    const { client } = make();
    await client.fetch(`${BASE}/api/a/`);
    server.seen.length = 0;
    server.failNext = { code: 458066, status: 401, remaining: 1 };
    expect((await client.fetch(`${BASE}/api/b/`)).status).toBe(200);
    expect(server.seen).toHaveLength(2);
    server.seen.length = 0;
    server.failNext = { code: 458066, status: 401, remaining: 5 };
    const res = await client.fetch(`${BASE}/api/c/`);
    expect(res.status).toBe(401);
    expect(server.seen).toHaveLength(2); // original + exactly one retry
    expect(client.isVerified(res)).toBe(false);
    expect(await res.json()).toMatchObject({ error_code: 458066 });
  });

  it('attestation expired (458085): re-registers the SAME key with a fresh challenge, then retries', async () => {
    const { client } = make();
    await client.fetch(`${BASE}/api/a/`);
    const id = client.getState().deviceId!;
    server.expire(id);
    const res = await client.fetch(`${BASE}/api/b/`);
    expect(res.status).toBe(200);
    expect(client.getState().deviceId).toBe(id);
    expect(server.counts).toMatchObject({ challenge: 2, register: 2 });
  });

  it('unknown device (458033): re-registers and retries', async () => {
    const { client } = make();
    await client.fetch(`${BASE}/api/a/`);
    const id = client.getState().deviceId!;
    server.forget(id);
    expect((await client.fetch(`${BASE}/api/b/`)).status).toBe(200);
    expect(server.counts.register).toBe(2);
    expect(client.getState().deviceId).toBe(id);
  });

  it('revoked (458071): wipes the key, registers a new one (new device id), retries', async () => {
    const { client, store } = make();
    await client.fetch(`${BASE}/api/a/`);
    const first = client.getState().deviceId!;
    server.revoke(first);
    expect((await client.fetch(`${BASE}/api/b/`)).status).toBe(200);
    const second = client.getState().deviceId!;
    expect(second).not.toBe(first);
    expect((await store.get(`${server.appId}|${BASE}`))!.deviceId).toBe(second);
  });

  it('revoked and banned: the registration failure is surfaced', async () => {
    const { client } = make();
    await client.fetch(`${BASE}/api/a/`);
    server.revoke(client.getState().deviceId!);
    server.banRegistrations = true;
    await expect(client.fetch(`${BASE}/api/b/`)).rejects.toMatchObject({ code: 'register_failed', serverCode: 458118 });
    expect(client.getState().status).toBe('error');
  });

  it('other codes are never retried (signature invalid 458047, required 458010) and surface as normal responses', async () => {
    const { client } = make();
    await client.fetch(`${BASE}/api/a/`);
    for (const code of [458047, 458010, 458151]) {
      server.seen.length = 0;
      server.failNext = { code, status: code === 458151 ? 429 : 401, remaining: 3 };
      const res = await client.fetch(`${BASE}/api/post/`, { method: 'POST', body: '{}' });
      expect(res.status).toBe(code === 458151 ? 429 : 401);
      expect(server.seen).toHaveLength(1);
    }
    server.failNext = undefined;
  });

  it('plain application errors (404) are verified and returned untouched', async () => {
    const { client } = make();
    const res = await client.fetch(`${BASE}/api/missing/`);
    expect(res.status).toBe(404);
    expect(client.isVerified(res)).toBe(true);
  });
});

describe('attestation lifetime', () => {
  it('renews in the background before attested_until, and awaits a renewal once it has passed', async () => {
    server.validitySeconds = 1000; // margin = min(6h, validity/4) = 250 s
    const real = Date.now;
    let shift = 0;
    vi.spyOn(Date, 'now').mockImplementation(() => real() + shift * 1000);
    const { client } = make({ autoRefresh: false });
    await client.fetch(`${BASE}/api/a/`);
    expect(server.counts.register).toBe(1);

    shift = 800; // 200 s left: inside the margin, still valid
    await client.fetch(`${BASE}/api/b/`);
    await vi.waitFor(() => expect(server.counts.register).toBe(2));
    expect(client.getState().attestedUntil).toBeGreaterThan(Math.floor(real() / 1000) + 1500);

    shift = 800 + 1100; // fully expired relative to the renewed attestation too
    const res = await client.fetch(`${BASE}/api/c/`);
    expect(res.status).toBe(200);
    expect(server.counts.register).toBe(3);
  });

  it('schedules a renewal timer for long-lived pages', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'Date'] });
    server.validitySeconds = 4000;
    const { client } = make();
    await client.ready();
    expect(server.counts.register).toBe(1);
    await vi.advanceTimersByTimeAsync(3100 * 1000); // past validity - margin(1000)
    await vi.waitFor(() => expect(server.counts.register).toBe(2));
    client.close();
  });

  it('a second client on the same store reuses the registration (page reload)', async () => {
    const store = createMemoryKeyStore();
    const { client } = make({ keyStore: store });
    await client.fetch(`${BASE}/api/a/`);
    const { client: reloaded } = make({ keyStore: store });
    await reloaded.fetch(`${BASE}/api/b/`);
    expect(server.counts.register).toBe(1);
    expect(reloaded.getState().deviceId).toBe(client.getState().deviceId);
  });
});

describe('concurrency', () => {
  it('parallel calls in one page register exactly once', async () => {
    const { client } = make();
    const results = await Promise.all(Array.from({ length: 8 }, (_, i) => client.fetch(`${BASE}/api/p/${i}/`)));
    expect(results.every((r) => r.status === 200)).toBe(true);
    expect(server.counts).toMatchObject({ challenge: 1, register: 1, api: 8 });
    expect(new Set(server.seen.map((s) => s.nonce)).size).toBe(8);
  });

  it('two "tabs" (separate clients sharing storage) register once through Web Locks', async () => {
    const holders: Array<Promise<unknown>> = [];
    let tail: Promise<unknown> = Promise.resolve();
    const lockRequests: string[] = [];
    vi.stubGlobal('navigator', {
      locks: {
        request: (name: string, fn: () => Promise<unknown>) => {
          lockRequests.push(name);
          const run = tail.then(fn, fn);
          tail = run.catch(() => undefined);
          holders.push(run);
          return run;
        },
      },
    });
    const store = createMemoryKeyStore();
    const a = make({ keyStore: store, useWebLocks: true }).client;
    const b = make({ keyStore: store, useWebLocks: true }).client;
    const [ra, rb] = await Promise.all([a.fetch(`${BASE}/api/a/`), b.fetch(`${BASE}/api/b/`)]);
    expect([ra.status, rb.status]).toEqual([200, 200]);
    expect(server.counts.register).toBe(1);
    expect(lockRequests.length).toBeGreaterThanOrEqual(2);
    expect(a.getState().deviceId).toBe(b.getState().deviceId);
    vi.unstubAllGlobals();
  });

  it('a failed registration fails fast during the cooldown and recovers afterwards', async () => {
    server.banRegistrations = true;
    const { client } = make({ registerCooldownMs: 60_000 });
    await expect(client.fetch(`${BASE}/api/a/`)).rejects.toMatchObject({ code: 'register_failed' });
    expect(server.counts.register).toBe(1);
    await expect(client.fetch(`${BASE}/api/a/`)).rejects.toMatchObject({ code: 'register_failed' });
    expect(server.counts.register).toBe(1); // no new PoW
    const { client: c2 } = make({ registerCooldownMs: 0 });
    await expect(c2.fetch(`${BASE}/api/a/`)).rejects.toBeInstanceOf(RestrictoError);
    server.banRegistrations = false;
    expect((await c2.fetch(`${BASE}/api/a/`)).status).toBe(200);
    expect(c2.getState().status).toBe('ready');
  });

  it('notifies subscribers: idle -> registering -> ready', async () => {
    const { client } = make();
    const seen: string[] = [];
    client.subscribe((s) => seen.push(s.status));
    await client.ready();
    expect(seen).toEqual(['registering', 'ready']);
  });
});

describe('response verification', () => {
  it('strict (default) rejects tampered body, bad signature, stale ts, replayed response, and unsigned responses', async () => {
    const { client } = make();
    await client.fetch(`${BASE}/api/a/`);
    server.tamperBody = true;
    await expect(client.fetch(`${BASE}/api/b/`)).rejects.toMatchObject({ code: 'response_unverified' });
    server.tamperBody = false;
    server.badSignature = true;
    await expect(client.fetch(`${BASE}/api/b/`)).rejects.toMatchObject({ code: 'response_unverified' });
    server.badSignature = false;
    server.staleResponseTs = true;
    await expect(client.fetch(`${BASE}/api/b/`)).rejects.toThrow(/timestamp/);
    server.staleResponseTs = false;
    server.replayResponseNonce = true;
    await expect(client.fetch(`${BASE}/api/b/`)).rejects.toMatchObject({ code: 'response_unverified' });
    server.replayResponseNonce = false;
    server.signResponses = false;
    await expect(client.fetch(`${BASE}/api/b/`)).rejects.toThrow(/no Restricto signature/);
    server.signResponses = true;
    expect((await client.fetch(`${BASE}/api/b/`)).status).toBe(200);
  });

  it('an unsigned non-Restricto 403/401 is untrusted (rejected in strict mode)', async () => {
    const { client } = make({
      fetch: (async (input: RequestInfo | URL, init?: RequestInit) => {
        const u = String(input);
        if (u.includes('/api/')) return new Response('<html>proxy says no</html>', { status: 403 });
        return server.fetch(input, init);
      }) as typeof fetch,
    });
    await expect(client.fetch(`${BASE}/api/a/`)).rejects.toMatchObject({ code: 'response_unverified' });
  });

  it('unsigned Restricto rejections (which the server cannot sign) are returned but flagged unverified', async () => {
    const { client } = make();
    await client.fetch(`${BASE}/api/a/`);
    server.failNext = { code: 458047, status: 401, remaining: 1 };
    const res = await client.fetch(`${BASE}/api/a/`);
    expect(res.status).toBe(401);
    expect(client.isVerified(res)).toBe(false);
  });

  it('warn mode returns the response and warns; off mode skips verification', async () => {
    const warnings: string[] = [];
    const { client } = make({ verifyResponses: 'warn', onWarning: (m) => warnings.push(m) });
    server.tamperBody = true;
    expect((await client.fetch(`${BASE}/api/a/`)).status).toBe(200);
    expect(warnings.join()).toMatch(/not verified/);
    const { client: off } = make({ verifyResponses: 'off', keyStore: createMemoryKeyStore() });
    expect((await off.fetch(`${BASE}/api/a/`)).status).toBe(200);
  });

  it('a wrong pinned key rejects everything; an unknown kid is not fetched when pinned', async () => {
    const { client } = make({ pinnedResponseKeys: { k1: Buffer.alloc(32, 7).toString('base64url') } });
    await expect(client.fetch(`${BASE}/api/a/`)).rejects.toMatchObject({ code: 'response_unverified' });
    const { client: other } = make({ pinnedResponseKeys: { other: server.publicKeyB64 }, keyStore: createMemoryKeyStore() });
    await expect(other.fetch(`${BASE}/api/a/`)).rejects.toThrow(/unknown response signing key/);
    expect(server.counts.keys).toBe(0);
  });

  it('without pins, keys are fetched once from /keys/ (TOFU) and cached', async () => {
    const { client } = make({ pinnedResponseKeys: undefined });
    await client.fetch(`${BASE}/api/a/`);
    await client.fetch(`${BASE}/api/b/`);
    expect(server.counts.keys).toBe(1);
  });

  it('works with the noble Ed25519 fallback', async () => {
    const { client } = make({ forceEd25519Fallback: true });
    const res = await client.fetch(`${BASE}/api/a/`);
    expect(client.isVerified(res)).toBe(true);
    server.tamperBody = true;
    await expect(client.fetch(`${BASE}/api/b/`)).rejects.toMatchObject({ code: 'response_unverified' });
  });

  it('config errors: missing fields and an empty pin set', () => {
    expect(() => createRestricto({ baseUrl: '', appId: '' })).toThrow(RestrictoError);
    expect(() => createRestricto({ baseUrl: BASE, appId: 'a', pinnedResponseKeys: {} })).toThrow(/pinnedResponseKeys/);
  });
});

describe('axios adapter', () => {
  it('signs through a real axios instance (params, JSON body, error status, custom validateStatus)', async () => {
    const axios = (await import('axios')).default;
    const { client } = make();
    const http = axios.create({ baseURL: BASE, adapter: restrictoAxios(client) as never });
    const r = await http.post('/api/ax/', { hello: 'wörld' }, { params: { q: 'a b', n: 2 } });
    expect(r.status).toBe(200);
    expect(r.data).toMatchObject({ method: 'POST', body: '{"hello":"wörld"}' });
    expect(r.data.target).toBe('/api/ax/?q=a+b&n=2');
    await expect(http.get('/api/missing/')).rejects.toMatchObject({ isAxiosError: true, response: { status: 404 } });
    expect((await http.get('/api/missing/', { validateStatus: () => true })).status).toBe(404);
    server.tamperBody = true;
    await expect(http.get('/api/ax/')).rejects.toMatchObject({ code: 'response_unverified' });
  });
});
