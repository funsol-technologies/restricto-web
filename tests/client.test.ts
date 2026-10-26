import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createMemoryKeyStore, createRestricto, RestrictoError, restrictoAxios, type RestrictoConfig } from '../src';
import { FakeRestricto } from './helpers/fake-server';
import { BASE, makeIn, withProps, type Env } from './helpers/make';

const env: Env = { server: undefined as unknown as FakeRestricto, rawCalls: [] };
let server: FakeRestricto;
const make = (over: Partial<RestrictoConfig> = {}) => makeIn(env, over);
const stateOf = async (store: ReturnType<typeof createMemoryKeyStore>) => (await store.get(`${server.appId}|${BASE}`))!;

beforeEach(() => {
  server = new FakeRestricto();
  env.server = server;
  env.rawCalls = [];
});
afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe('register + signed fetch', () => {
  it('registers once (challenge -> key-bound PoW -> register), then signs; response verified; key is non-extractable', async () => {
    const { client, store } = make();
    expect(client.getState().status).toBe('idle');
    const res = await client.fetch(`${BASE}/api/hello/?a=1`);
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ ok: true, method: 'GET', target: '/api/hello/?a=1', host: 'api.example.com' });
    expect(client.isVerified(res)).toBe(true);
    expect(server.counts).toMatchObject({ challenge: 1, register: 1, api: 1, keys: 0, config: 0 });
    expect(server.registeredBodies[0]).toMatchObject({ platform: 'web', app_version: 'web-1.0.0', caps: { sig: [1], cfg: 0 }, renew: false });
    expect(server.registeredBodies[0]!.web).toEqual({ pow: expect.stringMatching(/^\d+$/) });
    expect(client.getState()).toMatchObject({ status: 'ready', trustLevel: 1, error: null, upgrade: null, config: { source: 'none' } });
    expect(client.getState().deviceId).toMatch(/^rd_[0-9a-f]{32}$/);

    const rec = await stateOf(store);
    expect(rec.privateKey.extractable).toBe(false);
    await expect(crypto.subtle.exportKey('pkcs8', rec.privateKey)).rejects.toThrow();
    expect(JSON.stringify(rec)).not.toContain('PRIVATE');
  });

  it('sends Restricto-Signature (v=1,id,ts,nonce,bh,sig) and leaves the application Authorization header alone', async () => {
    const { client } = make();
    const res = await client.fetch(`${BASE}/api/hello/`, { headers: { Authorization: 'Bearer app-token' } });
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ authorization: 'Bearer app-token' });
    const sent = env.rawCalls.at(-1)!.headers;
    expect(sent.get('authorization')).toBe('Bearer app-token');
    expect(sent.get('restricto-signature')).toMatch(/^v=1,id=rd_[0-9a-f]{32},ts=\d+,nonce=[A-Za-z0-9_-]{16,64},bh=[A-Za-z0-9_-]{43},sig=[A-Za-z0-9_-]{86}$/);
    expect(sent.get('x-app-id')).toBe(server.appId);
    expect(server.seen.at(-1)!.header).toBe(sent.get('restricto-signature'));
  });

  it('signs hosts, paths and queries the way the server canonicalises them (reordered query, %2F, unicode, ports)', async () => {
    const { client } = make();
    for (const p of ['/api/a b/c/', '/api/a+b/', '/api/ü/', '/api/x%2Fy/', '/api/%7Etilde/', '/api/q/?x=a%20b&y=%C3%BC&z=a+b&e=', '/api/q/?b=2&a=%7e&&c&a=1', '//api//double//slash/']) {
      const res = await client.fetch(BASE + p);
      expect(res.status, p).toBe(200);
      expect(client.isVerified(res)).toBe(true);
    }
    expect((await client.fetch('https://api.example.com:443/api/p/')).status).toBe(200);
    expect(server.seen.at(-1)!.host).toBe('api.example.com');
    const { client: other } = make({ baseUrl: 'https://api.example.com:8443', keyStore: createMemoryKeyStore() });
    expect((await other.fetch('https://api.example.com:8443/api/p/')).status).toBe(200);
    expect(server.seen.at(-1)!.host).toBe('api.example.com:8443');
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
    expect(env.rawCalls.at(-1)!.headers.get('x-extra')).toBe('1');
  });

  it('HEAD and 204 answers are signed over the empty body and verify', async () => {
    const { client } = make();
    const head = await client.fetch(`${BASE}/api/h/`, { method: 'HEAD' });
    expect(head.status).toBe(200);
    expect(client.isVerified(head)).toBe(true);
    const nc = await client.fetch(`${BASE}/api/nocontent/`);
    expect(nc.status).toBe(204);
    expect(client.isVerified(nc)).toBe(true);
  });

  it('refuses FormData, streams and oversize bodies before anything is sent; exactly the limit is fine', async () => {
    const { client } = make();
    await expect(client.fetch(`${BASE}/api/up/`, { method: 'POST', body: new FormData() })).rejects.toMatchObject({ code: 'unsupported_body' });
    const stream = new ReadableStream();
    await expect(client.fetch(`${BASE}/api/up/`, { method: 'POST', body: stream, duplex: 'half' } as RequestInit)).rejects.toMatchObject({ code: 'unsupported_body' });
    await expect(client.fetch(`${BASE}/api/up/`, { method: 'POST', body: new Uint8Array(5 * 1024 * 1024 + 1) })).rejects.toMatchObject({ code: 'body_too_large' });
    const multipart = new Request(`${BASE}/api/up/`, { method: 'POST', body: new FormData() });
    await expect(client.fetch(multipart)).rejects.toMatchObject({ code: 'unsupported_body' });
    expect(server.counts.api).toBe(0);
    const ok = await client.fetch(`${BASE}/api/up/`, { method: 'POST', body: new Uint8Array(5 * 1024 * 1024) });
    expect(ok.status).toBe(200);
  });

  it('works when the browser clock is an hour off (clock follows the server)', async () => {
    const real = Date.now;
    const { client } = make();
    server.now = () => Math.floor(real() / 1000);
    vi.spyOn(Date, 'now').mockImplementation(() => real() + 3600_000);
    expect((await client.fetch(`${BASE}/api/hello/`)).status).toBe(200);
  });

  it('exposes sign() for custom stacks, only for the configured origin', async () => {
    const { client } = make();
    const signed = await client.sign({ method: 'post', url: `${BASE}/api/custom/?x=1`, body: '{"k":1}' });
    expect(signed.headers['Restricto-Signature']).toMatch(/^v=1,id=rd_[0-9a-f]{32},ts=\d+,nonce=[A-Za-z0-9_-]{16,64},bh=[A-Za-z0-9_-]{43},sig=[A-Za-z0-9_-]{86}$/);
    expect(signed.headers['X-APP-ID']).toBe(server.appId);
    const res = await server.fetch(`${BASE}/api/custom/?x=1`, { method: 'POST', body: '{"k":1}', headers: signed.headers });
    expect(res.status).toBe(200);
    await signed.verify(res);
    await expect(client.sign({ url: 'https://evil.example/x' })).rejects.toMatchObject({ code: 'config' });
  });

  it('onRequest hook can add headers (step-up extension point)', async () => {
    const { client } = make({ onRequest: (h) => h.set('X-Step-Up', 'assertion') });
    await client.fetch(`${BASE}/api/x/`);
    expect(env.rawCalls.at(-1)!.headers.get('x-step-up')).toBe('assertion');
  });

  it('sends the Turnstile token from the user callback', async () => {
    server.requireTurnstile = true;
    const { client } = make({ getTurnstileToken: async () => 'ts-ok' });
    expect((await client.fetch(`${BASE}/api/x/`)).status).toBe(200);
    expect(server.registeredBodies[0]!.web).toMatchObject({ turnstile_token: 'ts-ok' });
    const { client: bad } = make({ getTurnstileToken: async () => 'nope', keyStore: createMemoryKeyStore() });
    await expect(bad.fetch(`${BASE}/api/x/`)).rejects.toMatchObject({ code: 'register_failed', serverCode: 458118 });
  });

  it('never follows redirects on signed calls (redirect: manual by default, configurable to error); registration traffic neither', async () => {
    const { client } = make();
    await client.fetch(`${BASE}/api/a/`, { redirect: 'follow' });
    expect(env.rawCalls.at(-1)!.init!.redirect).toBe('manual');
    expect(env.rawCalls.filter((c) => c.url.includes('/restricto/')).every((c) => c.init!.redirect === 'error')).toBe(true);
    const { client: strict } = make({ redirect: 'error', keyStore: createMemoryKeyStore() });
    await strict.fetch(`${BASE}/api/a/`);
    expect(env.rawCalls.at(-1)!.init!.redirect).toBe('error');
  });
});

describe('cross-origin safety', () => {
  it('never signs, registers for, or leaks headers to another origin', async () => {
    const other = vi.fn(async () => new Response('ok'));
    const { client: c2 } = make({ fetch: other as unknown as typeof fetch });
    const res = await c2.fetch('https://cdn.other.example/lib.js', { headers: { 'x-a': 'b' } });
    expect(await res.text()).toBe('ok');
    const [, init] = other.mock.calls[0] as unknown as [string, RequestInit];
    expect(new Headers(init.headers).get('restricto-signature')).toBeNull();
    expect(new Headers(init.headers).get('x-app-id')).toBeNull();
    expect(other).toHaveBeenCalledTimes(1);
    expect(c2.getState().status).toBe('idle');
    for (const u of ['http://api.example.com/x', 'https://api.example.com:8443/x', 'https://x.api.example.com/x', 'https://api.example.com.evil.io/x']) {
      other.mockClear();
      await c2.fetch(u);
      const [, i2] = other.mock.calls[0] as unknown as [string, RequestInit | undefined];
      expect(new Headers(i2?.headers).get('restricto-signature'), u).toBeNull();
    }
  });
});

describe('signed rejections: only the verified `action` is acted upon', () => {
  it('resync_clock: adopts the SIGNED server_time (even when our clock is >300 s off) and retries with a NEW nonce', async () => {
    const { client } = make();
    await client.fetch(`${BASE}/api/a/`);
    server.seen.length = 0;
    const base = Math.floor(Date.now() / 1000);
    server.now = () => base + 600;
    const res = await client.fetch(`${BASE}/api/b/`);
    expect(res.status).toBe(200);
    expect(server.seen).toHaveLength(2);
    expect(server.seen[0]!.nonce).not.toBe(server.seen[1]!.nonce);
    expect(client.isVerified(res)).toBe(true);
  });

  it('replay (458066, action none): one retry with a new nonce; a second failure is surfaced, not looped', async () => {
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
    expect(server.seen).toHaveLength(2);
    expect(client.isVerified(res)).toBe(true);
    expect(await res.json()).toMatchObject({ error_code: 458066 });
  });

  it('attestation expired (action reregister): a SIGNED renew:true with the same key, then retry', async () => {
    const { client } = make();
    await client.fetch(`${BASE}/api/a/`);
    const id = client.getState().deviceId!;
    server.expire(id);
    const res = await client.fetch(`${BASE}/api/b/`);
    expect(res.status).toBe(200);
    expect(client.getState().deviceId).toBe(id);
    expect(server.counts).toMatchObject({ challenge: 2, register: 2, renew: 1 });
    expect(server.registeredBodies[1]).toMatchObject({ renew: true, caps: { sig: [1], cfg: 0 } });
  });

  it('unknown device (action reregister): falls back to a plain registration of the same key, then retries', async () => {
    const { client } = make();
    await client.fetch(`${BASE}/api/a/`);
    const id = client.getState().deviceId!;
    server.forget(id);
    expect((await client.fetch(`${BASE}/api/b/`)).status).toBe(200);
    expect(client.getState().deviceId).toBe(id);
    expect(server.registeredBodies.map((b) => b.renew)).toEqual([false, true, false]);
  });

  it('revoked (action wipe): wipes the key, registers a new one (new device id), retries', async () => {
    const { client, store } = make();
    await client.fetch(`${BASE}/api/a/`);
    const first = client.getState().deviceId!;
    server.revoke(first);
    expect((await client.fetch(`${BASE}/api/b/`)).status).toBe(200);
    const second = client.getState().deviceId!;
    expect(second).not.toBe(first);
    expect((await stateOf(store)).deviceId).toBe(second);
    expect(server.registeredBodies.at(-1)!.renew).toBe(false);
  });

  it('revoked and banned: the registration failure is surfaced', async () => {
    const { client } = make();
    await client.fetch(`${BASE}/api/a/`);
    server.revoke(client.getState().deviceId!);
    server.banRegistrations = true;
    await expect(client.fetch(`${BASE}/api/b/`)).rejects.toMatchObject({ code: 'register_failed', serverCode: 458118 });
    expect(client.getState().status).toBe('error');
  });

  it('action none is never retried (signature invalid, required, device rate limited) and surfaces as a verified response', async () => {
    const { client } = make();
    await client.fetch(`${BASE}/api/a/`);
    for (const code of [458047, 458010, 458151]) {
      server.seen.length = 0;
      server.failNext = { code, status: code === 458151 ? 429 : 401, remaining: 3 };
      const res = await client.fetch(`${BASE}/api/post/`, { method: 'POST', body: '{}' });
      expect(res.status).toBe(code === 458151 ? 429 : 401);
      expect(server.seen).toHaveLength(1);
      expect(client.isVerified(res)).toBe(true);
    }
    server.failNext = undefined;
  });

  it('backoff with a short Retry-After: an idempotent call waits once and retries; unknown actions go to the app untouched', async () => {
    const { client } = make();
    await client.fetch(`${BASE}/api/a/`);
    server.seen.length = 0;
    server.failNext = { code: 458151, status: 429, remaining: 1, action: 'backoff', retryAfter: '1' };
    const t0 = Date.now();
    expect((await client.fetch(`${BASE}/api/b/`)).status).toBe(200);
    expect(Date.now() - t0).toBeGreaterThanOrEqual(900);
    expect(server.seen).toHaveLength(2);
    server.seen.length = 0;
    server.failNext = { code: 450000, status: 400, remaining: 1, action: 'frobnicate' };
    const res = await client.fetch(`${BASE}/api/c/`);
    expect(res.status).toBe(400);
    expect(server.seen).toHaveLength(1);
  });

  it('action upgrade in an error body is advisory only: event + soft state, the response still comes back, calls keep working', async () => {
    const events: string[] = [];
    const { client } = make({ onUpgradeRequired: (u) => events.push(`${u.mode}:${u.reason}`) });
    await client.fetch(`${BASE}/api/a/`);
    server.failNext = { code: 458025, status: 400, remaining: 1, action: 'upgrade' };
    const res = await client.fetch(`${BASE}/api/b/`);
    expect(res.status).toBe(400);
    expect(events).toEqual(['soft:server']);
    expect(client.getState().upgrade).toMatchObject({ mode: 'soft' });
    expect((await client.fetch(`${BASE}/api/c/`)).status).toBe(200);
  });

  it('a plain application error (404) is verified and returned untouched', async () => {
    const { client } = make();
    const res = await client.fetch(`${BASE}/api/missing/`);
    expect(res.status).toBe(404);
    expect(client.isVerified(res)).toBe(true);
  });
});

describe('unsigned answers to signed requests are network errors, never acted upon', () => {
  it('an unsigned proxy error on a GET is retried with bounded backoff, then surfaces; key and registration are untouched', async () => {
    const { client, store } = make();
    await client.fetch(`${BASE}/api/a/`);
    const before = await stateOf(store);
    server.seen.length = 0;
    server.proxyNext = { status: 502, remaining: 99 };
    await expect(client.fetch(`${BASE}/api/b/`)).rejects.toMatchObject({ code: 'response_unverified', unsigned: true, status: 502 });
    expect(server.seen).toHaveLength(1 + 3);
    expect(await stateOf(store)).toEqual(before);
    expect(server.counts.register).toBe(1);
    expect(client.getState().status).toBe('ready');
    server.proxyNext = undefined;
    expect((await client.fetch(`${BASE}/api/c/`)).status).toBe(200);
  });

  it('a transient unsigned error that clears up is retried transparently', async () => {
    const { client } = make();
    await client.fetch(`${BASE}/api/a/`);
    server.proxyNext = { status: 503, remaining: 2 };
    const res = await client.fetch(`${BASE}/api/b/`);
    expect(res.status).toBe(200);
    expect(client.isVerified(res)).toBe(true);
  });

  it('a POST is never replayed after an unsigned error', async () => {
    const { client } = make();
    await client.fetch(`${BASE}/api/a/`);
    server.seen.length = 0;
    server.proxyNext = { status: 502, remaining: 5 };
    await expect(client.fetch(`${BASE}/api/post/`, { method: 'POST', body: '{}' })).rejects.toMatchObject({ code: 'response_unverified' });
    expect(server.seen).toHaveLength(1);
  });

  it('an unsigned body that LOOKS like a revocation (action wipe) never wipes the key or re-registers', async () => {
    const { client, store } = make();
    await client.fetch(`${BASE}/api/a/`);
    const before = await stateOf(store);
    server.proxyNext = { status: 403, remaining: 9, looksLikeRestricto: true };
    await expect(client.fetch(`${BASE}/api/post/`, { method: 'POST', body: '{}' })).rejects.toMatchObject({ code: 'response_unverified', unsigned: true });
    await expect(client.fetch(`${BASE}/api/get/`)).rejects.toMatchObject({ code: 'response_unverified' });
    expect(await stateOf(store)).toEqual(before);
    expect(server.counts).toMatchObject({ register: 1, challenge: 1 });
    expect(client.getState().deviceId).toBe(before.deviceId);
  });

  it('an unsigned reply never moves the clock', async () => {
    const { client } = make();
    await client.fetch(`${BASE}/api/a/`);
    server.proxyNext = { status: 401, remaining: 1, body: JSON.stringify({ error_code: 458052, action: 'resync_clock', server_time: 12345 }) };
    await expect(client.fetch(`${BASE}/api/post/`, { method: 'POST', body: '{}' })).rejects.toMatchObject({ code: 'response_unverified' });
    expect((await client.fetch(`${BASE}/api/b/`)).status).toBe(200);
  });

  it('an unsigned answer to a renewal is a network error: the old registration stays', async () => {
    const { client, store } = make();
    await client.fetch(`${BASE}/api/a/`);
    const id = client.getState().deviceId!;
    const before = await stateOf(store);
    const real = Date.now;
    vi.spyOn(Date, 'now').mockImplementation(() => real() + 4 * 86400_000); // the attestation has run out
    server.signResponses = false;
    await expect(client.ready()).rejects.toMatchObject({ code: 'response_unverified' });
    expect(await stateOf(store)).toEqual(before);
    expect(client.getState().deviceId).toBe(id);
    server.signResponses = true;
    expect((await client.fetch(`${BASE}/api/b/`)).status).toBe(200);
    expect(client.getState().deviceId).toBe(id);
    expect(server.counts.renew).toBe(2); // the failed one and the one that worked: never a plain re-registration
  });
});

describe('redirects and off-origin replies are ignored (A-1)', () => {
  const via = (props: Record<string, unknown>) => (async (input: RequestInfo | URL, init?: RequestInit) => {
    const res = await server.fetch(input, init);
    return String(input).includes('/api/') ? withProps(res, props) : res;
  }) as typeof fetch;

  it('a perfectly signed "wipe" that arrived through a redirect is not acted upon', async () => {
    const { client, store } = make({ fetch: via({ redirected: true, url: 'https://evil.example/api/x' }) });
    await client.ready();
    const id = client.getState().deviceId!;
    server.failNext = { code: 458071, status: 403, remaining: 9, action: 'wipe' };
    await expect(client.fetch(`${BASE}/api/post/`, { method: 'POST', body: '{}' })).rejects.toMatchObject({ code: 'redirect' });
    expect((await stateOf(store)).deviceId).toBe(id);
    expect(server.counts.register).toBe(1);
  });

  it('same for a reply whose url is another origin, and for recover()', async () => {
    const { client } = make({ fetch: via({ url: 'https://evil.example/api/x' }) });
    await client.ready();
    const signed = await client.sign({ url: `${BASE}/api/x/` });
    server.failNext = { code: 458071, status: 403, remaining: 1, action: 'wipe' };
    const res = withProps(await server.fetch(`${BASE}/api/x/`, { headers: signed.headers }), { url: 'https://evil.example/api/x' });
    expect(await client.recover(res, signed)).toBe(false);
    expect(client.getState().deviceId).not.toBeNull();
    expect(server.counts.register).toBe(1);
  });

  it('an opaqueredirect (browser, redirect: manual) is reported as a redirect error, not followed or trusted', async () => {
    const { client } = make({ fetch: via({ type: 'opaqueredirect', status: 0 }) });
    await client.ready();
    await expect(client.fetch(`${BASE}/api/x/`)).rejects.toMatchObject({ code: 'redirect' });
    expect(server.counts.api).toBe(1);
  });

  it('a signed 302 is verified including its Location and handed back, never followed; an unsigned one is rejected', async () => {
    const { client } = make();
    await client.ready();
    server.redirectNext = { location: 'https://evil.example/', remaining: 1 };
    const res = await client.fetch(`${BASE}/api/x/`);
    expect(res.status).toBe(302);
    expect(client.isVerified(res)).toBe(true);
    server.redirectNext = { location: 'https://evil.example/', remaining: 9, signed: false };
    await expect(client.fetch(`${BASE}/api/post/`, { method: 'POST', body: '{}' })).rejects.toMatchObject({ code: 'response_unverified' });
  });
});

describe('recover() for custom stacks', () => {
  it('acts only on a verified signed reply for THAT request', async () => {
    const { client } = make();
    await client.ready();
    const base = Math.floor(Date.now() / 1000);
    server.now = () => base + 200;
    const signed = await client.sign({ url: `${BASE}/api/x/` });
    const rejected = await server.fetch(`${BASE}/api/x/`, { headers: signed.headers });
    expect(rejected.status).toBe(401);
    expect(await client.recover(rejected, signed)).toBe(true);
    const again = await client.sign({ url: `${BASE}/api/x/` });
    const ok = await server.fetch(`${BASE}/api/x/`, { headers: again.headers });
    expect(ok.status).toBe(200);
    const forged = new Response(JSON.stringify({ error_code: 458071, action: 'wipe' }), { status: 403 });
    expect(await client.recover(forged, again)).toBe(false);
    const other = await client.sign({ url: `${BASE}/api/y/` });
    server.failNext = { code: 458071, status: 403, remaining: 1, action: 'wipe' };
    const stranger = await server.fetch(`${BASE}/api/y/`, { headers: other.headers });
    expect(await client.recover(stranger, again)).toBe(false);
    expect(await client.recover(ok, again)).toBe(false);
    expect(server.counts.register).toBe(1);
  });
});

describe('attestation lifetime', () => {
  it('renews in the background (signed renewal) before attested_until, and awaits a renewal once it has passed', async () => {
    server.validitySeconds = 1000;
    const real = Date.now;
    let shift = 0;
    vi.spyOn(Date, 'now').mockImplementation(() => real() + shift * 1000);
    const { client } = make({ autoRefresh: false });
    await client.fetch(`${BASE}/api/a/`);
    expect(server.counts.register).toBe(1);

    shift = 800;
    await client.fetch(`${BASE}/api/b/`);
    await vi.waitFor(() => expect(client.getState().attestedUntil).toBeGreaterThan(Math.floor(real() / 1000) + 1500));
    expect(server.counts.register).toBe(2);
    expect(server.counts.renew).toBe(1);

    shift = 800 + 1100;
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
    await vi.advanceTimersToNextTimerAsync(); // the renewal timer: stops there, so the fake clock does not run on during the registration
    await vi.waitFor(() => expect(server.counts.register).toBe(2));
    expect(server.counts.renew).toBe(1);
    client.close();
  });

  it('a server that refuses web renewals (signed 403, action none): falls back once to a plain registration and remembers it', async () => {
    server.renewSupported = false;
    const { client, store } = make();
    await client.fetch(`${BASE}/api/a/`);
    const id = client.getState().deviceId!;
    server.expire(id);
    expect((await client.fetch(`${BASE}/api/b/`)).status).toBe(200);
    expect(server.counts.renew).toBe(1);
    expect(server.registeredBodies.map((b) => b.renew)).toEqual([false, true, false]);
    expect((await stateOf(store)).noRenew).toBe(true);
    server.expire(id);
    expect((await client.fetch(`${BASE}/api/c/`)).status).toBe(200);
    expect(server.counts.renew).toBe(1);
    expect(client.getState().deviceId).toBe(id);
  });

  it('signedRenewal:false always re-registers the key directly', async () => {
    const { client } = make({ signedRenewal: false });
    await client.fetch(`${BASE}/api/a/`);
    server.expire(client.getState().deviceId!);
    expect((await client.fetch(`${BASE}/api/b/`)).status).toBe(200);
    expect(server.counts.renew).toBe(0);
  });

  it('A-3: a "successful" registration that is already expired does not loop (one attempt, then fail fast)', async () => {
    server.validitySeconds = -10;
    const { client } = make();
    const err = await client.fetch(`${BASE}/api/a/`).catch((e: RestrictoError) => e);
    expect(err).toMatchObject({ code: 'register_failed', retryAfter: 60 });
    expect(server.counts.register).toBe(1);
    await expect(client.fetch(`${BASE}/api/a/`)).rejects.toMatchObject({ code: 'register_failed' });
    await expect(client.fetch(`${BASE}/api/a/`)).rejects.toMatchObject({ code: 'register_failed' });
    expect(server.counts.register).toBe(1);
    expect(server.counts.api).toBe(0);
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

describe('concurrency and lifecycle (A-2, A-4)', () => {
  it('parallel calls in one page register exactly once', async () => {
    const { client } = make();
    const results = await Promise.all(Array.from({ length: 8 }, (_, i) => client.fetch(`${BASE}/api/p/${i}/`)));
    expect(results.every((r) => r.status === 200)).toBe(true);
    expect(server.counts).toMatchObject({ challenge: 1, register: 1, api: 8 });
    expect(new Set(server.seen.map((s) => s.nonce)).size).toBe(8);
  });

  it('two "tabs" (separate clients sharing storage) register once through Web Locks', async () => {
    let tail: Promise<unknown> = Promise.resolve();
    const lockRequests: string[] = [];
    vi.stubGlobal('navigator', {
      locks: {
        request: (name: string, fn: () => Promise<unknown>) => {
          lockRequests.push(name);
          const run = tail.then(fn, fn);
          tail = run.catch(() => undefined);
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

  it('two tabs that both receive a wipe action mint exactly ONE replacement key', async () => {
    const store = createMemoryKeyStore();
    const a = make({ keyStore: store }).client;
    const b = make({ keyStore: store }).client;
    await a.ready();
    await b.ready();
    expect(a.getState().deviceId).toBe(b.getState().deviceId);
    expect(server.devices.size).toBe(1);
    server.revoke(a.getState().deviceId!);
    const [ra, rb] = await Promise.all([a.fetch(`${BASE}/api/a/`), b.fetch(`${BASE}/api/b/`)]);
    expect([ra.status, rb.status]).toEqual([200, 200]);
    expect(server.devices.size).toBe(2);
    expect(a.getState().deviceId).toBe(b.getState().deviceId);
  });

  it('reset() during an in-flight registration: the late result does not resurrect the wiped key', async () => {
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    let reachedRegister!: () => void;
    const reached = new Promise<void>((r) => (reachedRegister = r));
    const store = createMemoryKeyStore();
    const { client } = make({
      keyStore: store,
      fetch: (async (input: RequestInfo | URL, init?: RequestInit) => {
        if (String(input).endsWith('/device/register/')) {
          reachedRegister();
          await gate; // deliberately ignores the abort signal: the late answer must still be discarded
        }
        return server.fetch(input, init);
      }) as typeof fetch,
    });
    const settled = client.ready().then(() => 'ok', (e: RestrictoError) => e.code);
    await reached;
    const resetting = client.reset();
    release();
    await resetting;
    expect(await settled).toBe('aborted');
    expect(await store.get(`${server.appId}|${BASE}`)).toBeUndefined();
    expect(client.getState()).toMatchObject({ status: 'idle', deviceId: null });
    expect((await client.fetch(`${BASE}/api/a/`)).status).toBe(200);
    expect(client.getState().status).toBe('ready');
  });

  it('close() aborts the proof of work in flight (main-thread solve), quickly', async () => {
    server.powBits = 24;
    const { client } = make();
    const started = Date.now();
    const p = client.ready().catch((e: RestrictoError) => e);
    await new Promise((r) => setTimeout(r, 150));
    client.close();
    expect(await p).toMatchObject({ code: 'aborted' });
    expect(Date.now() - started).toBeLessThan(3000);
    expect(server.counts.register).toBe(0);
  });

  it('the proof of work gives up after its wall-clock budget', async () => {
    server.powBits = 24;
    const { client } = make({ powBudgetMs: 100 });
    const started = Date.now();
    await expect(client.ready()).rejects.toMatchObject({ code: 'register_failed', message: expect.stringMatching(/budget/) });
    expect(Date.now() - started).toBeLessThan(3000);
  });

  it('a failed registration fails fast during the cooldown and recovers afterwards', async () => {
    server.banRegistrations = true;
    const { client } = make({ registerCooldownMs: 60_000 });
    await expect(client.fetch(`${BASE}/api/a/`)).rejects.toMatchObject({ code: 'register_failed' });
    expect(server.counts.register).toBe(1);
    await expect(client.fetch(`${BASE}/api/a/`)).rejects.toMatchObject({ code: 'register_failed' });
    expect(server.counts.register).toBe(1);
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
    const post = (): Promise<Response> => client.fetch(`${BASE}/api/post/`, { method: 'POST', body: '{}' });
    server.tamperBody = true;
    await expect(post()).rejects.toMatchObject({ code: 'response_unverified' });
    server.tamperBody = false;
    server.badSignature = true;
    await expect(post()).rejects.toMatchObject({ code: 'response_unverified' });
    server.badSignature = false;
    server.staleResponseTs = true;
    await expect(post()).rejects.toThrow(/timestamp/);
    server.staleResponseTs = false;
    server.replayResponseNonce = true;
    await expect(post()).rejects.toMatchObject({ code: 'response_unverified' });
    server.replayResponseNonce = false;
    server.signResponses = false;
    await expect(post()).rejects.toThrow(/no Restricto signature/);
    server.signResponses = true;
    expect((await post()).status).toBe(200);
  });

  it('accepts a response if ANY listed signature verifies: unknown algorithms and unknown kids are ignored', async () => {
    const { client } = make();
    server.extraSigFields = [`v=1,kid=zz,alg=Ed25519,ts=${server.now()},sig=${'A'.repeat(86)}`, `v=1,kid=k1,alg=ML-DSA-44,ts=${server.now()},sig=${'B'.repeat(86)}`];
    const res = await client.fetch(`${BASE}/api/a/`);
    expect(res.status).toBe(200);
    expect(client.isVerified(res)).toBe(true);
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
    await expect(client.fetch(`${BASE}/api/post/`, { method: 'POST', body: '{}' })).rejects.toMatchObject({ code: 'response_unverified' });
    const { client: other } = make({ pinnedResponseKeys: { other: server.publicKeyB64 }, keyStore: createMemoryKeyStore() });
    await expect(other.fetch(`${BASE}/api/post/`, { method: 'POST', body: '{}' })).rejects.toThrow(/unknown response signing key/);
    expect(server.counts.keys).toBe(0);
  });

  it('without any pin the keys are fetched once from /keys/ (trust on first use, weaker) and cached', async () => {
    const { client } = make({ pinnedResponseKeys: undefined });
    await client.fetch(`${BASE}/api/a/`);
    await client.fetch(`${BASE}/api/b/`);
    expect(server.counts.keys).toBe(1);
    expect(server.counts.config).toBe(0);
  });

  it('works with the noble Ed25519 fallback', async () => {
    const { client } = make({ forceEd25519Fallback: true });
    const res = await client.fetch(`${BASE}/api/a/`);
    expect(client.isVerified(res)).toBe(true);
    server.tamperBody = true;
    await expect(client.fetch(`${BASE}/api/post/`, { method: 'POST', body: '{}' })).rejects.toMatchObject({ code: 'response_unverified' });
  });

  it('config errors: missing fields and empty pin sets', () => {
    expect(() => createRestricto({ baseUrl: '', appId: '' })).toThrow(RestrictoError);
    expect(() => createRestricto({ baseUrl: BASE, appId: 'a', pinnedResponseKeys: {} })).toThrow(/pinnedResponseKeys/);
    expect(() => createRestricto({ baseUrl: BASE, appId: 'a', pinnedConfigKeys: {} })).toThrow(/pinnedConfigKeys/);
  });
});

describe('axios adapter', () => {
  it('signs through a real axios instance (params, JSON body, error status, Authorization passthrough)', async () => {
    const axios = (await import('axios')).default;
    const { client } = make();
    const http = axios.create({ baseURL: BASE, adapter: restrictoAxios(client) as never });
    const r = await http.post('/api/ax/', { hello: 'wörld' }, { params: { q: 'a b', n: 2 }, headers: { Authorization: 'Bearer t' } });
    expect(r.status).toBe(200);
    expect(r.data).toMatchObject({ method: 'POST', body: '{"hello":"wörld"}', authorization: 'Bearer t' });
    expect(r.data.target).toBe('/api/ax/?n=2&q=a%2Bb');
    await expect(http.get('/api/missing/')).rejects.toMatchObject({ isAxiosError: true, response: { status: 404 } });
    expect((await http.get('/api/missing/', { validateStatus: () => true })).status).toBe(404);
    server.tamperBody = true;
    await expect(http.get('/api/ax/')).rejects.toMatchObject({ code: 'response_unverified' });
  });
});
