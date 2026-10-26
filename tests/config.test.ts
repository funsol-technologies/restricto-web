import { generateKeyPairSync } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createMemoryKeyStore, type RestrictoConfig } from '../src';
import { FakeRestricto } from './helpers/fake-server';
import { BASE, makeIn, type Env } from './helpers/make';

const env: Env = { server: undefined as unknown as FakeRestricto, rawCalls: [] };
let server: FakeRestricto;
/** A client that trusts only the pinned config key: response keys come from the signed document. */
const make = (over: Partial<RestrictoConfig> = {}) => makeIn(env, { pinnedConfigKeys: server.pinnedConfigKeys, pinnedResponseKeys: undefined, ...over });

beforeEach(() => {
  server = new FakeRestricto();
  env.server = server;
  env.rawCalls = [];
});
afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe('signed config document (section 6)', () => {
  it('is fetched at first use, verified, and supplies the response keys (no /keys/ trust on first use)', async () => {
    server.publishConfig();
    const { client } = make();
    const res = await client.fetch(`${BASE}/api/a/`);
    expect(res.status).toBe(200);
    expect(client.isVerified(res)).toBe(true);
    expect(server.counts).toMatchObject({ config: 1, keys: 0 });
    expect(client.getState().config).toMatchObject({ source: 'valid', seq: 1, relaxed: false, lastError: null });
    expect(server.registeredBodies[0]!.caps).toEqual({ sig: [1], cfg: 1 }); // the registration reports the document we hold
    expect(env.rawCalls.find((c) => c.url.endsWith('/restricto/config/'))!.headers.get('x-app-id')).toBe(server.appId);
  });

  it('unknown fields in the document are ignored', async () => {
    server.publishConfig({ extra: { brand_new: { nested: [1, 2, 3] }, pow: { alg: 'sha256-lz', bits: 12, max_bits: 26, future: true } } });
    const { client } = make();
    expect((await client.fetch(`${BASE}/api/a/`)).status).toBe(200);
  });

  it('without a document and without any other key, the SDK fails closed (never "no security")', async () => {
    const { client } = make();
    await expect(client.fetch(`${BASE}/api/post/`, { method: 'POST', body: '{}' })).rejects.toMatchObject({ code: 'response_unverified', message: expect.stringMatching(/signed config/) });
    expect(client.getState().config).toMatchObject({ source: 'defaults' });
    expect(server.counts.keys).toBe(0);
  });

  it('with pinnedResponseKeys as well, a missing document is survivable (those keys are authoritative)', async () => {
    const { client } = make({ pinnedResponseKeys: { k1: server.publicKeyB64 } });
    expect((await client.fetch(`${BASE}/api/a/`)).status).toBe(200);
    expect(client.getState().config.source).toBe('defaults');
  });

  describe('verification rules', () => {
    it.each([
      ['signed by a key that is not pinned', () => server.publishConfig({ signWith: generateKeyPairSync('ed25519').privateKey })],
      ['naming a kid that is not pinned', () => server.publishConfig({ kid: 'cfg-unknown' })],
      ['for another application', () => server.publishConfig({ app: 'com.other.app' })],
    ])('rejects a document %s', async (_n, publish) => {
      publish();
      const warnings: string[] = [];
      const { client } = make({ onWarning: (m) => warnings.push(m) });
      await expect(client.fetch(`${BASE}/api/post/`, { method: 'POST', body: '{}' })).rejects.toMatchObject({ code: 'response_unverified' });
      expect(client.getState().config).toMatchObject({ source: 'defaults' });
      expect(client.getState().config.lastError).toMatch(/rejected/);
      expect(warnings.join()).toMatch(/config document rejected/);
    });

    it('rejects a tampered payload', async () => {
      const doc = server.publishConfig();
      const bad = { ...doc, payload: Buffer.from(Buffer.from(doc.payload, 'base64url').toString().replace('"seq":1', '"seq":9')).toString('base64url') };
      server.configOverride = { status: 200, body: bad };
      const { client } = make({ pinnedResponseKeys: { k1: server.publicKeyB64 } });
      expect((await client.fetch(`${BASE}/api/a/`)).status).toBe(200);
      expect(client.getState().config.source).toBe('defaults');
    });

    it('any one of several pinned config keys may verify', async () => {
      server.publishConfig();
      const { client } = make({ pinnedConfigKeys: { 'cfg-old': Buffer.alloc(32, 3).toString('base64url'), ...server.pinnedConfigKeys } });
      expect((await client.fetch(`${BASE}/api/a/`)).status).toBe(200);
      expect(client.getState().config.source).toBe('valid');
    });

    it('anti-rollback: a lower seq is rejected, the higher one stays in force', async () => {
      server.publishConfig({ seq: 5 });
      const warnings: string[] = [];
      const { client } = make({ onWarning: (m) => warnings.push(m) });
      await client.fetch(`${BASE}/api/a/`);
      expect(client.getState().config.seq).toBe(5);
      server.publishConfig({ seq: 3 });
      const status = await client.refreshConfig();
      expect(status).toMatchObject({ seq: 5, source: 'valid' });
      expect(status.lastError).toMatch(/rollback/);
      expect((await client.fetch(`${BASE}/api/b/`)).status).toBe(200);
      server.publishConfig({ seq: 6 });
      expect((await client.refreshConfig()).seq).toBe(6);
    });

    it('an expired document is not adopted while a good one is held (last good wins)', async () => {
      server.publishConfig({ seq: 1 });
      const { client } = make();
      await client.fetch(`${BASE}/api/a/`);
      server.publishConfig({ seq: 2, exp: server.now() - 10 });
      const status = await client.refreshConfig();
      expect(status).toMatchObject({ seq: 1, source: 'valid' });
      expect(status.lastError).toMatch(/expired/);
    });

    it('with nothing better, an expired document still supplies its key set and limits - but its relax flags are dead', async () => {
      server.publishConfig({ exp: server.now() - 10, extra: { relax: { verify_responses: false } } });
      const { client } = make();
      expect((await client.fetch(`${BASE}/api/a/`)).status).toBe(200);
      expect(client.getState().config).toMatchObject({ source: 'expired', relaxed: false });
      server.tamperBody = true;
      await expect(client.fetch(`${BASE}/api/post/`, { method: 'POST', body: '{}' })).rejects.toMatchObject({ code: 'response_unverified' });
    });

    it('a document that runs out while the page is open becomes "expired" (and stops relaxing)', async () => {
      const real = Date.now;
      let shift = 0;
      vi.spyOn(Date, 'now').mockImplementation(() => real() + shift * 1000);
      server.publishConfig({ exp: server.now() + 1000, extra: { relax: { verify_responses: false } } });
      const { client } = make();
      await client.fetch(`${BASE}/api/a/`);
      expect(client.getState().config).toMatchObject({ source: 'valid', relaxed: true });
      server.tamperBody = true;
      expect((await client.fetch(`${BASE}/api/post/`, { method: 'POST', body: '{}' })).status).toBe(200); // relaxed: warn, not throw
      shift = 2000;
      await client.refreshConfig(); // nothing newer: still the same expired document
      expect(client.getState().config).toMatchObject({ source: 'expired', relaxed: false });
      await expect(client.fetch(`${BASE}/api/post/`, { method: 'POST', body: '{}' })).rejects.toMatchObject({ code: 'response_unverified' });
    });
  });

  describe('server-driven behaviour', () => {
    it('key rotation: next -> active needs no new document and no SDK change', async () => {
      server.addKey('k2', 'next');
      server.publishConfig();
      const { client } = make();
      expect(client.isVerified(await client.fetch(`${BASE}/api/a/`))).toBe(true);
      server.promote('k2'); // the server now signs with k2; k1 is retired
      expect(server.active.kid).toBe('k2');
      const res = await client.fetch(`${BASE}/api/b/`);
      expect(client.isVerified(res)).toBe(true);
      expect(server.counts.config).toBe(1);
    });

    it('key rotation with an unforeseen key: an unknown kid triggers one throttled refetch of the document', async () => {
      const real = Date.now;
      let shift = 0;
      vi.spyOn(Date, 'now').mockImplementation(() => real() + shift * 1000);
      server.publishConfig();
      const { client } = make();
      await client.fetch(`${BASE}/api/a/`);
      server.addKey('k9', 'next');
      server.promote('k9');
      server.publishConfig(); // seq 2 lists k9
      // too soon after the last fetch: refused to hammer the endpoint, the call fails closed (idempotent: retried, then surfaces)
      await expect(client.fetch(`${BASE}/api/b/`)).rejects.toMatchObject({ code: 'response_unverified', message: expect.stringMatching(/unknown response signing key "k9"/) });
      expect(server.counts.config).toBe(1);
      shift = 61;
      const res = await client.fetch(`${BASE}/api/c/`);
      expect(client.isVerified(res)).toBe(true);
      expect(server.counts.config).toBe(2);
      expect(client.getState().config.seq).toBe(2);
    });

    it('a higher cfg_seq reported by the challenge triggers a refetch', async () => {
      const real = Date.now;
      let shift = 0;
      vi.spyOn(Date, 'now').mockImplementation(() => real() + shift * 1000);
      server.publishConfig();
      const { client } = make();
      await client.fetch(`${BASE}/api/a/`);
      expect(server.counts.config).toBe(1);
      server.publishConfig(); // seq 2
      shift = 4 * 86400; // the attestation has run out: a renewal starts and its challenge reports cfg_seq 2
      await client.fetch(`${BASE}/api/b/`);
      await vi.waitFor(() => expect(client.getState().config.seq).toBe(2));
      expect(server.counts.config).toBe(2);
    });

    it('a hostile challenge cannot make the SDK work beyond the signed max_bits', async () => {
      server.announcedBits = 60;
      server.publishConfig({ extra: { pow: { alg: 'sha256-lz', bits: 4, max_bits: 8 } } });
      const { client } = make();
      const started = Date.now();
      await expect(client.ready()).rejects.toMatchObject({ code: 'register_failed', status: 403 });
      expect(Date.now() - started).toBeLessThan(3000);
    });

    it('the compiled-in ceiling (26 bits) wins over a document asking for more, and the config base bits are honoured', async () => {
      server.announcedBits = 0;
      server.publishConfig({ extra: { pow: { alg: 'sha256-lz', bits: 12, max_bits: 99 } } });
      const { client } = make();
      await client.ready(); // challenge says 0, the signed config says 12: the SDK does the 12 bits the server enforces
      expect(client.getState().status).toBe('ready');
    });

    it('retry budgets come from the document (transient: 0 means no retry of an unsigned GET error)', async () => {
      server.publishConfig({ extra: { retry: { replay: 0, unknown_device: 0, transient: 0 } } });
      const { client } = make();
      await client.fetch(`${BASE}/api/a/`);
      server.seen.length = 0;
      server.proxyNext = { status: 502, remaining: 9 };
      await expect(client.fetch(`${BASE}/api/b/`)).rejects.toMatchObject({ code: 'response_unverified' });
      expect(server.seen).toHaveLength(1);
      server.proxyNext = undefined;
      server.seen.length = 0;
      server.failNext = { code: 458066, status: 401, remaining: 3 };
      expect((await client.fetch(`${BASE}/api/c/`)).status).toBe(401); // replay budget 0
      expect(server.seen).toHaveLength(1);
      server.failNext = undefined;
      server.revoke(client.getState().deviceId!);
      expect((await client.fetch(`${BASE}/api/d/`)).status).toBe(403); // unknown_device budget 0: the wipe is not acted upon here
    });

    it('relax.verify_responses=false turns strict into warn while the document is valid', async () => {
      server.publishConfig({ extra: { relax: { verify_responses: false } } });
      const warnings: string[] = [];
      const { client } = make({ onWarning: (m) => warnings.push(m) });
      await client.fetch(`${BASE}/api/a/`);
      expect(client.getState().config.relaxed).toBe(true);
      server.tamperBody = true;
      const res = await client.fetch(`${BASE}/api/post/`, { method: 'POST', body: '{}' });
      expect(res.status).toBe(200);
      expect(client.isVerified(res)).toBe(false);
      expect(warnings.join()).toMatch(/not verified/);
    });

    it('min_sdk above this SDK is a hard upgrade (only from the signed document): signed calls fail, state + event say why', async () => {
      server.publishConfig({ extra: { min_sdk: { web: '9.0.0' }, upgrade: { mode: 'hard', url: 'https://example.com/update' } } });
      const events: Array<{ mode: string; reason: string; url: string }> = [];
      const { client } = make({ onUpgradeRequired: (u) => events.push(u) });
      await expect(client.fetch(`${BASE}/api/a/`)).rejects.toMatchObject({ code: 'upgrade_required' });
      expect(client.getState().upgrade).toMatchObject({ mode: 'hard', reason: 'min_sdk', minSdk: '9.0.0', url: 'https://example.com/update' });
      expect(events).toHaveLength(1);
      expect(server.counts.register).toBe(0); // nothing was signed or registered for a build the server refuses
    });

    it('a pre-release of the required version is accepted (1.0.0-rc.1 vs min 1.0.0); soft upgrades only notify', async () => {
      server.publishConfig({ extra: { min_sdk: { web: '1.0.0' }, upgrade: { mode: 'soft', url: 'javascript:alert(1)' } } });
      const events: string[] = [];
      const { client } = make({ onUpgradeRequired: (u) => events.push(`${u.mode}:${u.reason}:${u.url}`) });
      expect((await client.fetch(`${BASE}/api/a/`)).status).toBe(200);
      expect(events).toEqual(['soft:config:']); // a non-http(s) URL is dropped
      expect(client.getState().upgrade).toMatchObject({ mode: 'soft' });
    });

    it('a document that drops signature version 1 makes this SDK a hard upgrade; the same claim in an unsigned challenge is only advice', async () => {
      server.publishConfig({ extra: { sig_versions: [2] } });
      const { client } = make();
      await expect(client.fetch(`${BASE}/api/a/`)).rejects.toMatchObject({ code: 'upgrade_required' });
      expect(client.getState().upgrade).toMatchObject({ mode: 'hard', reason: 'sig_version' });
    });
  });

  describe('persistence', () => {
    it('the accepted document survives a reload (used when the network fails) and its seq is the rollback floor', async () => {
      const store = createMemoryKeyStore();
      server.publishConfig({ seq: 7 });
      const { client } = make({ keyStore: store });
      await client.fetch(`${BASE}/api/a/`);
      expect((await store.getConfig!(`${server.appId}|${BASE}`))!.seq).toBe(7);

      server.configOverride = { status: 500 };
      const { client: reloaded } = make({ keyStore: store });
      expect((await reloaded.fetch(`${BASE}/api/b/`)).status).toBe(200);
      expect(reloaded.getState().config).toMatchObject({ source: 'valid', seq: 7 });

      const old = server.publishConfig({ seq: 3 });
      server.configOverride = { status: 200, body: old };
      const { client: third } = make({ keyStore: store });
      await third.fetch(`${BASE}/api/c/`);
      expect(third.getState().config).toMatchObject({ seq: 7 });
      expect(third.getState().config.lastError).toMatch(/rollback/);
    });

    it('a tampered stored document is ignored (it is verified again on load)', async () => {
      const store = createMemoryKeyStore();
      const doc = server.publishConfig({ seq: 2 });
      const bad = { ...doc, payload: Buffer.from(Buffer.from(doc.payload, 'base64url').toString().replace('"seq":2', '"seq":4')).toString('base64url') };
      await store.putConfig!(`${server.appId}|${BASE}`, { doc: bad, seq: 1 });
      const { client } = make({ keyStore: store });
      await client.fetch(`${BASE}/api/a/`);
      expect(client.getState().config).toMatchObject({ source: 'valid', seq: 2 });
    });

    it('reset() wipes the device but keeps the anti-rollback state', async () => {
      const store = createMemoryKeyStore();
      server.publishConfig({ seq: 4 });
      const { client } = make({ keyStore: store });
      await client.fetch(`${BASE}/api/a/`);
      await client.reset();
      expect(await store.get(`${server.appId}|${BASE}`)).toBeUndefined();
      expect((await store.getConfig!(`${server.appId}|${BASE}`))!.seq).toBe(4);
      expect(client.getState().config.seq).toBe(4);
    });
  });

  it('a hanging config endpoint times out; the first call then proceeds with what it has (here: pinned response keys)', async () => {
    const hang: typeof fetch = ((input: RequestInfo | URL, init?: RequestInit) =>
      String(input).endsWith('/restricto/config/')
        ? new Promise((_, reject) => init?.signal?.addEventListener('abort', () => reject(new Error('aborted'))))
        : server.fetch(input, init)) as typeof fetch;
    const { client } = make({ fetch: hang, configTimeoutMs: 50, pinnedResponseKeys: { k1: server.publicKeyB64 } });
    const started = Date.now();
    expect((await client.fetch(`${BASE}/api/a/`)).status).toBe(200);
    expect(Date.now() - started).toBeLessThan(3000);
    expect(client.getState().config).toMatchObject({ source: 'defaults', lastError: expect.stringMatching(/unavailable/) });
  });

  it('refreshConfig() without pinnedConfigKeys reports "none" and fetches nothing', async () => {
    const { client } = makeIn(env, {});
    expect((await client.refreshConfig()).source).toBe('none');
    expect(server.counts.config).toBe(0);
  });
});
