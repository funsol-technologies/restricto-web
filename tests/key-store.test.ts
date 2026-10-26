import 'fake-indexeddb/auto';
import { describe, expect, it } from 'vitest';
import { createIndexedDbKeyStore, createMemoryKeyStore, createRestricto, defaultKeyStore } from '../src';
import { FakeRestricto } from './helpers/fake-server';

async function newKey() {
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
  return pair;
}

describe('IndexedDB key store', () => {
  it('persists a non-extractable CryptoKey that still signs after a round trip, and namespaces per app', async () => {
    const store = createIndexedDbKeyStore('t1');
    const pair = await newKey();
    await store.put('app-a', { privateKey: pair.privateKey, publicKey: 'spki', deviceId: 'rd_x', attestedUntil: 123 });
    const again = createIndexedDbKeyStore('t1'); // new handle = "next page load"
    const rec = (await again.get('app-a'))!;
    expect(rec).toMatchObject({ publicKey: 'spki', deviceId: 'rd_x', attestedUntil: 123 });
    expect(rec.privateKey.extractable).toBe(false);
    const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, rec.privateKey, new Uint8Array([1, 2, 3]));
    expect(await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, pair.publicKey, sig, new Uint8Array([1, 2, 3]))).toBe(true);
    expect(await again.get('app-b')).toBeUndefined();
    await again.delete('app-a');
    expect(await store.get('app-a')).toBeUndefined();
  });

  it('a client survives a "reload" through IndexedDB without re-registering', async () => {
    const server = new FakeRestricto();
    const cfg = { baseUrl: 'https://api.example.com', appId: server.appId, fetch: server.fetch as typeof fetch, pow: { useWorker: false }, pinnedResponseKeys: { k1: server.publicKeyB64 }, useWebLocks: false };
    const a = createRestricto({ ...cfg, keyStore: createIndexedDbKeyStore('t2') });
    await a.fetch('https://api.example.com/api/x/');
    const b = createRestricto({ ...cfg, keyStore: createIndexedDbKeyStore('t2') });
    await b.fetch('https://api.example.com/api/x/');
    expect(server.counts.register).toBe(1);
    expect(b.getState().deviceId).toBe(a.getState().deviceId);
  });

  it('defaultKeyStore falls back to memory when IndexedDB breaks', async () => {
    const real = globalThis.indexedDB;
    (globalThis as { indexedDB: unknown }).indexedDB = { open: () => { throw new Error('private mode'); } };
    try {
      const store = defaultKeyStore();
      const pair = await newKey();
      await store.put('x', { privateKey: pair.privateKey, publicKey: 'p' });
      expect((await store.get('x'))?.publicKey).toBe('p');
    } finally {
      (globalThis as { indexedDB: unknown }).indexedDB = real;
    }
  });

  it('memory store basics', async () => {
    const s = createMemoryKeyStore();
    const pair = await newKey();
    await s.put('k', { privateKey: pair.privateKey, publicKey: 'p' });
    expect((await s.get('k'))?.publicKey).toBe('p');
    await s.delete('k');
    expect(await s.get('k')).toBeUndefined();
  });
});
