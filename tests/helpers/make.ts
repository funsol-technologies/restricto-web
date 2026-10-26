import { createMemoryKeyStore, createRestricto, type RestrictoConfig } from '../../src';
import type { FakeRestricto } from './fake-server';

export const BASE = 'https://api.example.com';

export interface Env {
  server: FakeRestricto;
  rawCalls: Array<{ url: string; headers: Headers; init?: RequestInit }>;
}

/** A client wired to the fake server; every call that reaches the "network" is recorded in `env.rawCalls`. */
export function makeIn(env: Env, over: Partial<RestrictoConfig> = {}, srv: FakeRestricto = env.server) {
  const store = over.keyStore ?? createMemoryKeyStore();
  const client = createRestricto({
    baseUrl: BASE,
    appId: srv.appId,
    keyStore: store,
    pow: { useWorker: false },
    useWebLocks: false,
    registerCooldownMs: 0,
    transientBackoffMs: 0,
    pinnedResponseKeys: { k1: srv.publicKeyB64 },
    onWarning: () => undefined,
    fetch: (async (input: RequestInfo | URL, init?: RequestInit) => {
      env.rawCalls.push({ url: typeof input === 'string' ? input : String(input), headers: new Headers(init?.headers), init });
      return srv.fetch(input, init);
    }) as typeof fetch,
    ...over,
  });
  return { client, store };
}

/** Pretend the browser followed a redirect / the reply came from elsewhere. */
export function withProps(res: Response, props: Record<string, unknown>): Response {
  for (const [k, v] of Object.entries(props)) Object.defineProperty(res, k, { value: v });
  return res;
}
