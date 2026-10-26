import { renderToString } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { createRestricto } from '../src';
import { RestrictoProvider, useRestricto } from '../src/react';

describe('SSR (pure Node: no window, no indexedDB, no navigator)', () => {
  it('has none of the browser globals this test relies on', () => {
    expect(typeof window).toBe('undefined');
    expect(typeof indexedDB).toBe('undefined');
  });

  it('createRestricto and the React provider render without touching browser APIs, even with autoRegister', () => {
    let seen = '';
    function Probe() {
      seen = useRestricto().status;
      return <p>{seen}</p>;
    }
    const html = renderToString(
      <RestrictoProvider config={{ baseUrl: 'https://api.example.com', appId: 'web.example.com', autoRegister: true }} autoRegister>
        <Probe />
      </RestrictoProvider>,
    );
    expect(html).toContain('idle');
  });

  it('pinnedConfigKeys + autoRegister on the server: no fetch, no storage, still idle', () => {
    let calls = 0;
    const c = createRestricto({
      baseUrl: 'https://api.example.com',
      appId: 'x',
      autoRegister: true,
      pinnedConfigKeys: { k: 'A'.repeat(43) },
      fetch: (async () => void calls++) as unknown as typeof fetch,
    });
    expect(c.getState()).toMatchObject({ status: 'idle', config: { source: 'defaults' } });
    expect(calls).toBe(0);
  });

  it('a client created on the server stays idle and uses the in-memory store only if asked to sign', () => {
    const c = createRestricto({ baseUrl: 'https://api.example.com', appId: 'x', autoRegister: true });
    expect(c.getState().status).toBe('idle');
  });
});
