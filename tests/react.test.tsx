// @vitest-environment happy-dom
import { act, cleanup, render, screen, waitFor } from '@testing-library/react';
import { renderToString } from 'react-dom/server';
import { afterEach, describe, expect, it } from 'vitest';
import { createMemoryKeyStore, createRestricto, type RestrictoConfig } from '../src';
import { RestrictoProvider, useRestricto, useRestrictoFetch } from '../src/react';
import { FakeRestricto } from './helpers/fake-server';

const BASE = 'https://api.example.com';
afterEach(cleanup);

function setup() {
  const server = new FakeRestricto();
  const config: RestrictoConfig = {
    baseUrl: BASE,
    appId: server.appId,
    keyStore: createMemoryKeyStore(),
    fetch: server.fetch as typeof fetch,
    pow: { useWorker: false },
    useWebLocks: false,
    pinnedResponseKeys: { k1: server.publicKeyB64 },
  };
  return { server, config };
}

function Status() {
  const r = useRestricto();
  return (
    <div>
      <span data-testid="status">{r.status}</span>
      <span data-testid="device">{r.deviceId ?? '-'}</span>
      <span data-testid="trust">{String(r.trustLevel)}</span>
    </div>
  );
}

describe('<RestrictoProvider>', () => {
  it('renders children immediately and stays idle until used (lazy registration)', async () => {
    const { server, config } = setup();
    render(
      <RestrictoProvider config={config}>
        <Status />
      </RestrictoProvider>,
    );
    expect(screen.getByTestId('status').textContent).toBe('idle');
    await new Promise((r) => setTimeout(r, 30));
    expect(server.counts.register).toBe(0);
  });

  it('autoRegister registers on mount and the hook state follows idle -> registering -> ready', async () => {
    const { server, config } = setup();
    render(
      <RestrictoProvider config={config} autoRegister>
        <Status />
      </RestrictoProvider>,
    );
    await waitFor(() => expect(screen.getByTestId('status').textContent).toBe('ready'));
    expect(screen.getByTestId('device').textContent).toMatch(/^rd_/);
    expect(screen.getByTestId('trust').textContent).toBe('1');
    expect(server.counts.register).toBe(1);
  });

  it('useRestrictoFetch signs; ready() resolves; error state surfaces a failed registration', async () => {
    const { server, config } = setup();
    let doFetch: ReturnType<typeof useRestrictoFetch> | undefined;
    let ready: (() => Promise<unknown>) | undefined;
    function Probe() {
      doFetch = useRestrictoFetch();
      ready = useRestricto().ready;
      return <Status />;
    }
    render(
      <RestrictoProvider config={config}>
        <Probe />
      </RestrictoProvider>,
    );
    let res: Response | undefined;
    await act(async () => {
      res = await doFetch!(`${BASE}/api/hello/`);
    });
    expect(res!.status).toBe(200);
    expect(screen.getByTestId('status').textContent).toBe('ready');
    await act(async () => void (await ready!()));

    // new provider, registration refused
    cleanup();
    server.banRegistrations = true;
    const bad = setup();
    bad.server.banRegistrations = true;
    function Err() {
      const r = useRestricto();
      return <span data-testid="err">{r.status}:{r.error?.code ?? ''}</span>;
    }
    render(
      <RestrictoProvider config={{ ...bad.config, registerCooldownMs: 0 }} autoRegister>
        <Err />
      </RestrictoProvider>,
    );
    await waitFor(() => expect(screen.getByTestId('err').textContent).toBe('error:register_failed'));
  });

  it('accepts a prebuilt client', async () => {
    const { config } = setup();
    const client = createRestricto(config);
    render(
      <RestrictoProvider client={client} autoRegister>
        <Status />
      </RestrictoProvider>,
    );
    await waitFor(() => expect(screen.getByTestId('status').textContent).toBe('ready'));
    expect(client.getState().status).toBe('ready');
  });

  it('does not crash on the server: renders children, idle state, no registration, no window access', () => {
    const { server, config } = setup();
    const html = renderToString(
      <RestrictoProvider config={config} autoRegister>
        <Status />
      </RestrictoProvider>,
    );
    expect(html).toContain('idle');
    expect(server.counts.register).toBe(0);
  });

  it('hooks outside the provider give a clear error', () => {
    const spy = console.error;
    console.error = () => undefined;
    try {
      expect(() => render(<Status />)).toThrow(/RestrictoProvider/);
    } finally {
      console.error = spy;
    }
  });
});
