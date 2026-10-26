import { createRestricto } from '@funsol/restricto-web';
import type { ConfigStatus, RestrictoClient, RestrictoConfig, RestrictoError, RestrictoState, RestrictoStatus, UpgradeInfo } from '@funsol/restricto-web';
import { createContext, useContext, useEffect, useMemo, useState, useSyncExternalStore, type ReactNode } from 'react';

const Context = createContext<RestrictoClient | null>(null);

/** What the server render and the first client render both see, so hydration matches. */
const SERVER_STATE: RestrictoState = {
  status: 'idle',
  deviceId: null,
  trustLevel: null,
  attestedUntil: null,
  error: null,
  config: { source: 'none', seq: null, exp: null, relaxed: false, lastError: null },
  upgrade: null,
};

export interface RestrictoProviderProps {
  /** Pass an existing client, or `config` to have the provider create one (created once; keep `config` stable). */
  client?: RestrictoClient;
  config?: RestrictoConfig;
  /** Register on mount instead of lazily on the first signed call. */
  autoRegister?: boolean;
  children?: ReactNode;
}

export function RestrictoProvider({ client, config, autoRegister, children }: RestrictoProviderProps) {
  const [active] = useState<RestrictoClient>(() => {
    if (client) return client;
    if (!config) throw new Error('<RestrictoProvider> needs a `client` or a `config`.');
    return createRestricto(config);
  });
  useEffect(() => {
    // effects never run during SSR, so nothing registers on the server
    if (autoRegister) active.ready().catch(() => undefined);
  }, [active, autoRegister]);
  return <Context.Provider value={active}>{children}</Context.Provider>;
}

export interface UseRestricto {
  status: RestrictoStatus;
  deviceId: string | null;
  trustLevel: number | null;
  error: RestrictoError | null;
  /** Signed config document state (needs `pinnedConfigKeys`). */
  config: ConfigStatus;
  /** A newer SDK is wanted; `mode: 'hard'` means signed calls now fail with `upgrade_required`. */
  upgrade: UpgradeInfo | null;
  /** Signs requests to the configured origin; registers lazily. */
  fetch: RestrictoClient['fetch'];
  /** Starts registration if needed and resolves when the device is ready (a function, so rendering never triggers work). */
  ready: () => Promise<RestrictoState>;
  client: RestrictoClient;
}

export function useRestricto(): UseRestricto {
  const client = useContext(Context);
  if (!client) throw new Error('useRestricto() must be used inside <RestrictoProvider>.');
  const state = useSyncExternalStore(client.subscribe, client.getState, () => SERVER_STATE);
  return useMemo(
    () => ({
      status: state.status,
      deviceId: state.deviceId,
      trustLevel: state.trustLevel,
      error: state.error,
      config: state.config,
      upgrade: state.upgrade,
      fetch: client.fetch,
      ready: () => client.ready(),
      client,
    }),
    [state, client],
  );
}

/** Just the signing fetch, for components that do not care about registration state. */
export function useRestrictoFetch(): RestrictoClient['fetch'] {
  const client = useContext(Context);
  if (!client) throw new Error('useRestrictoFetch() must be used inside <RestrictoProvider>.');
  return client.fetch;
}
