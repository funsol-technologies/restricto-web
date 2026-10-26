import { createRestricto } from '@funsol/restricto-web';
import type { ConfigStatus, RestrictoClient, RestrictoConfig, RestrictoError, RestrictoState, RestrictoStatus, UpgradeInfo } from '@funsol/restricto-web';
import { computed, inject, shallowRef, type App, type ComputedRef, type InjectionKey, type ShallowRef } from 'vue';

interface Injected {
  client: RestrictoClient;
  state: ShallowRef<RestrictoState>;
}

const KEY: InjectionKey<Injected> = Symbol('restricto');

declare module 'vue' {
  interface ComponentCustomProperties {
    $restricto: RestrictoClient;
  }
}

const isClient = (v: RestrictoConfig | RestrictoClient): v is RestrictoClient => typeof (v as RestrictoClient).fetch === 'function' && !('baseUrl' in v);

/** `app.use(createRestrictoPlugin(config))` - or pass an existing client. Registers lazily unless `config.autoRegister`. */
export function createRestrictoPlugin(configOrClient: RestrictoConfig | RestrictoClient) {
  return {
    install(app: App): void {
      const client = isClient(configOrClient) ? configOrClient : createRestricto(configOrClient);
      const state = shallowRef(client.getState());
      client.subscribe((s) => {
        state.value = s;
      });
      app.provide(KEY, { client, state });
      app.config.globalProperties.$restricto = client;
    },
  };
}

export interface UseRestricto {
  status: ComputedRef<RestrictoStatus>;
  deviceId: ComputedRef<string | null>;
  trustLevel: ComputedRef<number | null>;
  error: ComputedRef<RestrictoError | null>;
  config: ComputedRef<ConfigStatus>;
  upgrade: ComputedRef<UpgradeInfo | null>;
  fetch: RestrictoClient['fetch'];
  ready: () => Promise<RestrictoState>;
  client: RestrictoClient;
}

export function useRestricto(): UseRestricto {
  const injected = inject(KEY, null);
  if (!injected) throw new Error('useRestricto(): install the plugin first - app.use(createRestrictoPlugin(config)).');
  const { client, state } = injected;
  return {
    status: computed(() => state.value.status),
    deviceId: computed(() => state.value.deviceId),
    trustLevel: computed(() => state.value.trustLevel),
    error: computed(() => state.value.error),
    config: computed(() => state.value.config),
    upgrade: computed(() => state.value.upgrade),
    fetch: client.fetch,
    ready: () => client.ready(),
    client,
  };
}
