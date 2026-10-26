// @vitest-environment happy-dom
import { mount, flushPromises } from '@vue/test-utils';
import { describe, expect, it } from 'vitest';
import { defineComponent, h } from 'vue';
import { createMemoryKeyStore, createRestricto, type RestrictoConfig } from '../src';
import { createRestrictoPlugin, useRestricto } from '../src/vue';
import { FakeRestricto } from './helpers/fake-server';

const BASE = 'https://api.example.com';

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
    registerCooldownMs: 0,
  };
  return { server, config };
}

const Probe = defineComponent({
  setup() {
    const r = useRestricto();
    return { r };
  },
  render() {
    return h('div', [
      h('span', { class: 'status' }, this.r.status.value),
      h('span', { class: 'device' }, this.r.deviceId.value ?? '-'),
      h('span', { class: 'err' }, this.r.error.value?.code ?? ''),
      h('span', { class: 'cfg' }, this.r.config.value.source),
      h('span', { class: 'up' }, this.r.upgrade.value ? `${this.r.upgrade.value.mode}:${this.r.upgrade.value.reason}` : '-'),
    ]);
  },
});

describe('Vue plugin', () => {
  it('installs $restricto and useRestricto() returns reactive refs that follow registration', async () => {
    const { server, config } = setup();
    const wrapper = mount(Probe, { global: { plugins: [createRestrictoPlugin(config)] } });
    expect(wrapper.find('.status').text()).toBe('idle');
    const client = wrapper.vm.$.appContext.config.globalProperties.$restricto;
    expect(typeof client.fetch).toBe('function');
    const res = await client.fetch(`${BASE}/api/hello/`);
    expect(res.status).toBe(200);
    await flushPromises();
    expect(wrapper.find('.status').text()).toBe('ready');
    expect(wrapper.find('.device').text()).toMatch(/^rd_/);
    expect(server.counts.register).toBe(1);
  });

  it('$restricto is usable from templates/options API and useRestricto().ready() registers', async () => {
    const { server, config } = setup();
    const Opt = defineComponent({
      template: '<i>{{ typeof $restricto.fetch }}</i>',
      async mounted() {
        await this.$restricto.ready();
      },
    });
    const wrapper = mount(Opt, { global: { plugins: [createRestrictoPlugin(config)] } });
    await flushPromises();
    await new Promise((r) => setTimeout(r, 20));
    expect(wrapper.text()).toBe('function');
    expect(server.counts.register).toBe(1);

    const Ready = defineComponent({
      setup() {
        const r = useRestricto();
        return { r };
      },
      render() {
        return h('button', { onClick: () => void this.r.ready() }, this.r.status.value);
      },
    });
    const { server: s2, config: c2 } = setup();
    const w2 = mount(Ready, { global: { plugins: [createRestrictoPlugin(c2)] } });
    await w2.find('button').trigger('click');
    await new Promise((r) => setTimeout(r, 30));
    await flushPromises();
    expect(w2.text()).toBe('ready');
    expect(s2.counts.register).toBe(1);
  });

  it('accepts a prebuilt client and surfaces registration errors as refs', async () => {
    const { server, config } = setup();
    server.banRegistrations = true;
    const client = createRestricto(config);
    const wrapper = mount(Probe, { global: { plugins: [createRestrictoPlugin(client)] } });
    await expect(client.ready()).rejects.toMatchObject({ code: 'register_failed' });
    await flushPromises();
    expect(wrapper.find('.status').text()).toBe('error');
    expect(wrapper.find('.err').text()).toBe('register_failed');
  });

  it('useRestricto() without the plugin throws a helpful error', () => {
    expect(() => mount(Probe)).toThrow(/createRestrictoPlugin/);
  });
});

describe('config + upgrade in the Vue composable', () => {
  it('exposes the signed config status and a hard upgrade requirement reactively', async () => {
    const { server, config } = setup();
    server.publishConfig({ extra: { min_sdk: { web: '9.0.0' } } });
    const wrapper = mount(Probe, { global: { plugins: [createRestrictoPlugin({ ...config, pinnedResponseKeys: undefined, pinnedConfigKeys: server.pinnedConfigKeys })] } });
    expect(wrapper.find('.cfg').text()).toBe('defaults');
    const client = wrapper.vm.$.appContext.config.globalProperties.$restricto;
    await expect(client.fetch(`${BASE}/api/x/`)).rejects.toMatchObject({ code: 'upgrade_required' });
    await flushPromises();
    expect(wrapper.find('.cfg').text()).toBe('valid');
    expect(wrapper.find('.up').text()).toBe('hard:min_sdk');
  });
});
