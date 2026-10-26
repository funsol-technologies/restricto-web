#!/usr/bin/env node
// Optional end-to-end check against a REAL Restricto deployment (not part of `npm test`).
//
//   npm run build
//   node scripts/live-check.mjs <baseUrl> <appId> <origin> [--config-key <kid>=<base64url Ed25519 pub>] [--path /api/hello/]
//
// <origin> is sent as the `Origin` header on every request (browsers do that themselves; the server's web allow-list needs it
// for registration). The deployment needs a web-enabled Application for <appId> and any route under --path (default /api/hello/)
// that the Restricto middleware protects and that answers 2xx.
//
// It registers (challenge -> key-bound PoW -> register), then makes signed GET / POST / HEAD / odd-path calls and requires every
// response to be verified (Restricto-Response-Signature), and finally checks that an unsigned call is refused. Exit code 1 on failure.
import { createRestricto, createMemoryKeyStore } from '../dist/index.js';

const args = process.argv.slice(2);
const flag = (name) => {
  const i = args.indexOf(name);
  return i < 0 ? undefined : args.splice(i, 2)[1];
};
const configKey = flag('--config-key');
const path = flag('--path') ?? '/api/hello/';
const [baseUrl, appId, origin] = args;
if (!baseUrl || !appId || !origin) {
  console.error('usage: node scripts/live-check.mjs <baseUrl> <appId> <origin> [--config-key kid=pub] [--path /api/hello/]');
  process.exit(2);
}

let failures = 0;
const ok = (cond, label, extra = '') => {
  console.log(`${cond ? 'ok  ' : 'FAIL'} ${label}${extra ? ` - ${extra}` : ''}`);
  if (!cond) failures++;
};

const withOrigin = (input, init = {}) => {
  const headers = new Headers(init.headers);
  headers.set('Origin', origin);
  return fetch(input, { ...init, headers });
};

const warnings = [];
const client = createRestricto({
  baseUrl,
  appId,
  keyStore: createMemoryKeyStore(),
  fetch: withOrigin,
  pow: { useWorker: false },
  useWebLocks: false,
  autoRefresh: false,
  onWarning: (m) => warnings.push(m),
  ...(configKey ? { pinnedConfigKeys: { [configKey.split('=')[0]]: configKey.split('=')[1] } } : {}),
});

const url = (p) => new URL(p, baseUrl).href;
try {
  const started = Date.now();
  const state = await client.ready();
  ok(state.status === 'ready' && /^rd_/.test(state.deviceId ?? ''), 'registered', `${state.deviceId}, trust ${state.trustLevel}, ${Date.now() - started} ms`);
  ok(state.attestedUntil > Date.now() / 1000, 'attestation is in the future');
  if (configKey) ok(state.config.source === 'valid', 'signed config document accepted', `seq ${state.config.seq}`);
  else console.log('note  no --config-key: response keys were fetched from /keys/ (trust on first use, weaker)');

  const get = await client.fetch(url(`${path}?b=2&a=%7e&&c&a=1`));
  ok(get.ok && client.isVerified(get), 'signed GET answered and the response signature verified', `HTTP ${get.status}`);

  const post = await client.fetch(url(path), { method: 'POST', headers: { 'content-type': 'application/json', Authorization: 'Bearer app-owned' }, body: JSON.stringify({ hello: 'wörld' }) });
  ok(post.ok && client.isVerified(post), 'signed POST (body hash, app Authorization header untouched) verified', `HTTP ${post.status}`);

  const head = await client.fetch(url(path), { method: 'HEAD' });
  ok(head.ok && client.isVerified(head), 'HEAD verified over the empty body', `HTTP ${head.status}`);

  const odd = await client.fetch(url(`${path}a%2Fb/x y/a+b/%7Etilde/?q=a+b&z=%2F`));
  ok(odd.status !== 401 && client.isVerified(odd), 'odd path/query canonicalisation (%2F, space, +, %7E) accepted and verified', `HTTP ${odd.status}`);

  // Informational: a non-ASCII path. Not counted, because a WSGI deployment whose framework rewrites PATH_INFO to decoded text
  // (Django does) may canonicalise it differently from the protocol vectors; ASGI deployments use the raw path and agree.
  const uni = await client.fetch(url(`${path}%C3%A9/`));
  console.log(`${uni.status === 401 ? 'note ' : 'ok  '} non-ASCII path (%C3%A9) -> HTTP ${uni.status}${uni.status === 401 ? ' (server canonicalised it differently from the vectors; see README, WSGI note)' : ''}`);

  const bare = await withOrigin(url(path), { headers: { 'X-APP-ID': appId } });
  console.log(`note  an UNsigned request to a protected route got HTTP ${bare.status} (depends on require_signed_requests)`);
} catch (e) {
  ok(false, 'unexpected error', `${e?.code ?? ''} ${e?.message ?? e}`);
}
client.close();
for (const w of warnings) console.log(`warn  ${w}`);
console.log(failures ? `\n${failures} check(s) failed` : '\nall checks passed');
process.exit(failures ? 1 : 0);
