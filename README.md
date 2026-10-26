# @funsol/restricto-web

Browser SDK for **Restricto-Sig v1** (wire protocol: `docs/PROTOCOL_V1_FINAL.md` in the Restricto repository). It gives a web
page its own device identity (a non-extractable WebCrypto key), registers it with your Restricto deployment (challenge, key-bound
proof of work, optional Turnstile), signs every request to your API with a `Restricto-Signature` header and verifies the signed
responses. Server-driven behaviour (response keys, PoW limits, renewal timing, retry budgets, forced upgrades) comes from a
**signed config document** that you pin once.

It talks only to *your* Restricto deployment, the Django package (`restricto`) or the Laravel package (`funsol/restricto-laravel`).
Both speak the same wire protocol. It never talks to the Funsol control plane.

* ESM + CJS + types, zero runtime dependencies in the core (about 12 KB min+gzip, see "Size"). The proof of work, the config
  document parser and the `@noble/curves` Ed25519 fallback (browsers without native WebCrypto Ed25519) are lazily imported.
* `/react` (React >= 18) and `/vue` (Vue >= 3.3) subpath exports; both frameworks are optional peers.
* Works in Vite, Next.js and Nuxt (client side), and in a plain `<script>`.
* Your own `Authorization` header is **not** touched (the signature lives in `Restricto-Signature`).

```
npm i @funsol/restricto-web
```

## Quickstart

**Plain JavaScript**

```js
import { createRestricto } from '@funsol/restricto-web';

const restricto = createRestricto({
  baseUrl: 'https://api.example.com',   // origin of the Restricto deployment; only this origin is ever signed
  appId: 'web.example.com',             // X-APP-ID: the Application's package name in the Restricto admin
  // RECOMMENDED: pin the config signing key(s) (printed by `restricto_config sign` / the Go-live page)
  pinnedConfigKeys: { 'cfg-24f6ed6a': 'BASE64URL_ED25519_CONFIG_PUBLIC_KEY' },
  onUpgradeRequired: (info) => showUpdateBanner(info), // optional, see "Config document"
});

const res = await restricto.fetch('https://api.example.com/api/things/', {
  method: 'POST',
  headers: { Authorization: `Bearer ${appToken}` },   // yours, passed through untouched
  body: JSON.stringify({ a: 1 }),
});
```

`restricto.fetch` is a drop-in for `window.fetch`. The first call fetches the config document and registers the device (the
proof of work takes about 100 ms to a second at the default 16 bits); concurrent calls and other tabs share that one registration.

**React**

```tsx
import { RestrictoProvider, useRestricto } from '@funsol/restricto-web/react';

<RestrictoProvider config={{ baseUrl, appId, pinnedConfigKeys }} autoRegister>
  <App />
</RestrictoProvider>;

function Things() {
  const { fetch, status, deviceId, trustLevel, error, config, upgrade, ready } = useRestricto();
  // status: idle | registering | ready | error;  config.source: none | defaults | valid | expired;
  // upgrade: null | { mode: 'soft' | 'hard', reason, url }  (hard: signed calls now fail with `upgrade_required`)
}
```

**Vue 3**

```ts
import { createRestrictoPlugin, useRestricto } from '@funsol/restricto-web/vue';

app.use(createRestrictoPlugin({ baseUrl, appId, pinnedConfigKeys }));
// in a component: const { fetch, status, deviceId, trustLevel, error, config, upgrade, ready } = useRestricto(); // refs
// options API / templates: this.$restricto.fetch(...)
```

Next.js: put the provider in a `'use client'` component. Nuxt: register the plugin in a `*.client.ts` plugin. Nothing runs during
SSR (no `window`/`indexedDB` access, effects never run, the first render is `idle`).

**Script tag** (no bundler; everything including the Ed25519 fallback is bundled, about 31 KB gzip). Nothing is attached to
`window` unless the tag opts in, and you choose the name (a global signing factory is a convenience for injected scripts):

```html
<script src="/restricto.global.js" data-restricto-global="MyAppRestricto"></script>
<script>const r = MyAppRestricto.createRestricto({ baseUrl: '...', appId: '...', pinnedConfigKeys: { /* ... */ } });</script>
```

Prefer the npm package and a bundler where you can.

## Configuration

| Option | Default | Notes |
|---|---|---|
| `baseUrl` | required | Origin of the deployment. Requests to any other origin pass through **untouched** (no signature, no `X-APP-ID`). |
| `appId` | required | Sent as `X-APP-ID`. Also namespaces the stored key (`appId` + origin). |
| `pinnedConfigKeys` | none | **Recommended.** `{ kid: base64url raw Ed25519 public key }`, any may verify. Enables the signed config document and takes the response keys from it. |
| `pinnedResponseKeys` | none | `{ kid: base64url Ed25519 public key }`: authoritative in addition to the config's keys (or on their own, without config). |
| `verifyResponses` | `'strict'` | `'strict'` rejects missing/bad response signatures, `'warn'` calls `onWarning`, `'off'` skips. A valid signed config can relax `strict` to `warn` (kill switch). |
| `getTurnstileToken` | none | `() => Promise<string>`; needed if the server has `TURNSTILE_SECRET`. |
| `restrictoPath` | `/restricto` | Where the routes are mounted. |
| `autoRegister` | `false` | Register at creation (browser only). Otherwise lazily on first signed call / `ready()`. |
| `refreshMarginSeconds` | config `renew.before_s` (1 day) | Renew this long before `attested_until` (capped to a quarter of the validity); `autoRefresh: false` disables the timer. |
| `registerCooldownMs` | config `renew.backoff` ladder (5 s, 30 s, 5 min, 1 h) | After a failed registration calls fail fast instead of redoing the proof of work. A registration that is "successful" but already expired waits at least 60 s. |
| `configTimeoutMs` | 8000 | Timeout of the config document fetch (the first call then proceeds with what it has). |
| `powBudgetMs` | 60000 | Wall-clock budget for the proof of work. |
| `pow` / `onPowProgress` | worker on | `pow: { useWorker: false }` forces the main thread. |
| `redirect` | `'manual'` | `'manual'` or `'error'`; signed calls never follow redirects. |
| `transientBackoffMs` | 400 | Base delay of the bounded retry of unsigned answers to idempotent calls. |
| `signedRenewal` | `true` | Try a signed `renew:true` before re-registering the key directly. |
| `keyStore` | IndexedDB, memory fallback | Implement `{ get, put, delete }` (+ optional `getConfig`, `putConfig` for the anti-rollback state). |
| `fetch` | global `fetch` | Underlying transport (tests, custom stacks). |
| `appVersion` | `web-1.0.0` | Sent at registration. |
| `maxBodyBytes` | 5 MiB | Matches the server limit; larger bodies are refused before sending. |
| `onRequest(headers, info)` | none | Hook run before each signed attempt (extension point, see below). |
| `onUpgradeRequired(info)` / `onWarning(msg)` | `console.warn` | Events. |

Other APIs: `sign({ method, url, body })` for custom HTTP stacks (returns `headers` and `verify(response)`);
`recover(response, signed)` (true = a signed rejection was handled, re-sign and resend ONCE; it only acts on a verified reply for
that very request); `ready()`, `refreshConfig()`, `getState()` (`status`, `deviceId`, `trustLevel`, `attestedUntil`, `error`,
`config`, `upgrade`), `subscribe()`, `isVerified(response)`, `reset()`, `close()` (both abort an in-flight registration).

**axios** (an adapter, because interceptors run before the body is serialised and the signature must cover the exact bytes sent):

```js
import { restrictoAxios } from '@funsol/restricto-web';
const http = axios.create({ baseURL: 'https://api.example.com', adapter: restrictoAxios(restricto) });
```

## Protocol summary (what the SDK sends and believes)

* **Request**: `Restricto-Signature: v=1,id=<device>,ts=<s>,nonce=<22 chars>,bh=<b64url sha256 of the body>,sig=<ECDSA P-256 raw r||s>` and
  `X-APP-ID`. The signed canonical string includes the lower-cased host (`:port` only when not the default), the canonical path
  (percent-decoded to bytes, re-encoded except `A-Za-z0-9-._~` and `/`) and the canonical query (pairs decoded, re-encoded, sorted;
  the raw query string is not signed, so re-ordering proxies are harmless). Bodies: string, `URLSearchParams`, `Blob`,
  `ArrayBuffer`/views, `Request` objects. `FormData` and streams are refused (sign uploads via presigned URLs).
* **Response**: `Restricto-Response-Signature` (one or more fields). The reply is accepted when ANY listed signature with a known `kid`
  and `alg` (Ed25519) verifies; unknown algorithms and kids are ignored. The signature covers status, the request's nonce and device,
  `ts` (within +-300 s of the server-corrected clock), the SHA-256 of the body (empty for HEAD/204/304) and the `Content-Type`,
  `Location` and `Retry-After` values. A reply that was redirected or came from another origin is never trusted.
* **Registration**: `POST /restricto/device/challenge/` (announces `pow`, `sig_versions`, `cfg_seq`), then proof of work **bound to the
  key** (`SHA-256(challenge ":" hex(SHA-256(SPKI)) ":" n)` with the announced number of leading zero bits, never more than 26 and
  never more than the signed config's `max_bits`, gives up after `powBudgetMs`, aborts on `close()`/`reset()`), then
  `POST /restricto/device/register/` with `caps: { sig: [1], cfg: <seq held> }` and `renew`.
* **Renewal**: a *signed* register request with `renew: true` using the existing key. A server that does not offer web renewals
  answers with a signed refusal; the SDK then re-registers the same key directly and remembers that (the Python reference
  currently does this for web: renewal is defined for Android/iOS there).
* **Unsigned answers are never acted upon.** If a signed request gets an unsigned (or unverifiable) reply - a proxy, a captive
  portal, an attacker - the SDK treats it as a network error: idempotent calls are retried a bounded number of times with backoff,
  then `RestrictoError('response_unverified', { unsigned: true })` is thrown. It never wipes the key, never re-registers, never
  adopts a clock from it. Only a *verified* body's `action` matters:

  | `action` | SDK behaviour |
  |---|---|
  | `resync_clock` | adopt the **signed** `server_time` (works even if our clock is >300 s off), re-sign, retry once |
  | `reregister` | renew the same key (`renew:true`, else plain re-registration), retry (budget `retry.unknown_device`) |
  | `wipe` | discard the key, create and register a new one, retry; a second tab that also got `wipe` reuses the first tab's new key |
  | `backoff` | a short `Retry-After` is waited out once for idempotent calls; otherwise the response goes to your code |
  | `upgrade` | **advisory**: `state.upgrade = { mode: 'soft' }` + `onUpgradeRequired`; calls keep working |
  | `none` / unknown | returned to your code. Unknown actions/codes are mapped by HTTP class and `Retry-After`; the one code the SDK looks at is a replayed nonce (458066), retried with a new nonce (budget `retry.replay`) |

## Config document (spec section 6)

`pinnedConfigKeys` makes the SDK fetch `GET /restricto/config/` at first use and whenever a challenge/register reply reports a
higher `cfg_seq` (or an unknown response `kid` shows up, or the document nears its expiry). The document
`{ payload, kid, sig }` is produced offline (`restricto_config sign --key config.pem` / `restricto:config:sign`) and merely served.
The SDK:

* verifies `sig` over `RESTRICTO-CFG-V1\n<appId>\n<payload bytes>` with a pinned key (any listed key may verify), requires
  `app` to equal its `appId`, `seq` >= the stored one (**anti-rollback, persisted** next to the key, survives `reset()`), and
  `exp` in the future; an expired document is not adopted while a good one is held, and with none it still supplies its
  key set and limits but its `relax` flags are dead. It never falls back to "no security": without any document and without
  `pinnedResponseKeys` the SDK fails closed (`response_unverified`);
* clamps every value to bounds compiled into the SDK (PoW <= 26 bits, skew 30-300 s, renewal margin 5 min-14 days, retry budgets
  0-3/0-3/0-5, backoff 1 s-1 day) and ignores unknown fields;
* uses `resp_keys` (states `active`/`next`/`retired`, with `nbf`/`naf`) as the response key set, so response keys rotate
  (`next` -> `active`) without an SDK release;
* applies `relax.verify_responses=false` (strict becomes warn) only while the document is valid;
* **hard upgrade** (`min_sdk.web` above this SDK, `upgrade.mode: "hard"`, or no common signature version) comes ONLY from the signed
  document: `state.upgrade.mode === 'hard'`, `onUpgradeRequired` fires, and signed calls fail with `RestrictoError('upgrade_required')`.
  Soft upgrades only notify. `min_sdk` compares `major.minor.patch` (a `-rc.1` suffix is ignored).

Without `pinnedConfigKeys` the SDK works with compiled-in defaults and fetches the response keys from `GET /restricto/keys/` on
first use (trust on first use, **weaker**: whoever controls the first response of a page load can substitute keys). Pin.

## Server setup: CORS

When the page and the API are on different origins the API must allow and expose these:

```
Access-Control-Allow-Origin:   https://app.example.com
Access-Control-Allow-Headers:  Restricto-Signature, X-APP-ID, Content-Type
Access-Control-Expose-Headers: Restricto-Response-Signature, Retry-After
```

(add your own `Authorization` to the allow list if your API uses it). The same origin must be on the Application's allowed-origins
list (the `Origin` header is checked at registration). If the expose list is missing the signature header is invisible to the page
and strict mode reports "response carries no Restricto signature (... must expose Restricto-Response-Signature ...)".

* **Django**: `django-cors-headers` with `CORS_ALLOW_HEADERS = [*default_headers, "restricto-signature", "x-app-id"]`,
  `CORS_EXPOSE_HEADERS = ["Restricto-Response-Signature", "Retry-After"]`. Behind a proxy/CDN set `RESTRICTO["PUBLIC_HOST"]` so the
  host line the browser signs matches.
* **Laravel**: `php artisan restricto:cors` prints the config.
* CSP: `connect-src` for the API, and `worker-src blob:` if you set a CSP (otherwise the main-thread solver is used, slower but works).

## Cloudflare Turnstile

The SDK never loads Cloudflare scripts. If the server has `TURNSTILE_SECRET`, pass a callback; this one uses the
non-interactive/managed widget and removes it afterwards:

```js
function turnstileToken(siteKey) {
  return new Promise((resolve, reject) => {
    const run = () => {
      const box = document.createElement('div');
      document.body.appendChild(box);
      window.turnstile.render(box, {
        sitekey: siteKey,
        appearance: 'interaction-only',
        callback: (token) => { window.turnstile.remove(box); box.remove(); resolve(token); },
        'error-callback': () => reject(new Error('turnstile failed')),
      });
    };
    if (window.turnstile) return run();
    const s = document.createElement('script');
    s.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
    s.async = true; s.onload = run; s.onerror = () => reject(new Error('turnstile blocked'));
    document.head.appendChild(s);
  });
}
createRestricto({ /* ... */, getTurnstileToken: () => turnstileToken('0x4AAAA...') });
```

The callback runs for every registration and renewal (about every 3 days), and runs *before* the challenge is requested because
challenges expire in 2 minutes.

## Security notes: what the web can and cannot prove

* A browser cannot be hardware-attested. Registration proves **cost** (key-bound proof of work), optionally **humanness**
  (Turnstile) and a **nuisance-level origin** check. The server caps web keys at **trust level 1**; budget and automation policies
  should treat web as your weakest client. Web registration is only for web-only Applications.
* **Pin `pinnedConfigKeys`.** It is the one pin that makes response keys, rotation and forced upgrades trustworthy without an SDK
  release; without it a MITM on the first load can substitute the response keys.
* The key is **non-extractable**: script, extensions with page access and XSS cannot copy it out. But code running in your page
  *can still use* it to sign (and verify) while the page is compromised - a signing oracle - for as long as the page is open. Damage
  is bounded to that origin and browser and the server's per-device limits; fix the XSS and revoke the device. The `<script>` build
  therefore attaches no global unless you opt in with `data-restricto-global`; prefer the bundled package.
* Clearing site data deletes the key; the next load registers a new device (and pays the proof of work again).
* Signing prevents replay and tampering in transit and ties requests to one key. It does not stop a user driving your site's own
  JavaScript, or a script that registers many keys slowly (proof of work, Turnstile and per-network registration limits do that).
* **Path canonicalisation**: `%2F` and `/` are the same canonical path (`/a%2Fb` signs as `/a/b`), `+` in a path is a literal plus
  (`%2B`). Do not rely on `%2F` vs `/` to select different resources on the server. Known interop issue of the Python reference on **WSGI**
  (Django): it rebuilds the path from `PATH_INFO`, which Django has already turned into decoded text, so a valid-UTF-8 non-ASCII
  path (`/caf%C3%A9/`) is hashed as latin-1 (`%E9`) and rejected with 458047 (ASGI deployments use the raw path and agree with the
  vectors; ASCII paths are unaffected). `scripts/live-check.mjs` reports it.
* **No streaming**: request bodies must be bytes you can hash (no `ReadableStream`, no `FormData`); responses are buffered
  (cloned) for verification, so SSE / `text/event-stream` and very large downloads are not supported on signed calls - serve them
  from another origin (not signed) or use `verifyResponses: 'off'` for a dedicated client.
* **Redirects** are never followed on signed calls (`redirect: 'manual'`); a reply that was redirected or came from another origin
  is not trusted, never acted upon, and in `strict` mode rejected (`RestrictoError('redirect')` for an opaque redirect).
* **Extension point for step-up (WebAuthn)**: use `onRequest(headers, { method, url })` to add an assertion header to selected
  requests. The server side is separate.

## Live check

`scripts/live-check.mjs` (not part of `npm test`) exercises register -> signed GET/POST/HEAD -> verified responses against a real
deployment:

```
npm run build
node scripts/live-check.mjs https://api.example.com web.example.com https://app.example.com [--config-key kid=BASE64URL_PUB]
```

## Size

`npm run size` (esbuild, minified, code-split): the always-loaded core is about 12 KB gzip; the proof of work (about 2.3 KB) and the
config document parser (about 1.2 KB) are lazy chunks, and `@noble/curves` is a further lazy import. The React and Vue entries add
about 0.6 KB each.

## Development

```
npm test          # vitest: protocol vectors, PoW, fake server integration, config document, IndexedDB, React, Vue, SSR
npm run typecheck
npm run build     # tsup: ESM + CJS + .d.ts for ".", "./react", "./vue", plus dist/restricto.global.js
npm run size
```

`tests/vectors.test.ts` runs every group of `docs/protocol_vectors.json` (canonical path/query/host, header parse, request
signature incl. negatives, response signature, config document, PoW, binding). `tests/helpers/fake-server.ts` is an independent
implementation of the server side (own header parser, byte-oriented canonicalisation, signed rejections, config signing, key
rotation) written from the protocol document.
