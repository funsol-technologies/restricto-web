# @funsol/restricto-web

Browser SDK for **Restricto-Sig v1**. It gives a web page its own device identity (a non-extractable WebCrypto key),
registers it with your Restricto deployment (challenge, proof of work, optional Turnstile), then signs every request to
your API and verifies the signed responses.

It talks only to *your* Restricto deployment, the Django package (`restricto`) or the Laravel package
(`funsol/restricto-laravel`). Both speak the same wire protocol, so nothing in the SDK changes between them. It never talks
to the Funsol control plane.

* ESM + CJS + types, zero runtime dependencies in the core (about 9.5 KB min+gzip). `@noble/curves` is a lazily-imported
  Ed25519 fallback, loaded only in browsers without native WebCrypto Ed25519.
* `/react` (React >= 18) and `/vue` (Vue >= 3.3) subpath exports; both frameworks are optional peers.
* Works in Vite, Next.js and Nuxt (client side), and in a plain `<script>`.

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
  pinnedResponseKeys: { k1: 'PUBLIC_KEY_FROM_GO_LIVE_PAGE' }, // recommended, see "Response verification"
});

const res = await restricto.fetch('https://api.example.com/api/things/', { method: 'POST', body: JSON.stringify({ a: 1 }) });
```

`restricto.fetch` is a drop-in for `window.fetch`. The first call registers the device (about 100 ms to a second of
proof of work); concurrent calls and other tabs share that one registration.

**React**

```tsx
import { RestrictoProvider, useRestricto } from '@funsol/restricto-web/react';

<RestrictoProvider config={{ baseUrl, appId, pinnedResponseKeys }} autoRegister>
  <App />
</RestrictoProvider>;

function Things() {
  const { fetch, status, deviceId, trustLevel, error, ready } = useRestricto(); // status: idle | registering | ready | error
  // fetch(...) signs; `await ready()` waits for registration
}
```

**Vue 3**

```ts
import { createRestrictoPlugin, useRestricto } from '@funsol/restricto-web/vue';

app.use(createRestrictoPlugin({ baseUrl, appId, pinnedResponseKeys }));
// in a component: const { fetch, status, deviceId, trustLevel, error, ready } = useRestricto(); // status etc. are refs
// options API / templates: this.$restricto.fetch(...)
```

Next.js: put the provider in a `'use client'` component. Nuxt: register the plugin in a `*.client.ts` plugin. Nothing runs
during SSR (no `window`/`indexedDB` access, effects never run, the first render is `idle`).

**Script tag** (global build, no bundler; the Ed25519 fallback is bundled in, 25 KB gzip):

```html
<script src="/restricto.global.js"></script>
<script>const r = Restricto.createRestricto({ baseUrl: '...', appId: '...' });</script>
```

## Configuration

| Option | Default | Notes |
|---|---|---|
| `baseUrl` | required | Origin of the deployment. Requests to any other origin pass through **untouched** (no signature, no `X-APP-ID`). |
| `appId` | required | Sent as `X-APP-ID`. Also namespaces the stored key (`appId` + origin). |
| `pinnedResponseKeys` | none | `{ kid: base64url Ed25519 public key }`. Strongly recommended. |
| `verifyResponses` | `'strict'` | `'strict'` throws on a missing/bad response signature, `'warn'` calls `onWarning`, `'off'` skips. |
| `getTurnstileToken` | none | `() => Promise<string>`; needed if the server has `TURNSTILE_SECRET`. |
| `restrictoPath` | `/restricto` | Where the routes are mounted. |
| `autoRegister` | `false` | Register at creation (browser only). Otherwise lazily on first signed call / `ready()`. |
| `refreshMarginSeconds` | 6 h | Renew this long before `attested_until` (capped to a quarter of the validity); also schedules a timer (`autoRefresh: false` to disable). |
| `keyStore` | IndexedDB, memory fallback | Implement `{ get, put, delete }` to store elsewhere; `createMemoryKeyStore()` for tests. |
| `fetch` | global `fetch` | Underlying transport (tests, custom stacks). |
| `appVersion` | `web-1.0.0` | Sent at registration. |
| `maxBodyBytes` | 5 MiB | Matches the server limit; larger bodies are refused before sending. |
| `pow` / `onPowProgress` | worker on | `pow: { useWorker: false }` forces the main thread. `onPowProgress(attempts)` for a progress UI. |
| `onRequest(headers, info)` | none | Hook run before each signed attempt (extension point, see below). |
| `registerCooldownMs` | 5000 | After a failed registration, calls fail fast instead of redoing the proof of work. |

Other APIs: `restricto.sign({ method, url, body })` for custom HTTP stacks (returns `headers` plus `verify(response)`;
`restricto.recover(response, signed)` tells you whether a rejection was fixed and the request should be re-signed and sent
once); `restricto.ready()`, `getState()`, `subscribe()`, `isVerified(response)`, `reset()`, `close()`.

**axios** (no dependency on axios; an adapter, because interceptors run before the body is serialised and the signature
must cover the exact bytes sent):

```js
import { restrictoAxios } from '@funsol/restricto-web';
const http = axios.create({ baseURL: 'https://api.example.com', adapter: restrictoAxios(restricto) });
```

## What the SDK does for you

* **Key**: ECDSA P-256 generated with `extractable: false`, stored as a `CryptoKey` in IndexedDB. The private key is never
  readable by script, never in `localStorage`. Per-app namespace.
* **Registration**: `POST /restricto/device/challenge/`, then proof of work (`SHA-256(challenge + ":" + n)` with `pow_bits`
  leading zero bits, solved in an inline Web Worker created from a Blob, falling back to a time-sliced main-thread loop if
  workers or `blob:` are blocked), then `POST /restricto/device/register/` with `platform: "web"`. Across tabs a Web Lock
  makes sure only one registers; the others adopt the stored result.
* **Renewal**: the same key re-registers with a fresh challenge before `attested_until`, and on demand.
* **Signing**: `Authorization: Restricto-Sig v1 id=…,ts=…,nonce=…,sig=…` + `X-APP-ID`, canonical string exactly as in
  DEVICE_ATTESTATION.md §5. The path is percent-normalised the way the server does it; the query goes out byte-for-byte as
  sent. Bodies: string, `URLSearchParams`, `Blob`, `ArrayBuffer`/views, `Request` objects. `FormData` and streams are refused
  with a clear error (sign uploads via presigned URLs). The browser clock is not trusted: the offset to the server is
  tracked from `server_time` and `X-Restricto-Server-Time`.
* **Recoverable rejections** are retried exactly once, re-signed with a new nonce and timestamp:

  | Code | Action |
  |---|---|
  | 458052 clock skew | resync from `X-Restricto-Server-Time`, retry |
  | 458066 replay | retry with a new nonce |
  | 458033 unknown device / 458085 attestation expired | re-register the same key, retry |
  | 458071 revoked (403) | wipe the key, register a new one (fails if the device is banned), retry |

  Everything else (458047, 458010, rate limits, application errors) is returned as an ordinary response. These codes are
  produced by the server before your handler runs, so resending a POST after them cannot execute it twice.
* **Response verification**: Ed25519 over `RESTRICTO-RESP-V1 / status / request nonce / device id / ts / body hash`; the
  timestamp must be within ±5 minutes. WebCrypto Ed25519 where available, `@noble/curves` otherwise.

### Response verification: pins and trust on first use

With `pinnedResponseKeys` the SDK trusts only those keys (an unknown `kid` is a failure and nothing is fetched). Without
them it fetches `GET /restricto/keys/` on first use and caches it in memory: that is trust-on-first-use, so an attacker
who controls the very first response of a page load could substitute keys. Pin the public key shown on the Go-live page
(or `restricto_gen_response_key`) in your build. When you rotate, ship both `kid`s.

The Django server only signs responses to requests it identified. Rejections that happen *before* that (skew, unknown device,
bad signature) are unsigned. The SDK therefore returns an unsigned response with a Restricto `error_code` (458xxx) as is
(check `restricto.isVerified(res)`), but in `strict` mode any other unsigned response to a signed request, such as an HTML
403 from a proxy, throws `RestrictoError('response_unverified')`. Until the server has a response-signing key,
use `verifyResponses: 'warn'`.

## Server setup: CORS

When the page and the API are on different origins the API must allow and expose these (see `docs/WEB_AND_LARAVEL.md`):

```
Access-Control-Allow-Origin:   https://app.example.com
Access-Control-Allow-Headers:  Authorization, X-APP-ID, Content-Type
Access-Control-Expose-Headers: X-Restricto-Resp-Kid, X-Restricto-Resp-Ts, X-Restricto-Resp-Sig, X-Restricto-Server-Time, Retry-After
```

The same origin must be on the Application's allowed-origins list (the `Origin` header is checked at registration).
If the expose list is missing, the signature headers are invisible to the page and strict mode reports
"response carries no Restricto signature (… must expose X-Restricto-Resp-* …)".

* **Django**: `django-cors-headers` with `CORS_ALLOWED_ORIGINS`, `CORS_ALLOW_HEADERS = [*default_headers, "x-app-id"]`,
  `CORS_EXPOSE_HEADERS = ["X-Restricto-Resp-Kid", "X-Restricto-Resp-Ts", "X-Restricto-Resp-Sig", "X-Restricto-Server-Time", "Retry-After"]`.
* **Laravel**: `php artisan restricto:cors` prints the config.
* CSP: `connect-src` for the API, and `worker-src blob:` if you set a CSP (otherwise the main-thread solver is used, which is slower but works).

## Cloudflare Turnstile

The SDK never loads Cloudflare scripts. If the server has `TURNSTILE_SECRET`, pass a callback; this one uses
the non-interactive/managed widget and removes it afterwards:

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
createRestricto({ /* … */, getTurnstileToken: () => turnstileToken('0x4AAAA…') });
```

The callback runs for every registration and renewal (about every 3 days), and runs *before* the challenge is requested
because challenges expire in 2 minutes.

## Security notes: what the web can and cannot prove

* A browser cannot be hardware-attested. Registration proves **cost** (proof of work), optionally **humanness** (Turnstile)
  and a **nuisance-level origin** check. The server caps web keys at **trust level 1** with a base risk of 15; budget and
  automation policies should treat web as your weakest client.
* The key is **non-extractable**: script, extensions with page access and XSS cannot copy it out. But code running in your page
  *can still use* it to sign while the page is compromised (a signing oracle). Damage is bounded to that origin, that
  browser and the server's per-device credits and anomaly limits; fix the XSS and `reset()`/revoke the device.
* Clearing site data deletes the key; the next load registers a new device (and pays the proof of work again).
* Signing prevents replay and tampering in transit and ties requests to one key. It does not stop a user driving
  your site's own JavaScript, or a script that registers many keys slowly (that is what the proof of work, Turnstile and
  per-IP registration limits are for).
* If response signatures are verified with an unpinned (TOFU) key set, a MITM on the first load can substitute it. Pin.
* Verification buffers a clone of each response body, so very large downloads cost memory; serve those from a
  different origin (not signed) or set `verifyResponses: 'off'` for deployments that do not need it.
* Redirects: the signature covers the URL you requested. A server redirect to another path will fail verification;
  call the final URL directly.
* `Authorization` is used by Restricto-Sig. Sending your own `Authorization` header to the signed origin throws
  `authorization_conflict`; use another header for app tokens.
* **Extension point for step-up (WebAuthn)**: not built in. Use `onRequest(headers, { method, url })` to add an assertion header
  to selected requests, and obtain the assertion with `navigator.credentials.get()` yourself. The server side is separate.

## Talking to Django vs Laravel

Same endpoints, headers, error codes and vectors (`docs/test_vectors.json`, `docs/web_vectors.json`); you only point
`baseUrl` at the deployment. Differences are operational: Django configures CORS via `django-cors-headers`, Laravel via
`restricto:cors`; both enforce production enrolment with the Funsol control plane (`restricto_install` /
`restricto:install`), which the browser never sees.

## Development

```
npm test          # vitest: vectors, PoW, fake server integration, IndexedDB, React, Vue, SSR
npm run typecheck
npm run build     # tsup: ESM + CJS + .d.ts for ".", "./react", "./vue", plus dist/restricto.global.js
npm run size
```

`tests/helpers/fake-server.ts` is an independent implementation of the server side (stateless challenge, PoW check, signature,
nonce replay and skew checks, Ed25519 response signing) written from the protocol document.

The `Restricto-Sig` protocol is specified in `docs/DEVICE_ATTESTATION.md` and `docs/WEB_AND_LARAVEL.md` of the Restricto repository.
