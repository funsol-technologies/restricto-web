# Changelog

## 1.0.0-rc.1

Port to the final wire protocol (`docs/PROTOCOL_V1_FINAL.md`). **Breaking** relative to 0.1.0 (nothing was published).

### Wire protocol
* `Restricto-Signature: v=1,id,ts,nonce,bh,sig[,ext]` replaces `Authorization: Restricto-Sig`. The application's own `Authorization`
  header passes through untouched; the `authorization_conflict` refusal is gone.
* Canonical request string with the host line, canonical path (`%2F` = `/`), canonical query (decoded, re-encoded, sorted) and the
  body hash `bh` in the header. Every group of `protocol_vectors.json` passes byte for byte (canonical path/query/host, header
  parse, request signature incl. negatives, response signature incl. negatives, config document incl. negatives, PoW, binding).
* `Restricto-Response-Signature` (several fields allowed: any verifying signature with a known kid+alg wins, unknown ones are
  ignored); the canonical string covers `Content-Type`, `Location` and `Retry-After`; HEAD/204/304 are signed over the empty body.
* Proof of work bound to the key (`challenge:hex(sha256(SPKI)):n`), size from the challenge `pow` object and the signed config,
  clamped to <= 26 bits, wall-clock budget (`powBudgetMs`), aborted by `close()`/`reset()`.
* Register payload with `caps` and `renew`; renewal is a **signed** `renew:true` request with the existing key. A server that
  refuses it (signed 4xx) gets a plain re-registration of the same key, remembered per key (`noRenew`).
* Challenge/register `sig_versions`, `cfg_seq` and `pow` are read; the labelled binding hash is `bindingHash()` in `src/canonical.ts` (covered by the vectors).

### Signed config document (section 6)
* New `pinnedConfigKeys`: `GET /restricto/config/`, signature, app binding, anti-rollback `seq` (persisted), `exp`, clamping of every
  value, `resp_keys` as the response key set (rotation without an SDK release), `relax` only while valid, renewal timing/backoff,
  retry budgets, clock skew, PoW limits, `min_sdk`/`upgrade`. Without it: trust-on-first-use `/keys/` (weaker, documented).
* State and events: `state.config`, `state.upgrade`, `onUpgradeRequired`, `refreshConfig()`, also in the React hook and the Vue composable.

### Error handling (frozen by the spec)
* Unsigned (or unverifiable, redirected, off-origin) answers to signed requests are treated as network errors with bounded backoff;
  they never wipe a key, re-register or move the clock. Only a verified body's `action` is acted upon
  (`none|reregister|wipe|resync_clock|backoff|upgrade`); `upgrade` in an error body is advisory, hard upgrades come only from the
  signed config.

### Review fixes
* A-1 `recover()` and the in-client recovery only act on verified replies for the same request, same origin, not redirected;
  signed calls use `redirect: 'manual'` (configurable to `'error'`).
* A-2 PoW ceiling 26 bits (was 40), wall-clock budget, `AbortSignal` plumbed through registration.
* A-3 A grant that is already expired no longer causes a re-registration on every call (at least 60 s of back-off).
* A-4 `reset()` takes the registration lock and invalidates the in-flight registration; a wipe re-checks the stored key under the
  lock, so two tabs mint one replacement, not two.
* A-5 Documentation: pinning, XSS signing oracle, `%2F` canonicalisation, no streaming/SSE. The `<script>` build no longer
  attaches `window.Restricto` unless the tag has `data-restricto-global="Name"`.

### Packaging
* The proof of work and the config document parser are lazily imported (core about 12 KB gzip, see `npm run size`).
* `scripts/live-check.mjs` for an end-to-end check against a real deployment (not part of `npm test`).
