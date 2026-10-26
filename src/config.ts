import { DEFAULTS, POW_SDK_MAX_BITS, type ConfigValues } from './config-defaults';
import { b64urlDecode, utf8 } from './encoding';
import { ed25519Verify, int, isObj, parseRespKeys } from './verify';
const clamp = (v: unknown, lo: number, hi: number, dflt: number): number => {
  const n = typeof v === 'number' && Number.isFinite(v) ? v : dflt;
  return Math.min(hi, Math.max(lo, n));
};

function values(p: Record<string, unknown>): ConfigValues {
  const pow = isObj(p.pow) ? p.pow : {};
  const renew = isObj(p.renew) ? p.renew : {};
  const retry = isObj(p.retry) ? p.retry : {};
  const clock = isObj(p.clock) ? p.clock : {};
  const up = isObj(p.upgrade) ? p.upgrade : {};
  const minSdk = isObj(p.min_sdk) && typeof p.min_sdk.web === 'string' && /^[0-9]+\.[0-9]+\.[0-9]+/.test(p.min_sdk.web) ? p.min_sdk.web : undefined;
  const bits = int(pow.bits);
  const backoff = Array.isArray(renew.backoff) ? renew.backoff.slice(0, 8).filter((x): x is number => typeof x === 'number').map((x) => clamp(x, 1, 86400, 60)) : [];
  const versions = Array.isArray(p.sig_versions) ? p.sig_versions.filter((x): x is number => Number.isInteger(x) && (x as number) > 0).slice(0, 8) : [];
  const url = typeof up.url === 'string' && /^https?:\/\//i.test(up.url) && up.url.length <= 2048 ? up.url : '';
  return {
    seq: p.seq as number,
    iat: int(p.iat) ?? 0,
    exp: p.exp as number,
    sigVersions: versions.length ? versions : DEFAULTS.sigVersions,
    respKeys: parseRespKeys(p.resp_keys),
    pow: {
      bits: bits === undefined ? undefined : clamp(bits, 0, POW_SDK_MAX_BITS, 0),
      maxBits: clamp(int(pow.max_bits), 1, POW_SDK_MAX_BITS, POW_SDK_MAX_BITS),
    },
    maxSkew: clamp(clock.max_skew, 30, 300, DEFAULTS.maxSkew),
    renew: {
      beforeS: clamp(renew.before_s, 300, 14 * 86400, DEFAULTS.renew.beforeS),
      jitter: clamp(renew.jitter, 0, 0.5, DEFAULTS.renew.jitter),
      backoff: backoff.length ? backoff : DEFAULTS.renew.backoff,
    },
    retry: {
      replay: Math.trunc(clamp(retry.replay, 0, 3, DEFAULTS.retry.replay)),
      unknownDevice: Math.trunc(clamp(retry.unknown_device, 0, 3, DEFAULTS.retry.unknownDevice)),
      transient: Math.trunc(clamp(retry.transient, 0, 5, DEFAULTS.retry.transient)),
    },
    minSdk,
    upgrade: { mode: up.mode === 'soft' || up.mode === 'hard' ? up.mode : 'none', url },
    relaxVerify: isObj(p.relax) && p.relax.verify_responses === false,
  };
}

export type ConfigCheck = { ok: true; values: ConfigValues } | { ok: false; reason: string };

/**
 * Signature (a pinned config key; any listed key may verify), `app` binding and envelope only. The clock-dependent rules
 * (`exp`, anti-rollback `seq`) are applied by the caller because they depend on state. The signature covers the payload bytes as
 * served: they are never re-serialised.
 */
export async function verifyConfigDocument(doc: unknown, appId: string, pins: Record<string, string>, forceFallback?: boolean): Promise<ConfigCheck> {
  if (!isObj(doc) || typeof doc.payload !== 'string' || typeof doc.kid !== 'string' || typeof doc.sig !== 'string') return { ok: false, reason: 'malformed document' };
  const pin = Object.prototype.hasOwnProperty.call(pins, doc.kid) ? pins[doc.kid] : undefined;
  if (!pin) return { ok: false, reason: `config key "${doc.kid}" is not pinned` };
  let raw: Uint8Array;
  let payload: unknown;
  try {
    raw = b64urlDecode(doc.payload);
    const message = new Uint8Array([...utf8(`RESTRICTO-CFG-V1\n${appId}\n`), ...raw]);
    if (!(await ed25519Verify(b64urlDecode(pin), b64urlDecode(doc.sig), message, forceFallback))) return { ok: false, reason: 'signature invalid' };
    payload = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(raw));
  } catch {
    return { ok: false, reason: 'malformed document' };
  }
  if (!isObj(payload) || payload.v !== 1) return { ok: false, reason: 'unsupported document version' };
  if (payload.app !== appId) return { ok: false, reason: 'document is for another application' };
  if (!Number.isSafeInteger(payload.seq) || (payload.seq as number) < 0 || !Number.isSafeInteger(payload.exp)) return { ok: false, reason: 'document has no valid seq/exp' };
  return { ok: true, values: values(payload) };
}
