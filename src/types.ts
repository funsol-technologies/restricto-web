import type { RestrictoError } from './errors';
import type { KeyStore } from './key-store';
import type { PowOptions } from './pow';
import type { SignableBody } from './body';

export type VerifyMode = 'strict' | 'warn' | 'off';
export type RestrictoStatus = 'idle' | 'registering' | 'ready' | 'error';

/**
 * Where the server-driven behaviour comes from. `none`: no `pinnedConfigKeys`, compiled-in defaults only. `defaults`: pinned, but no
 * document has been accepted yet. `valid` / `expired`: the last accepted signed document (expired ones keep their key set and limits
 * but lose their `relax` flags).
 */
export interface ConfigStatus {
  readonly source: 'none' | 'defaults' | 'valid' | 'expired';
  readonly seq: number | null;
  /** unix seconds */
  readonly exp: number | null;
  /** The document currently relaxes response verification (`relax.verify_responses=false`). */
  readonly relaxed: boolean;
  readonly lastError: string | null;
}

/** A newer SDK is wanted. `mode: 'hard'` only ever comes from the signed config (and then signed calls fail with `upgrade_required`). */
export interface UpgradeInfo {
  readonly mode: 'soft' | 'hard';
  readonly reason: 'config' | 'min_sdk' | 'sig_version' | 'server';
  readonly url: string;
  readonly minSdk?: string;
}

export interface RestrictoState {
  readonly status: RestrictoStatus;
  readonly deviceId: string | null;
  /** Browser keys are capped at 1 by the server. */
  readonly trustLevel: number | null;
  /** unix seconds (server clock) */
  readonly attestedUntil: number | null;
  readonly error: RestrictoError | null;
  readonly config: ConfigStatus;
  readonly upgrade: UpgradeInfo | null;
}

export interface RestrictoConfig {
  /** Origin of the Restricto deployment, e.g. `https://api.example.com`. Only requests to this origin are ever signed. */
  baseUrl: string;
  /** Sent as `X-APP-ID`; the application's package name in the Restricto admin (e.g. `web.example.com`). */
  appId: string;
  /** Where the Restricto routes are mounted. Default `/restricto`. */
  restrictoPath?: string;
  /** Reported at registration. Default `web-1.0.0`. */
  appVersion?: string;
  /** Called on each (re-)registration; return a Cloudflare Turnstile token. The SDK never loads Cloudflare scripts itself. */
  getTurnstileToken?: () => Promise<string | undefined>;
  /**
   * RECOMMENDED. `{ kid: base64url raw Ed25519 public key }` of the config signing key(s) (any may verify). With it the SDK fetches
   * the signed config document (`GET /restricto/config/`) and takes the response-verification keys, PoW limits, renewal timing, retry
   * budgets and upgrade policy from it; response keys then rotate without an SDK release. Without it, response keys are fetched from
   * `/keys/` on first use (trust on first use: weaker) and everything else is compiled-in.
   */
  pinnedConfigKeys?: Record<string, string>;
  /** `{ kid: base64url Ed25519 public key }` of response-signing keys, authoritative alongside the config's keys. */
  pinnedResponseKeys?: Record<string, string>;
  /** Default `strict`. A valid signed config can relax `strict` to `warn` (kill switch). */
  verifyResponses?: VerifyMode;
  /** Default: IndexedDB, or memory where IndexedDB is unavailable. */
  keyStore?: KeyStore;
  /** Underlying fetch. Default: the global one at call time. */
  fetch?: typeof fetch;
  /** Register as soon as the client is created (in a browser). Default false: lazily on the first signed call. */
  autoRegister?: boolean;
  /** Renew the attestation this long before `attested_until`. Default: the config's `renew.before_s` (1 day), capped at a quarter of the validity. */
  refreshMarginSeconds?: number;
  /** Schedule the renewal with a timer for long-lived pages. Default true. */
  autoRefresh?: boolean;
  /** Default 5 MiB (the server's limit). */
  maxBodyBytes?: number;
  /** After a failed registration, calls fail fast for this long. Default: the config's `renew.backoff` ladder (5 s, 30 s, 5 min, 1 h). */
  registerCooldownMs?: number;
  /** Timeout of the config document fetch. Default 8000. */
  configTimeoutMs?: number;
  /** Wall-clock budget for the proof of work. Default 60000. */
  powBudgetMs?: number;
  pow?: Pick<PowOptions, 'useWorker' | 'createWorker'>;
  onPowProgress?: (attempts: number) => void;
  /** `manual` (default) never follows a redirect on a signed call; `error` makes the call reject on one. */
  redirect?: 'manual' | 'error';
  /** Base delay of the bounded retry of unsigned / unverifiable answers to idempotent calls. Default 400 ms (doubles, jittered). */
  transientBackoffMs?: number;
  /** Try a signed `renew:true` registration before falling back to a plain re-registration of the same key. Default true. */
  signedRenewal?: boolean;
  /**
   * Extension point, run before every signed attempt: add headers (e.g. a WebAuthn step-up assertion). The signature does not cover
   * headers, so anything added here is simply sent along.
   */
  onRequest?: (headers: Headers, info: { method: string; url: URL }) => void | Promise<void>;
  /** A newer SDK is wanted (hard: from the signed config, signed calls then fail; soft: advisory). */
  onUpgradeRequired?: (info: UpgradeInfo) => void;
  /** Receives non-fatal problems (`verifyResponses: 'warn'`, failed background renewals, rejected config documents). Default: console.warn. */
  onWarning?: (message: string) => void;
  /** false disables the Web Locks cross-tab lock (tests). */
  useWebLocks?: boolean;
  /** Tests only: always use the @noble/curves Ed25519 verifier. */
  forceEd25519Fallback?: boolean;
}

export interface SignInput {
  method?: string;
  url: string | URL;
  body?: SignableBody;
}

export interface SignedRequest {
  /** `Restricto-Signature` and `X-APP-ID`: put these on your request unchanged. Your own `Authorization` header is not touched. */
  readonly headers: { 'Restricto-Signature': string; 'X-APP-ID': string };
  readonly nonce: string;
  readonly ts: string;
  readonly deviceId: string;
  /** Check the response to this request; throws `RestrictoError('response_unverified')` in strict mode. */
  verify(response: Response): Promise<void>;
}

export interface RestrictoClient {
  readonly appId: string;
  /**
   * Drop-in for `window.fetch`: signs requests to `baseUrl`'s origin, passes everything else through untouched. Signed calls never
   * follow redirects. Streaming bodies/responses (SSE) are not supported.
   */
  fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response>;
  /** For custom HTTP stacks. Throws for URLs outside the configured origin. */
  sign(request: SignInput): Promise<SignedRequest>;
  /**
   * For custom stacks: after a response, returns true when it was a recoverable rejection that has now been fixed (clock resynced,
   * device re-registered or replaced) - call `sign` again and resend ONCE. Only responses that verify (signature, same origin, not
   * redirected) are ever acted upon; anything else returns false.
   */
  recover(response: Response, signed: SignedRequest): Promise<boolean>;
  /** Registers if needed; resolves when the device is ready. Concurrent callers share one registration. */
  ready(): Promise<RestrictoState>;
  /** Fetch the signed config document now (needs `pinnedConfigKeys`). Resolves with the resulting config status. */
  refreshConfig(): Promise<ConfigStatus>;
  getState(): RestrictoState;
  subscribe(listener: (state: RestrictoState) => void): () => void;
  /** true when the response's Ed25519 signature was checked successfully. */
  isVerified(response: Response): boolean;
  /** Forget the device key and registration (e.g. on logout from a shared computer). Aborts an in-flight registration. */
  reset(): Promise<void>;
  /** Stop timers and abort in-flight registration work. */
  close(): void;
}
