import type { RestrictoError } from './errors';
import type { KeyStore } from './key-store';
import type { PowOptions } from './pow';
import type { SignableBody } from './body';

export type VerifyMode = 'strict' | 'warn' | 'off';
export type RestrictoStatus = 'idle' | 'registering' | 'ready' | 'error';

export interface RestrictoState {
  readonly status: RestrictoStatus;
  readonly deviceId: string | null;
  /** Browser keys are capped at 1 by the server. */
  readonly trustLevel: number | null;
  /** unix seconds (server clock) */
  readonly attestedUntil: number | null;
  readonly error: RestrictoError | null;
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
  /** `{ kid: base64url Ed25519 public key }`. Recommended; without it keys are fetched once from `/keys/` (trust on first use). */
  pinnedResponseKeys?: Record<string, string>;
  /** Default `strict`. */
  verifyResponses?: VerifyMode;
  /** Default: IndexedDB, or memory where IndexedDB is unavailable. */
  keyStore?: KeyStore;
  /** Underlying fetch. Default: the global one at call time. */
  fetch?: typeof fetch;
  /** Register as soon as the client is created (in a browser). Default false: lazily on the first signed call. */
  autoRegister?: boolean;
  /** Renew the attestation this long before `attested_until`. Default 6 h (capped at a quarter of the validity). */
  refreshMarginSeconds?: number;
  /** Schedule the renewal with a timer for long-lived pages. Default true. */
  autoRefresh?: boolean;
  /** Default 5 MiB (the server's limit). */
  maxBodyBytes?: number;
  /** After a failed registration, calls fail fast for this long instead of redoing the work. Default 5000. */
  registerCooldownMs?: number;
  pow?: Pick<PowOptions, 'useWorker' | 'createWorker'>;
  onPowProgress?: (attempts: number) => void;
  /**
   * Extension point, run before every signed attempt: add headers (e.g. a WebAuthn step-up assertion). The signature does
   * not cover headers, so anything added here is simply sent along.
   */
  onRequest?: (headers: Headers, info: { method: string; url: URL }) => void | Promise<void>;
  /** Receives non-fatal problems (`verifyResponses: 'warn'`, failed background renewals). Default: console.warn. */
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
  /** `Authorization` and `X-APP-ID`: put these on your request unchanged. */
  readonly headers: { Authorization: string; 'X-APP-ID': string };
  readonly nonce: string;
  readonly ts: string;
  readonly deviceId: string;
  /** Check the response to this request; throws `RestrictoError('response_unverified')` in strict mode. */
  verify(response: Response): Promise<void>;
}

export interface RestrictoClient {
  readonly appId: string;
  /** Drop-in for `window.fetch`: signs requests to `baseUrl`'s origin, passes everything else through untouched. */
  fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response>;
  /** For custom HTTP stacks. Throws for URLs outside the configured origin. */
  sign(request: SignInput): Promise<SignedRequest>;
  /**
   * For custom stacks: after a response, returns true when it was a recoverable rejection (clock skew, replayed nonce,
   * unknown/expired device, revoked) that has now been fixed - call `sign` again and resend ONCE.
   */
  recover(response: Response, signed: SignedRequest): Promise<boolean>;
  /** Registers if needed; resolves when the device is ready. Concurrent callers share one registration. */
  ready(): Promise<RestrictoState>;
  getState(): RestrictoState;
  subscribe(listener: (state: RestrictoState) => void): () => void;
  /** true when the response's Ed25519 signature was checked successfully. */
  isVerified(response: Response): boolean;
  /** Forget the device key and registration (e.g. on logout from a shared computer). */
  reset(): Promise<void>;
  /** Stop timers. */
  close(): void;
}
