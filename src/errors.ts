/**
 * Public server error codes (restricto/client_errors.py), exported for your own logging. The SDK itself reacts to the signed `action`
 * field, not to these (the one exception is a replayed nonce, see README).
 */
export const ServerCode = {
  SignatureRequired: 458010,
  UnknownDevice: 458033,
  SignatureInvalid: 458047,
  ClockSkew: 458052,
  Replay: 458066,
  DeviceRevoked: 458071,
  AttestationExpired: 458085,
  BodyTooLarge: 458104,
  RegisterFailed: 458118,
  RegisterRateLimited: 458139,
} as const;

export type RestrictoErrorCode =
  | 'unsupported_environment'
  | 'unsupported_body'
  | 'body_too_large'
  | 'redirect'
  | 'upgrade_required'
  | 'challenge_failed'
  | 'register_failed'
  | 'response_unverified'
  | 'keys_unavailable'
  | 'aborted'
  | 'config';

export interface RestrictoErrorInit {
  status?: number;
  serverCode?: number;
  retryAfter?: number;
  /** The server answered, but not with a signature we could verify: a proxy, a captive portal, or an attacker. */
  unsigned?: boolean;
  /** The signed `action` of the refusal, when it was verified. */
  action?: string;
  cause?: unknown;
}

export class RestrictoError extends Error {
  readonly code: RestrictoErrorCode;
  /** HTTP status of the failing server reply, when there was one. */
  readonly status?: number;
  /** `error_code` from the server's opaque error body (e.g. 458118). */
  readonly serverCode?: number;
  /** Seconds, from `Retry-After`. */
  readonly retryAfter?: number;
  /** true when the (unsigned or unverifiable) reply is being treated as a network error. */
  readonly unsigned?: boolean;
  readonly action?: string;

  constructor(code: RestrictoErrorCode, message: string, init: RestrictoErrorInit = {}) {
    super(message);
    this.name = 'RestrictoError';
    this.code = code;
    this.status = init.status;
    this.serverCode = init.serverCode;
    this.retryAfter = init.retryAfter;
    this.unsigned = init.unsigned;
    this.action = init.action;
    if (init.cause !== undefined) (this as { cause?: unknown }).cause = init.cause;
  }
}

export function abortError(): RestrictoError {
  return new RestrictoError('aborted', 'The operation was aborted.');
}

export const parseRetryAfter = (v: string | null): number | undefined => {
  const n = Number(v);
  return v && /^[0-9]{1,7}$/.test(v.trim()) && n > 0 ? n : undefined;
};

/** Pull `error_code` out of a Restricto error body without ever throwing. */
export async function readServerCode(res: Response): Promise<number | undefined> {
  if (res.status < 400) return undefined;
  try {
    const body: unknown = await res.clone().json();
    if (body && typeof body === 'object' && 'error_code' in body) {
      const code = (body as { error_code: unknown }).error_code;
      return typeof code === 'number' ? code : undefined;
    }
  } catch {
    /* not JSON */
  }
  return undefined;
}
