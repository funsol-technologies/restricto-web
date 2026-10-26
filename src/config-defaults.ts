import type { ResponseKey } from './verify';

/** Server-driven behaviour after clamping every value to the bounds compiled into this SDK. */
export interface ConfigValues {
  seq: number;
  iat: number;
  exp: number;
  sigVersions: number[];
  respKeys: ResponseKey[];
  pow: { bits?: number; maxBits: number };
  maxSkew: number;
  renew: { beforeS: number; jitter: number; backoff: number[] };
  retry: { replay: number; unknownDevice: number; transient: number };
  minSdk?: string;
  upgrade: { mode: 'none' | 'soft' | 'hard'; url: string };
  relaxVerify: boolean;
}

/** The pre-signed document as served by `GET /restricto/config/` (and as persisted for anti-rollback). */
export interface ConfigDocument {
  payload: string;
  kid: string;
  sig: string;
}

/** Compiled-in hard limits ("never no security"): nothing the server sends can go outside these. */
export const POW_SDK_MAX_BITS = 26;

export const DEFAULTS: ConfigValues = {
  seq: 0,
  iat: 0,
  exp: 0,
  sigVersions: [1],
  respKeys: [],
  pow: { maxBits: POW_SDK_MAX_BITS },
  maxSkew: 90,
  renew: { beforeS: 86400, jitter: 0.2, backoff: [5, 30, 300, 3600] },
  retry: { replay: 1, unknownDevice: 1, transient: 3 },
  upgrade: { mode: 'none', url: '' },
  relaxVerify: false,
};

/** Numeric `major.minor.patch` comparison; a pre-release tag (`-rc.1`) is ignored on purpose. */
export function compareVersions(a: string, b: string): number {
  const pa = a.split(/[-+]/)[0]!.split('.').map(Number);
  const pb = b.split(/[-+]/)[0]!.split('.').map(Number);
  for (let i = 0; i < 3; i++) {
    const d = (pa[i] || 0) - (pb[i] || 0);
    if (d) return d < 0 ? -1 : 1;
  }
  return 0;
}
