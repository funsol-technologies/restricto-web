import { createHash, createHmac, createPublicKey, generateKeyPairSync, randomBytes, sign as nodeSign, verify as nodeVerify, type KeyObject } from 'node:crypto';

/**
 * Independent re-implementation of the server half of Restricto-Sig v1 (written from DEVICE_ATTESTATION.md and the
 * Python reference), deliberately sharing no code with the SDK.
 */
export interface Seen {
  method: string;
  path: string;
  authorization?: string;
  nonce?: string;
}

interface DeviceRec {
  pub: KeyObject;
  attestedUntil: number;
  revoked: boolean;
}

const b64u = (b: Buffer): string => b.toString('base64url');
const sha256Hex = (b: Buffer | string): string => createHash('sha256').update(b).digest('hex');

function quotePath(wirePath: string): string {
  const bytes: number[] = [];
  for (let i = 0; i < wirePath.length; i++) {
    if (wirePath[i] === '%') {
      bytes.push(parseInt(wirePath.slice(i + 1, i + 3), 16));
      i += 2;
    } else bytes.push(...Buffer.from(wirePath[i]!, 'utf8'));
  }
  return bytes.map((b) => (/[A-Za-z0-9_.\-~/]/.test(String.fromCharCode(b)) ? String.fromCharCode(b) : '%' + b.toString(16).toUpperCase().padStart(2, '0'))).join('');
}

export class FakeRestricto {
  readonly appId: string;
  powBits = 12;
  validitySeconds = 3 * 86400;
  maxSkew = 90;
  requireTurnstile = false;
  originAllowList: string[] | undefined;
  signResponses = true;
  tamperBody = false;
  badSignature = false;
  staleResponseTs = false;
  replayResponseNonce = false;
  banRegistrations = false;
  /** next N protected requests fail with this code before the handler runs */
  failNext: { code: number; status: number; remaining: number } | undefined;
  /** extra response for /api/rejected: unsigned 403 with a non-Restricto body */
  counts = { challenge: 0, register: 0, keys: 0, api: 0 };
  seen: Seen[] = [];
  registeredBodies: Array<Record<string, unknown>> = [];
  readonly devices = new Map<string, DeviceRec>();
  readonly signing = generateKeyPairSync('ed25519');
  readonly kid = 'k1';
  private readonly secret = randomBytes(32);
  private readonly usedChallenges = new Set<string>();
  private readonly nonces = new Set<string>();
  private lastNonce = '';

  constructor(appId = 'web.example.com') {
    this.appId = appId;
  }

  /** raw 32-byte Ed25519 public key, base64url (what /keys/ publishes and what apps pin) */
  get publicKeyB64(): string {
    return String(this.signing.publicKey.export({ format: 'jwk' }).x);
  }

  now = (): number => Math.floor(Date.now() / 1000);

  private denied(status: number, code: number, extra: Record<string, string> = {}): Response {
    return new Response(JSON.stringify({ detail: 'Request denied.', error_type: 'denied', error_code: code }), {
      status,
      headers: { 'content-type': 'application/json', ...extra },
    });
  }

  private challenge(): string {
    const ts = this.now();
    const rand = b64u(randomBytes(12));
    const mac = b64u(createHmac('sha256', this.secret).update(`${this.appId}|${ts}|${rand}`).digest()).slice(0, 22);
    return `v1.${ts}.${rand}.${mac}`;
  }

  private challengeOk(c: string): boolean {
    const m = /^v1\.(\d+)\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)$/.exec(c);
    if (!m) return false;
    const mac = b64u(createHmac('sha256', this.secret).update(`${this.appId}|${m[1]}|${m[2]}`).digest()).slice(0, 22);
    if (mac !== m[3] || this.now() - Number(m[1]) > 120 || this.usedChallenges.has(c)) return false;
    this.usedChallenges.add(c);
    return true;
  }

  private powOk(c: string, sol: unknown): boolean {
    if (typeof sol !== 'string' || !/^\d{1,20}$/.test(sol)) return false;
    const d = createHash('sha256').update(`${c}:${sol}`).digest();
    let bits = 0;
    for (const byte of d) {
      if (byte === 0) bits += 8;
      else {
        bits += Math.clz32(byte) - 24;
        break;
      }
    }
    return bits >= this.powBits;
  }

  expire(deviceId: string): void {
    this.devices.get(deviceId)!.attestedUntil = this.now() - 1;
  }
  forget(deviceId: string): void {
    this.devices.delete(deviceId);
  }
  revoke(deviceId: string): void {
    this.devices.get(deviceId)!.revoked = true;
  }

  fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const req = new Request(input as string, init);
    const url = new URL(req.url);
    const path = url.pathname;
    if (req.headers.get('X-APP-ID') !== this.appId && path.startsWith('/restricto/')) return this.denied(403, 458118);

    if (path === '/restricto/device/challenge/' && req.method === 'POST') {
      this.counts.challenge++;
      return Response.json({ challenge: this.challenge(), expires_in: 120, server_time: this.now(), scheme: 'Restricto-Sig v1', pow_bits: this.powBits });
    }
    if (path === '/restricto/device/register/' && req.method === 'POST') return this.register(req);
    if (path === '/restricto/keys/') {
      this.counts.keys++;
      return Response.json({ alg: 'Ed25519', active_kid: this.kid, keys: [{ kid: this.kid, public_key: this.publicKeyB64 }] });
    }
    return this.protectedRoute(req, url);
  };

  private async register(req: Request): Promise<Response> {
    this.counts.register++;
    const body = (await req.json()) as Record<string, any>;
    this.registeredBodies.push(body);
    if (this.banRegistrations) return this.denied(403, 458118);
    if (body.platform !== 'web' || !this.challengeOk(body.challenge)) return this.denied(403, 458118);
    if (!this.powOk(body.challenge, body.web?.pow)) return this.denied(403, 458118);
    if (this.requireTurnstile && body.web?.turnstile_token !== 'ts-ok') return this.denied(403, 458118);
    let spki: Buffer;
    let pub: KeyObject;
    try {
      spki = Buffer.from(body.public_key, 'base64url');
      pub = createPublicKey({ key: spki, format: 'der', type: 'spki' });
    } catch {
      return this.denied(403, 458118);
    }
    const deviceId = 'rd_' + sha256Hex(spki).slice(0, 32);
    const attestedUntil = this.now() + this.validitySeconds;
    this.devices.set(deviceId, { pub, attestedUntil, revoked: false });
    return Response.json({ device_id: deviceId, trust_level: 1, platform: 'web', attested_until: attestedUntil, server_time: this.now(), max_clock_skew: this.maxSkew, scheme: 'Restricto-Sig v1' });
  }

  private async protectedRoute(req: Request, url: URL): Promise<Response> {
    const auth = req.headers.get('Authorization') ?? '';
    const seen: Seen = { method: req.method, path: url.pathname + url.search, authorization: auth || undefined };
    this.seen.push(seen);
    this.counts.api++;
    const m = /^Restricto-Sig v1 id=([^,]+),ts=(\d+),nonce=([A-Za-z0-9_-]{16,64}),sig=([A-Za-z0-9_-]+)$/.exec(auth);
    if (!m) return this.denied(401, 458021);
    const [, id, ts, nonce, sig] = m as unknown as [string, string, string, string, string];
    seen.nonce = nonce;
    if (this.failNext && this.failNext.remaining > 0) {
      this.failNext.remaining--;
      return this.denied(this.failNext.status, this.failNext.code);
    }
    if (Math.abs(this.now() - Number(ts)) > this.maxSkew) return this.denied(401, 458052, { 'X-Restricto-Server-Time': String(this.now()) });
    const dev = this.devices.get(id);
    if (!dev) return this.denied(401, 458033);
    if (dev.revoked) return this.denied(403, 458071);
    if (dev.attestedUntil < this.now()) return this.denied(401, 458085);
    const bodyBytes = Buffer.from(await req.arrayBuffer());
    const rawPath = url.href.slice(url.origin.length).split('?')[0]!;
    const target = quotePath(rawPath) + (url.search.length > 1 ? url.search : '');
    const canonical = ['RESTRICTO-SIG-V1', req.method.toUpperCase(), target, ts, nonce, id, this.appId, sha256Hex(bodyBytes)].join('\n');
    const ok = nodeVerify('sha256', Buffer.from(canonical), { key: dev.pub, dsaEncoding: 'ieee-p1363' }, Buffer.from(sig, 'base64url'));
    if (!ok) return this.denied(401, 458047);
    if (this.nonces.has(id + nonce)) return this.denied(401, 458066);
    this.nonces.add(id + nonce);

    let status = 200;
    let payload: unknown = { ok: true, method: req.method, target, body: bodyBytes.toString('utf8') };
    if (url.pathname === '/api/missing/') {
      status = 404;
      payload = { detail: 'Not found.' };
    }
    return this.signed(status, JSON.stringify(payload), id, nonce);
  }

  private signed(status: number, body: string, deviceId: string, nonce: string): Response {
    const headers: Record<string, string> = { 'content-type': 'application/json' };
    if (this.signResponses) {
      const ts = String(this.now() + (this.staleResponseTs ? -1000 : 0));
      const signedNonce = this.replayResponseNonce && this.lastNonce ? this.lastNonce : nonce;
      const canonical = ['RESTRICTO-RESP-V1', String(status), signedNonce, deviceId, ts, sha256Hex(body)].join('\n');
      let sig = nodeSign(null, Buffer.from(canonical), this.signing.privateKey);
      if (this.badSignature) sig = Buffer.from(sig.map((b, i) => (i === 0 ? b ^ 1 : b)));
      headers['X-Restricto-Resp-Kid'] = this.kid;
      headers['X-Restricto-Resp-Ts'] = ts;
      headers['X-Restricto-Resp-Sig'] = b64u(sig);
    }
    this.lastNonce = nonce;
    return new Response(this.tamperBody ? body.replace('true', 'false') : body, { status, headers });
  }
}
