import { createHash, createHmac, createPublicKey, generateKeyPairSync, randomBytes, sign as nodeSign, verify as nodeVerify, type KeyObject } from 'node:crypto';

/**
 * Independent re-implementation of the server half of PROTOCOL_V1_FINAL.md (written from the spec and the Python reference), deliberately
 * sharing no code with the SDK: its own header parser, canonicalisation (byte oriented), response signer and config signer.
 */
export interface Seen {
  method: string;
  path: string;
  header?: string;
  authorization?: string | null;
  nonce?: string;
  host?: string;
}

interface DeviceRec {
  pub: KeyObject;
  attestedUntil: number;
  revoked: boolean;
}

interface RespKey {
  kid: string;
  priv: KeyObject;
  pub: string;
  state: 'active' | 'next' | 'retired';
  nbf?: number;
  naf?: number;
}

const b64u = (b: Buffer): string => b.toString('base64url');
const sha256Hex = (b: Buffer | string): string => createHash('sha256').update(b).digest('hex');
const sha256B64 = (b: Buffer | string): string => b64u(createHash('sha256').update(b).digest());

const UNRESERVED = /[A-Za-z0-9\-._~]/;
const isHex = (c: number | undefined): boolean => c !== undefined && ((c >= 48 && c <= 57) || (c >= 65 && c <= 70) || (c >= 97 && c <= 102));

function pctDecode(s: string): Buffer {
  const b = Buffer.from(s, 'utf8');
  const out: number[] = [];
  for (let i = 0; i < b.length; i++) {
    if (b[i] === 0x25 && isHex(b[i + 1]) && isHex(b[i + 2])) {
      out.push(parseInt(String.fromCharCode(b[i + 1]!, b[i + 2]!), 16));
      i += 2;
    } else out.push(b[i]!);
  }
  return Buffer.from(out);
}

function pctEncode(b: Buffer, keepSlash: boolean): string {
  let s = '';
  for (const x of b) s += UNRESERVED.test(String.fromCharCode(x)) || (keepSlash && x === 0x2f) ? String.fromCharCode(x) : '%' + x.toString(16).toUpperCase().padStart(2, '0');
  return s;
}

function canonicalTarget(url: URL): string {
  const path = pctEncode(pctDecode(url.pathname || '/'), true);
  const pairs = url.search
    .replace(/^\?/, '')
    .split('&')
    .filter(Boolean)
    .map((p) => {
      const i = p.indexOf('=');
      return [pctEncode(pctDecode(i < 0 ? p : p.slice(0, i)), false), pctEncode(pctDecode(i < 0 ? '' : p.slice(i + 1)), false)] as const;
    })
    .sort((a, b) => Buffer.compare(Buffer.from(a[0] + '\u0000' + a[1]), Buffer.from(b[0] + '\u0000' + b[1])));
  const query = pairs.map(([k, v]) => `${k}=${v}`).join('&');
  return query ? `${path}?${query}` : path;
}

function canonicalHostOf(url: URL): string {
  const def = url.protocol === 'http:' ? '80' : '443';
  return url.port && url.port !== def ? `${url.hostname}:${url.port}` : url.hostname;
}

export function parseSigHeader(h: string | null): Record<string, string> | undefined {
  if (!h || h.length > 1024) return undefined;
  const out: Record<string, string> = {};
  for (const part of h.split(',')) {
    const m = /^([A-Za-z0-9_]+)=([A-Za-z0-9_.:\-]+)$/.exec(part);
    if (!m || m[1]! in out) return undefined;
    out[m[1]!] = m[2]!;
  }
  if (out.v !== '1') return undefined;
  if (!/^rd_[A-Za-z0-9_.:\-]{1,61}$/.test(out.id ?? '') || !/^[0-9]{1,12}$/.test(out.ts ?? '') || !/^[A-Za-z0-9_\-]{16,64}$/.test(out.nonce ?? '')) return undefined;
  if (!/^[A-Za-z0-9_\-]{43}$/.test(out.bh ?? '') || !/^[A-Za-z0-9_\-]{80,128}$/.test(out.sig ?? '')) return undefined;
  return out;
}

export interface ConfigOverrides {
  seq?: number;
  exp?: number;
  iat?: number;
  app?: string;
  kid?: string;
  /** fields merged over the default payload (top level) */
  extra?: Record<string, unknown>;
  /** sign with this key instead of the server's config key */
  signWith?: KeyObject;
}

export class FakeRestricto {
  readonly appId: string;
  powBits = 12;
  /** what /challenge/ announces (null = the same as powBits); the register call always enforces powBits */
  announcedBits: number | null = null;
  validitySeconds = 3 * 86400;
  maxSkew = 90;
  requireTurnstile = false;
  signResponses = true;
  tamperBody = false;
  badSignature = false;
  staleResponseTs = false;
  replayResponseNonce = false;
  banRegistrations = false;
  /** web renewals (`renew:true`) are accepted; false mimics the Python reference: a signed 403 with action none */
  renewSupported = true;
  /** next N protected requests fail with this signed denial before the handler runs */
  failNext: { code: number; status: number; remaining: number; action?: string; retryAfter?: string; extra?: Record<string, unknown> } | undefined;
  /** next N protected requests are answered by an unsigned "proxy" */
  proxyNext: { status: number; remaining: number; body?: string; looksLikeRestricto?: boolean } | undefined;
  /** next N protected requests are answered by a 302 */
  redirectNext: { location: string; remaining: number; signed?: boolean } | undefined;
  /** extra Restricto-Response-Signature fields to prepend (unknown alg / kid) */
  extraSigFields: string[] = [];
  /** a fixed answer for GET /config/ (undefined = serve the stored document, 404 when none) */
  configOverride: { status: number; body?: unknown } | undefined;
  cfgSeq = 0;
  counts = { challenge: 0, register: 0, keys: 0, api: 0, config: 0, renew: 0 };
  seen: Seen[] = [];
  registeredBodies: Array<Record<string, any>> = [];
  readonly devices = new Map<string, DeviceRec>();
  readonly respKeys: RespKey[] = [];
  readonly configKey = generateKeyPairSync('ed25519');
  readonly configKid = 'cfg-test';
  private configDoc: { payload: string; kid: string; sig: string } | undefined;
  private readonly secret = randomBytes(32);
  private readonly usedChallenges = new Set<string>();
  private readonly nonces = new Set<string>();
  private lastNonce = '';

  constructor(appId = 'web.example.com') {
    this.appId = appId;
    this.addKey('k1', 'active');
  }

  addKey(kid: string, state: RespKey['state']): RespKey {
    const kp = generateKeyPairSync('ed25519');
    const k: RespKey = { kid, priv: kp.privateKey, pub: String(kp.publicKey.export({ format: 'jwk' }).x), state };
    if (state !== 'next') k.nbf = this.now() - 1000;
    this.respKeys.push(k);
    return k;
  }

  /** `next` -> `active` (the old active one is retired): the server changes what it signs with, no document republished */
  promote(kid: string): void {
    for (const k of this.respKeys) {
      if (k.state === 'active') Object.assign(k, { state: 'retired', naf: this.now() });
      if (k.kid === kid) Object.assign(k, { state: 'active', nbf: this.now() - 1 });
    }
  }

  get active(): RespKey {
    return this.respKeys.find((k) => k.state === 'active')!;
  }

  /** raw 32-byte Ed25519 public key of the active response key, base64url (what apps may pin) */
  get publicKeyB64(): string {
    return this.active.pub;
  }

  /** raw 32-byte Ed25519 config public key, base64url (what apps pin as `pinnedConfigKeys`) */
  get configPublicB64(): string {
    return String(this.configKey.publicKey.export({ format: 'jwk' }).x);
  }

  get pinnedConfigKeys(): Record<string, string> {
    return { [this.configKid]: this.configPublicB64 };
  }

  now = (): number => Math.floor(Date.now() / 1000);

  /** Produce, sign and store a config document reflecting the current keys. Returns the served document. */
  publishConfig(o: ConfigOverrides = {}): { payload: string; kid: string; sig: string } {
    const now = this.now();
    const seq = o.seq ?? this.cfgSeq + 1;
    this.cfgSeq = Math.max(this.cfgSeq, seq);
    const payload: Record<string, unknown> = {
      v: 1,
      seq,
      app: o.app ?? this.appId,
      iat: o.iat ?? now,
      exp: o.exp ?? now + 30 * 86400,
      sig_versions: [1],
      resp_keys: this.respKeys.map((k) => ({ kid: k.kid, alg: 'Ed25519', pub: k.pub, state: k.state, ...(k.nbf !== undefined ? { nbf: k.nbf } : {}), ...(k.naf !== undefined ? { naf: k.naf } : {}) })),
      pow: { alg: 'sha256-lz', bits: this.powBits, max_bits: 26 },
      clock: { max_skew: this.maxSkew },
      renew: { before_s: 86400, jitter: 0, backoff: [1, 2, 3] },
      retry: { replay: 1, unknown_device: 1, transient: 3 },
      unknown_future_field: { ignored: true },
      ...o.extra,
    };
    const raw = Buffer.from(JSON.stringify(payload), 'utf8');
    const sig = nodeSign(null, Buffer.concat([Buffer.from(`RESTRICTO-CFG-V1\n${o.app ?? this.appId}\n`), raw]), o.signWith ?? this.configKey.privateKey);
    this.configDoc = { payload: b64u(raw), kid: o.kid ?? this.configKid, sig: b64u(sig) };
    return this.configDoc;
  }

  private denied(status: number, code: number, extra: Record<string, unknown> = {}, headers: Record<string, string> = {}): Response {
    return new Response(JSON.stringify({ detail: 'Request denied.', error_type: 'denied', error_code: code, action: 'none', ...extra }), {
      status,
      headers: { 'content-type': 'application/json', ...headers },
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

  /** PoW bound to the key: SHA-256(challenge ":" hex(SHA-256(SPKI)) ":" n) with >= bits leading zero bits, n ASCII decimal <= 20 digits */
  private powOk(c: string, spki: Buffer, sol: unknown): boolean {
    if (typeof sol !== 'string' || !/^[0-9]{1,20}$/.test(sol)) return false;
    const d = createHash('sha256').update(`${c}:${sha256Hex(spki)}:${sol}`).digest();
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
    if (path.startsWith('/restricto/') && req.headers.get('X-APP-ID') !== this.appId) return this.denied(403, 458118);

    if (path === '/restricto/device/challenge/' && req.method === 'POST') {
      this.counts.challenge++;
      return Response.json({
        challenge: this.challenge(),
        expires_in: 120,
        server_time: this.now(),
        scheme: 'Restricto-Sig v1',
        sig_versions: [1],
        cfg_seq: this.cfgSeq,
        pow: { alg: 'sha256-lz', bits: this.announcedBits ?? this.powBits },
      });
    }
    if (path === '/restricto/device/register/' && req.method === 'POST') return this.register(req, url);
    if (path === '/restricto/keys/') {
      this.counts.keys++;
      const keys = this.respKeys.map((k) => ({ kid: k.kid, public_key: k.pub, state: k.state, ...(k.nbf !== undefined ? { nbf: k.nbf } : {}), ...(k.naf !== undefined ? { naf: k.naf } : {}) }));
      return Response.json({ alg: 'Ed25519', active_kid: this.active.kid, keys });
    }
    if (path === '/restricto/config/') {
      this.counts.config++;
      if (this.configOverride) return Response.json(this.configOverride.body ?? { detail: 'x' }, { status: this.configOverride.status });
      return this.configDoc ? Response.json(this.configDoc) : this.denied(404, 458118);
    }
    return this.protectedRoute(req, url);
  };

  private async register(req: Request, url: URL): Promise<Response> {
    this.counts.register++;
    const bytes = Buffer.from(await req.clone().arrayBuffer());
    const body = JSON.parse(bytes.toString('utf8')) as Record<string, any>;
    this.registeredBodies.push(body);
    // a renewal is itself a signed request; the reply (even a refusal) is signed under the claimed id and nonce
    let claim: { id: string; nonce: string } | undefined;
    if (body.renew === true) {
      this.counts.renew++;
      const p = parseSigHeader(req.headers.get('Restricto-Signature'));
      if (!p) return this.denied(401, 458021);
      claim = { id: p.id!, nonce: p.nonce! };
      const guard = await this.checkSignature(req, url, bytes, p);
      if (guard) return this.sign(guard, claim.id, claim.nonce, req.method);
      if (!this.renewSupported) return this.sign(this.denied(403, 458118), claim.id, claim.nonce, req.method);
    }
    const answer = (r: Response): Promise<Response> | Response => (claim ? this.sign(r, claim.id, claim.nonce, req.method) : r);
    if (this.banRegistrations) return answer(this.denied(403, 458118));
    if (body.platform !== 'web' || !this.challengeOk(body.challenge)) return answer(this.denied(403, 458118));
    if (!body.caps || !Array.isArray(body.caps.sig) || typeof body.caps.cfg !== 'number' || typeof body.renew !== 'boolean') return answer(this.denied(403, 458118));
    if (this.requireTurnstile && body.web?.turnstile_token !== 'ts-ok') return answer(this.denied(403, 458118));
    let spki: Buffer;
    let pub: KeyObject;
    try {
      spki = Buffer.from(body.public_key, 'base64url');
      pub = createPublicKey({ key: spki, format: 'der', type: 'spki' });
    } catch {
      return answer(this.denied(403, 458118));
    }
    if (!this.powOk(body.challenge, spki, body.web?.pow)) return answer(this.denied(403, 458118));
    const deviceId = 'rd_' + sha256Hex(spki).slice(0, 32);
    if (claim && claim.id !== deviceId) return answer(this.denied(403, 458118));
    const attestedUntil = this.now() + this.validitySeconds;
    this.devices.set(deviceId, { pub, attestedUntil, revoked: false });
    return answer(
      Response.json({ device_id: deviceId, trust_level: 1, platform: 'web', attested_until: attestedUntil, server_time: this.now(), max_clock_skew: this.maxSkew, scheme: 'Restricto-Sig v1', cfg_seq: this.cfgSeq }),
    );
  }

  /** skew -> device -> signature -> nonce -> body hash; returns a (not yet signed) denial or undefined */
  private async checkSignature(req: Request, url: URL, bodyBytes: Buffer, p: Record<string, string>, allowExpired = true): Promise<Response | undefined> {
    if (Math.abs(this.now() - Number(p.ts)) > this.maxSkew) return this.denied(401, 458052, { action: 'resync_clock', server_time: this.now() });
    const dev = this.devices.get(p.id!);
    if (!dev) return this.denied(401, 458033, { action: 'reregister' });
    if (dev.revoked) return this.denied(403, 458071, { action: 'wipe' });
    if (!allowExpired && dev.attestedUntil < this.now()) return this.denied(401, 458085, { action: 'reregister' });
    const canonical = ['RESTRICTO-SIG-V1', req.method.toUpperCase(), canonicalHostOf(url), canonicalTarget(url), p.ts, p.nonce, p.id, this.appId, p.bh, p.ext ?? ''].join('\n');
    const raw = Buffer.from(p.sig!, 'base64url');
    const ok = nodeVerify('sha256', Buffer.from(canonical), raw.length === 64 ? { key: dev.pub, dsaEncoding: 'ieee-p1363' } : dev.pub, raw);
    if (!ok) return this.denied(401, 458047);
    if (this.nonces.has(p.id! + p.nonce)) return this.denied(401, 458066);
    this.nonces.add(p.id! + p.nonce);
    if (sha256B64(bodyBytes) !== p.bh) return this.denied(401, 458047);
    return undefined;
  }

  private async protectedRoute(req: Request, url: URL): Promise<Response> {
    const header = req.headers.get('Restricto-Signature');
    const seen: Seen = { method: req.method, path: url.pathname + url.search, header: header ?? undefined, authorization: req.headers.get('Authorization'), host: url.host };
    this.seen.push(seen);
    this.counts.api++;
    if (this.proxyNext && this.proxyNext.remaining > 0) {
      this.proxyNext.remaining--;
      const pn = this.proxyNext;
      if (pn.looksLikeRestricto)
        return new Response(JSON.stringify({ detail: 'Request denied.', error_type: 'denied', error_code: 458071, action: 'wipe' }), { status: 403, headers: { 'content-type': 'application/json' } });
      return new Response(pn.body ?? '<html>bad gateway</html>', { status: pn.status, headers: { 'content-type': 'text/html' } });
    }
    const p = parseSigHeader(header);
    if (!p) return this.denied(401, 458021); // not signed: nothing to claim, so the answer is unsigned
    seen.nonce = p.nonce;
    const bodyBytes = Buffer.from(await req.arrayBuffer());
    const send = (r: Response): Promise<Response> => this.sign(r, p.id!, p.nonce!, req.method);
    if (this.failNext && this.failNext.remaining > 0) {
      this.failNext.remaining--;
      const f = this.failNext;
      return send(this.denied(f.status, f.code, { action: f.action ?? 'none', ...f.extra }, f.retryAfter ? { 'Retry-After': f.retryAfter } : {}));
    }
    if (this.redirectNext && this.redirectNext.remaining > 0) {
      this.redirectNext.remaining--;
      const r = new Response(null, { status: 302, headers: { Location: this.redirectNext.location } });
      return this.redirectNext.signed === false ? r : send(r);
    }
    const guard = await this.checkSignature(req, url, bodyBytes, p, false);
    if (guard) return send(guard);
    if (url.pathname === '/api/nocontent/') return send(new Response(null, { status: 204 }));
    if (req.method === 'HEAD') return send(new Response(null, { status: 200, headers: { 'content-type': 'application/json' } }));
    let status = 200;
    let payload: unknown = { ok: true, method: req.method, target: canonicalTarget(url), host: canonicalHostOf(url), body: bodyBytes.toString('utf8'), authorization: req.headers.get('Authorization') };
    if (url.pathname === '/api/missing/') {
      status = 404;
      payload = { detail: 'Not found.' };
    }
    return send(new Response(JSON.stringify(payload), { status, headers: { 'content-type': 'application/json' } }));
  }

  /** `Restricto-Response-Signature` for every response to a request that carried a parseable signature header */
  private async sign(res: Response, deviceId: string, nonce: string, method: string): Promise<Response> {
    const status = res.status;
    const noBody = method === 'HEAD' || status === 204 || status === 304 || (status >= 100 && status < 200);
    const bytes = res.body === null ? Buffer.alloc(0) : Buffer.from(await res.arrayBuffer());
    const headers = new Headers(res.headers);
    if (this.signResponses) {
      const fields: string[] = [...this.extraSigFields];
      const claimedNonce = this.replayResponseNonce && this.lastNonce ? this.lastNonce : nonce;
      for (const k of this.respKeys.filter((x) => x.state === 'active')) {
        const ts = String(this.now() + (this.staleResponseTs ? -1000 : 0));
        const canonical = ['RESTRICTO-RESP-V1', String(status), claimedNonce, deviceId, ts, sha256Hex(noBody ? Buffer.alloc(0) : bytes), headers.get('content-type') ?? '', headers.get('location') ?? '', headers.get('retry-after') ?? ''].join('\n');
        let sig = nodeSign(null, Buffer.from(canonical), k.priv);
        if (this.badSignature) sig = Buffer.from(sig.map((b, i) => (i === 0 ? b ^ 1 : b)));
        fields.push(`v=1,kid=${k.kid},alg=Ed25519,ts=${ts},sig=${b64u(sig)}`);
      }
      if (fields.length) headers.set('Restricto-Response-Signature', fields.join(', '));
    }
    this.lastNonce = nonce;
    const out = this.tamperBody ? Buffer.from(bytes.toString('utf8').replace('true', 'false')) : bytes;
    return new Response(res.body === null || status === 204 || status === 304 ? null : new Uint8Array(out), { status, headers });
  }
}
