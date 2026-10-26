import { createPublicKey, verify as nodeVerify } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { bindingHash, canonicalHost, canonicalPath, canonicalQuery, canonicalRequest, canonicalResponse, requestTarget, sha256B64, sha256Hex, hostLine } from '../src/canonical';
import { Clock } from '../src/clock';
import { verifyConfigDocument } from '../src/config';
import { b64urlDecode, b64urlEncode, hex, utf8 } from '../src/encoding';
import { parseSignatureHeader } from '../src/header';
import { makeSearcher, solvePow } from '../src/pow';
import { signRequest } from '../src/sign';
import { createKeyResolver, ed25519Verify, parseResponseSignatures, verifyResponseSignature } from '../src/verify';

const V = JSON.parse(readFileSync('/Users/mac/Documents/funsol_projects/Restricto/docs/protocol_vectors.json', 'utf8'));
const APP: string = V.app_id;
const SPKI: string = V.keys.p256.spki_der_b64url;
const DEVICE: string = V.keys.p256.device_id;
const RESP_PUB: string = V.keys.ed25519_response.public_key_b64url;

const nodePub = (spki: string) => createPublicKey({ key: Buffer.from(spki, 'base64url'), format: 'der', type: 'spki' });

async function deviceKey(): Promise<CryptoKey> {
  return crypto.subtle.importKey('pkcs8', b64urlDecode(V.keys.p256.pkcs8_der_b64url) as unknown as BufferSource, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
}

describe('canonical_path', () => {
  it.each(V.canonical_path as Array<{ raw: string; canonical: string }>)('$raw -> $canonical', ({ raw, canonical }) => {
    expect(canonicalPath(raw)).toBe(canonical);
  });
});

describe('canonical_query', () => {
  it.each(V.canonical_query as Array<{ raw: string; canonical: string }>)('$raw -> $canonical', ({ raw, canonical }) => {
    expect(canonicalQuery(raw)).toBe(canonical);
  });
});

describe('canonical_host', () => {
  it.each(V.canonical_host as Array<{ host: string; scheme: string; canonical: string }>)('$host ($scheme) -> $canonical', ({ host, scheme, canonical }) => {
    expect(canonicalHost(host, scheme)).toBe(canonical);
  });
  it('a URL object yields the same host line', () => {
    expect(hostLine(new URL('https://API.Example.COM:443/x'))).toBe('api.example.com');
    expect(hostLine(new URL('http://localhost:8000/x'))).toBe('localhost:8000');
    expect(hostLine(new URL('https://[::1]:8443/x'))).toBe('[::1]:8443');
  });
});

describe('header_parse', () => {
  it.each(V.header_parse as Array<{ header: string; result: string; id?: string; ts?: string; nonce?: string; ext?: string }>)('$result: $header', (c) => {
    const out = parseSignatureHeader(c.header);
    expect(out.result).toBe(c.result);
    if (out.result === 'ok') {
      expect(out.params.id).toBe(c.id);
      expect(out.params.ts).toBe(c.ts);
      expect(out.params.nonce).toBe(c.nonce);
      expect(out.params.ext).toBe(c.ext);
    }
  });
});

describe('request_signature', () => {
  type Req = {
    name: string; method: string; host: string; raw_path: string; raw_query: string; app_id: string; body_utf8: string; body_hex?: string;
    ts: string; nonce: string; ext: string; canonical_string: string; canonical_target: string; body_sha256_b64url: string;
    signature_der_b64url: string; signature_raw_rs_b64url: string; header: string; header_raw_rs: string; now: number;
  };
  const urlOf = (r: { host: string; raw_path: string; raw_query: string }) => new URL(`https://${r.host}${r.raw_path}${r.raw_query ? '?' + r.raw_query : ''}`);
  const bodyOf = (r: { body_utf8: string; body_hex?: string }) => (r.body_hex ? new Uint8Array(Buffer.from(r.body_hex, 'hex')) : utf8(r.body_utf8));
  const canonicalOf = async (r: Req['host'] extends string ? any : never): Promise<string> =>
    canonicalRequest({ method: r.method, host: hostLine(urlOf(r)), target: requestTarget(urlOf(r)), ts: r.ts, nonce: r.nonce, deviceId: DEVICE, appId: r.app_id, bh: await sha256B64(bodyOf(r)), ext: r.ext });

  describe.each(V.request_signature.positive as Req[])('positive: $name', (c) => {
    it('target, body hash and canonical string match byte for byte', async () => {
      expect(requestTarget(urlOf(c))).toBe(c.canonical_target);
      expect(await sha256B64(bodyOf(c))).toBe(c.body_sha256_b64url);
      expect(await canonicalOf(c)).toBe(c.canonical_string);
      expect(canonicalRequest({ method: c.method, host: hostLine(urlOf(c)), target: c.canonical_target, ts: c.ts, nonce: c.nonce, deviceId: DEVICE, appId: c.app_id, bh: c.body_sha256_b64url, ext: c.ext })).toBe(c.canonical_string);
    });
    it('the vector header parses and both signature encodings verify against the canonical string', () => {
      expect(parseSignatureHeader(c.header).result).toBe('ok');
      expect(parseSignatureHeader(c.header_raw_rs).result).toBe('ok');
      expect(nodeVerify('sha256', Buffer.from(c.canonical_string), nodePub(SPKI), Buffer.from(c.signature_der_b64url, 'base64url'))).toBe(true);
      expect(nodeVerify('sha256', Buffer.from(c.canonical_string), { key: nodePub(SPKI), dsaEncoding: 'ieee-p1363' }, Buffer.from(c.signature_raw_rs_b64url, 'base64url'))).toBe(true);
    });
    it('signRequest reproduces the canonical string and header shape, with a signature that verifies', async () => {
      const out = await signRequest({ privateKey: await deviceKey(), deviceId: DEVICE, appId: c.app_id, clock: new Clock() }, c.method, urlOf(c), bodyOf(c), { ts: c.ts, nonce: c.nonce, ext: c.ext || undefined });
      expect(out.canonical).toBe(c.canonical_string);
      const parsed = parseSignatureHeader(out.headers['Restricto-Signature']);
      expect(parsed.result).toBe('ok');
      if (parsed.result !== 'ok') return;
      expect(parsed.params).toMatchObject({ id: DEVICE, ts: c.ts, nonce: c.nonce, bh: c.body_sha256_b64url });
      expect(parsed.params.ext).toBe(c.ext || undefined);
      const raw = Buffer.from(parsed.params.sig, 'base64url');
      expect(raw.length).toBe(64);
      expect(nodeVerify('sha256', Buffer.from(c.canonical_string), { key: nodePub(SPKI), dsaEncoding: 'ieee-p1363' }, raw)).toBe(true);
      expect(out.headers['X-APP-ID']).toBe(c.app_id);
    });
  });

  // An independent re-implementation of the server's verification order: parse -> skew -> signature -> body hash.
  async function reference(c: { header: string; request: any; now: number }): Promise<string> {
    const p = parseSignatureHeader(c.header);
    if (p.result !== 'ok') return p.result;
    if (Math.abs(c.now - Number(p.params.ts)) > V.request_signature.max_skew_seconds) return 'clock_skew';
    const r = c.request;
    // the server rebuilds the canonical string from what it received, not from what was signed
    const canonical = canonicalRequest({ method: r.method, host: r.host, target: requestTarget(urlOf(r)), ts: p.params.ts, nonce: p.params.nonce, deviceId: p.params.id, appId: r.app_id, bh: p.params.bh, ext: p.params.ext });
    const sig = Buffer.from(p.params.sig, 'base64url');
    const ok = nodeVerify('sha256', Buffer.from(canonical), sig.length === 64 ? { key: nodePub(SPKI), dsaEncoding: 'ieee-p1363' } : nodePub(SPKI), sig);
    if (!ok) return 'bad_signature';
    if ((await sha256B64(bodyOf(r))) !== p.params.bh) return 'body_mismatch';
    return 'accepted';
  }

  it.each(V.request_signature.negative as Array<{ name: string; reason: string; header: string; request: any; now: number }>)('negative: $name -> $reason', async (c) => {
    expect(await reference(c)).toBe(c.reason);
  });

  it('the positive vectors are accepted by the same reference (guards the harness)', async () => {
    for (const c of V.request_signature.positive as Req[]) expect(await reference({ header: c.header, request: c, now: c.now })).toBe('accepted');
  });
});

describe('response_signature', () => {
  type Resp = {
    name: string; request_method: string; status: number; body_utf8_as_produced: string; content_type: string; location: string; retry_after: string;
    request_nonce: string; device_id: string; ts: string; bytes_hashed_utf8: string; body_sha256_hex: string; canonical_string: string; signature_b64url: string; header: string;
  };
  const respond = (c: Resp, over: { header?: string; body?: string } = {}): Response => {
    const headers: Record<string, string> = { 'Restricto-Response-Signature': over.header ?? c.header };
    if (c.content_type) headers['Content-Type'] = c.content_type;
    if (c.location) headers.Location = c.location;
    if (c.retry_after) headers['Retry-After'] = c.retry_after;
    const nullBody = [204, 304].includes(c.status) || c.request_method === 'HEAD';
    // bytes, not a string: a string body would make Response invent a text/plain Content-Type
    return new Response(nullBody ? null : (utf8(over.body ?? c.body_utf8_as_produced) as unknown as BodyInit), { status: c.status, headers });
  };
  const ctx = (c: { request_nonce: string; device_id: string; ts: string; request_method?: string }, now = Number(c.ts), pub = RESP_PUB) => {
    const clock = new Clock();
    clock.offset = now - Math.floor(Date.now() / 1000);
    return { nonce: c.request_nonce, deviceId: c.device_id, method: c.request_method ?? 'GET', clock, keys: createKeyResolver({ pinned: { k1: pub } }) };
  };

  describe.each(V.response_signature.positive as Resp[])('positive: $name', (c) => {
    it('canonical string, header parse and signature (WebCrypto and noble)', async () => {
      expect(canonicalResponse({ status: c.status, nonce: c.request_nonce, deviceId: c.device_id, ts: c.ts, bodySha256Hex: await sha256Hex(utf8(c.bytes_hashed_utf8)), contentType: c.content_type, location: c.location, retryAfter: c.retry_after })).toBe(c.canonical_string);
      expect(parseResponseSignatures(c.header)).toEqual([{ kid: 'k1', alg: 'Ed25519', ts: c.ts, sig: c.signature_b64url }]);
      for (const fallback of [false, true]) {
        expect(await ed25519Verify(b64urlDecode(RESP_PUB), b64urlDecode(c.signature_b64url), utf8(c.canonical_string), fallback)).toBe(true);
        expect(await ed25519Verify(b64urlDecode(RESP_PUB), b64urlDecode(c.signature_b64url), utf8(c.canonical_string + 'x'), fallback)).toBe(false);
      }
    });
    it('verifyResponseSignature accepts the response (and its method/status rules) and rejects the usual mismatches', async () => {
      expect((await verifyResponseSignature(respond(c), ctx(c))).ok).toBe(true);
      expect((await verifyResponseSignature(respond(c), ctx({ ...c, request_nonce: 'BBBBBBBBBBBBBBBBBBBBBB' }))).ok).toBe(false);
      expect((await verifyResponseSignature(respond(c), ctx({ ...c, device_id: 'rd_0' }))).ok).toBe(false);
      expect((await verifyResponseSignature(respond(c), ctx(c, Number(c.ts) + 301))).ok).toBe(false);
      expect((await verifyResponseSignature(respond(c), ctx(c, Number(c.ts) - 301))).ok).toBe(false);
      expect((await verifyResponseSignature(respond(c), ctx(c, Number(c.ts) + 299))).ok).toBe(true);
    });
  });

  it('HEAD / 204 / 304 are signed over the empty body whatever was produced', async () => {
    const head = (V.response_signature.positive as Resp[]).find((p) => p.name === 'head_is_signed_over_the_empty_body')!;
    const withBody = new Response('this body is not hashed for HEAD', { status: 200, headers: { 'Restricto-Response-Signature': head.header, 'Content-Type': head.content_type } });
    expect((await verifyResponseSignature(withBody, ctx({ ...head, request_method: 'HEAD' }))).ok).toBe(true);
    expect((await verifyResponseSignature(withBody.clone(), ctx({ ...head, request_method: 'GET' }))).ok).toBe(false);
  });

  it.each(V.response_signature.negative as Array<{ name: string; claimed: { status: number; request_nonce: string; device_id: string; ts: string; content_type: string; location: string; retry_after: string; body_utf8: string }; signature_b64url: string; verifies: boolean }>)(
    'negative: $name does not verify',
    async (n) => {
      const c = n.claimed;
      const header = `v=1,kid=k1,alg=Ed25519,ts=${c.ts},sig=${n.signature_b64url}`;
      const headers: Record<string, string> = { 'Restricto-Response-Signature': header };
      if (c.content_type) headers['Content-Type'] = c.content_type;
      if (c.location) headers.Location = c.location;
      if (c.retry_after) headers['Retry-After'] = c.retry_after;
      const res = new Response(utf8(c.body_utf8) as unknown as BodyInit, { status: c.status, headers });
      expect(n.verifies).toBe(false);
      expect((await verifyResponseSignature(res, ctx({ request_nonce: c.request_nonce, device_id: c.device_id, ts: c.ts }))).ok).toBe(false);
    },
  );

  it('several signatures: any one that verifies with a known kid+alg wins; unknown algs and kids are ignored', async () => {
    const c = (V.response_signature.positive as Resp[])[0]!;
    const good = c.header;
    const unknownAlg = `v=1,kid=k1,alg=ML-DSA-44,ts=${c.ts},sig=${'A'.repeat(86)}`;
    const unknownKid = `v=1,kid=zz,alg=Ed25519,ts=${c.ts},sig=${c.signature_b64url}`;
    const bad = `v=1,kid=k1,alg=Ed25519,ts=${c.ts},sig=${'A'.repeat(86)}`;
    const futureVersion = `v=2,kid=k1,alg=Ed25519,ts=${c.ts},sig=${'A'.repeat(86)}`;
    for (const sep of [', ', ',']) {
      for (const h of [[unknownAlg, unknownKid, good], [bad, good], [good, bad], [futureVersion, good]]) {
        expect((await verifyResponseSignature(respond(c, { header: h.join(sep) }), ctx(c))).ok, h.join(sep)).toBe(true);
      }
      for (const h of [[unknownAlg], [unknownKid], [bad], [unknownAlg, unknownKid, bad], [futureVersion]]) {
        expect((await verifyResponseSignature(respond(c, { header: h.join(sep) }), ctx(c))).ok, h.join(sep)).toBe(false);
      }
    }
    expect(await verifyResponseSignature(respond(c, { header: '' }), ctx(c))).toMatchObject({ ok: false, kind: 'unsigned' });
    expect(await verifyResponseSignature(respond(c, { header: 'garbage' }), ctx(c))).toMatchObject({ ok: false, kind: 'unsigned' });
  });

  it('a key outside its nbf/naf window does not verify a response signed at that time', async () => {
    const c = (V.response_signature.positive as Resp[])[0]!;
    const mk = (nbf?: number, naf?: number) => ({
      ...ctx(c),
      keys: { get: async () => ({ kid: 'k1', pub: b64urlDecode(RESP_PUB), nbf, naf }) },
    });
    expect((await verifyResponseSignature(respond(c), mk(Number(c.ts) - 1000, undefined))).ok).toBe(true);
    expect((await verifyResponseSignature(respond(c), mk(Number(c.ts) + 1000, undefined))).ok).toBe(false);
    expect((await verifyResponseSignature(respond(c), mk(undefined, Number(c.ts) - 1000))).ok).toBe(false);
    expect((await verifyResponseSignature(respond(c), mk(undefined, Number(c.ts) + 1000))).ok).toBe(true);
  });
});

describe('config_document', () => {
  const D = V.config_document;
  const pins = { [D.kid]: D.config_public_key_b64url };

  it('signing input and signature match the independent computation', () => {
    const raw = Buffer.from(D.payload_b64url, 'base64url');
    expect(raw.toString('utf8')).toBe(D.payload_json);
    const input = Buffer.concat([Buffer.from(`RESTRICTO-CFG-V1\n${D.app}\n`), raw]);
    expect(input.toString('utf8')).toBe(D.signing_input_utf8);
    expect(D.document.sig).toBe(D.signature_b64url);
  });

  it('the positive document verifies and is parsed, clamped and unknown fields ignored', async () => {
    const out = await verifyConfigDocument(D.document, APP, pins);
    expect(out.ok).toBe(true);
    if (!out.ok) return;
    const c = out.values;
    expect(c).toMatchObject({ seq: 17, iat: 1700000000, exp: 1702592000, sigVersions: [1], maxSkew: 90, relaxVerify: true });
    expect(c.pow).toEqual({ bits: 16, maxBits: 26 });
    expect(c.renew).toEqual({ beforeS: 86400, jitter: 0.2, backoff: [5, 30, 300, 3600] });
    expect(c.retry).toEqual({ replay: 1, unknownDevice: 1, transient: 3 });
    expect(c.minSdk).toBe('1.0.0');
    expect(c.upgrade).toEqual({ mode: 'none', url: '' });
    expect(c.respKeys.map((k) => [k.kid, k.nbf, k.naf])).toEqual([['k1', 1699000000, undefined], ['k2', undefined, undefined]]);
    expect(hex(c.respKeys[0]!.pub)).toBe(hex(b64urlDecode(RESP_PUB)));
    // both implementations of Ed25519 agree
    expect((await verifyConfigDocument(D.document, APP, pins, true)).ok).toBe(true);
  });

  it.each(D.negative as Array<{ name: string; app: string; document: any }>)('negative: $name is rejected', async (n) => {
    expect((await verifyConfigDocument(n.document, n.app, pins)).ok).toBe(false);
  });

  it('any pinned key may verify; a document naming a different pinned key id still needs that key to match', async () => {
    const other = { 'cfg-other': Buffer.alloc(32, 9).toString('base64url'), [D.kid]: D.config_public_key_b64url };
    expect((await verifyConfigDocument(D.document, APP, other)).ok).toBe(true);
    expect((await verifyConfigDocument(D.document, APP, { [D.kid]: Buffer.alloc(32, 9).toString('base64url') })).ok).toBe(false);
  });

  it('values outside the compiled-in bounds are clamped', async () => {
    const wild = { v: 1, seq: 1, app: APP, exp: 9e9, pow: { bits: 99, max_bits: 99 }, clock: { max_skew: 99999 }, renew: { before_s: 1, jitter: 9, backoff: [0, 1e9] }, retry: { replay: 99, unknown_device: -4, transient: 99 }, upgrade: { mode: 'hard', url: 'javascript:alert(1)' } };
    const { generateKeyPairSync, sign } = await import('node:crypto');
    const kp = generateKeyPairSync('ed25519');
    const raw = Buffer.from(JSON.stringify(wild));
    const sig = sign(null, Buffer.concat([Buffer.from(`RESTRICTO-CFG-V1\n${APP}\n`), raw]), kp.privateKey);
    const pub = String(kp.publicKey.export({ format: 'jwk' }).x);
    const out = await verifyConfigDocument({ payload: raw.toString('base64url'), kid: 'w', sig: sig.toString('base64url') }, APP, { w: pub });
    expect(out.ok).toBe(true);
    if (!out.ok) return;
    expect(out.values.pow).toEqual({ bits: 26, maxBits: 26 });
    expect(out.values.maxSkew).toBe(300);
    expect(out.values.renew).toEqual({ beforeS: 300, jitter: 0.5, backoff: [1, 86400] });
    expect(out.values.retry).toEqual({ replay: 3, unknownDevice: 0, transient: 5 });
    expect(out.values.upgrade).toEqual({ mode: 'hard', url: '' });
  });
});

describe('pow', () => {
  type P = { challenge: string; spki_b64url: string; spki_sha256_hex?: string; bits: number; solution: string; valid: boolean; name?: string; leading_zero_bits?: number };
  const prefixOf = async (p: P) => utf8(`${p.challenge}:${hex(await (async () => new Uint8Array(await crypto.subtle.digest('SHA-256', b64urlDecode(p.spki_b64url) as unknown as BufferSource)))())}:`);

  it.each(V.pow as P[])('$name / bits=$bits solution=$solution valid=$valid', async (p) => {
    const keyHash = hex(new Uint8Array(await crypto.subtle.digest('SHA-256', b64urlDecode(p.spki_b64url) as unknown as BufferSource)));
    if (p.spki_sha256_hex) expect(keyHash).toBe(p.spki_sha256_hex);
    const search = makeSearcher();
    const prefix = await prefixOf(p);
    if (/^[0-9]{1,20}$/.test(p.solution)) {
      // only well-formed decimal strings can be produced by the solver; the search accepts exactly the valid ones
      expect(search(prefix, p.bits, Number(p.solution), 1) === Number(p.solution)).toBe(p.valid);
      if (p.valid) expect(await solvePow(p.challenge, keyHash, p.bits, { useWorker: false })).toBe(p.solution);
    } else expect(p.valid).toBe(false); // malformed solutions are the server's to refuse; the SDK only ever emits [0-9]+
  });

  it('the old challenge-only formula no longer solves the puzzle', async () => {
    const p = (V.pow as P[]).find((x) => x.name === 'old_challenge_only_formula')!;
    expect(p.valid).toBe(false);
  });
});

describe('binding', () => {
  it('H = SHA-256("RESTRICTO-BIND-V1" || C || SPKI) and the Play Integrity requestHash', async () => {
    const B = V.binding;
    const h = await bindingHash(B.challenge, b64urlDecode(B.spki_b64url));
    expect(hex(h)).toBe(B.H_hex);
    expect(b64urlEncode(h)).toBe(B.play_integrity_requestHash_b64url);
    expect(await sha256Hex(utf8(B.challenge))).toBe(B.C_sha256_of_challenge_utf8_hex);
  });
});
