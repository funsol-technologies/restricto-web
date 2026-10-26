import { createHash, createPublicKey, verify as nodeVerify } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { canonicalRequest, canonicalResponse, requestTarget, sha256Hex } from '../src/canonical';
import { Clock } from '../src/clock';
import { b64urlDecode, b64urlEncode, utf8 } from '../src/encoding';
import { signRequest } from '../src/sign';
import { createKeyResolver, ed25519Verify, verifyResponseSignature } from '../src/verify';

const V = JSON.parse(readFileSync('/Users/mac/Documents/funsol_projects/Restricto/docs/test_vectors.json', 'utf8'));
const rq = V.request_signing;
const rs = V.response_signing;

async function vectorPrivateKey(): Promise<CryptoKey> {
  const spki = b64urlDecode(rq.public_key_spki_b64url);
  const point = spki.subarray(spki.length - 65);
  const d = Buffer.from(rq.p256_private_key_hex, 'hex');
  return crypto.subtle.importKey(
    'jwk',
    { kty: 'EC', crv: 'P-256', d: b64urlEncode(d), x: b64urlEncode(point.subarray(1, 33)), y: b64urlEncode(point.subarray(33, 65)) },
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign'],
  );
}

describe('request signing vector', () => {
  const url = new URL(`https://api.example.com${rq.path}?${rq.query}`);

  it('request target is built exactly as the vector says', () => {
    expect(requestTarget(url)).toBe(rq.request_target);
  });

  it('body hash and canonical string match byte-for-byte', async () => {
    expect(await sha256Hex(utf8(rq.body))).toBe(rq.body_sha256_hex);
    const canonical = canonicalRequest({
      method: rq.method.toLowerCase(), // method is upper-cased by the SDK
      target: rq.request_target,
      ts: rq.ts,
      nonce: rq.nonce,
      deviceId: rq.device_id,
      appId: rq.package_name,
      bodySha256Hex: rq.body_sha256_hex,
    });
    expect(canonical).toBe(rq.canonical_string);
    expect(Buffer.from(canonical).equals(Buffer.from(rq.canonical_string))).toBe(true);
  });

  it('the vector device id is derived from the SPKI the way the server does it (sanity for the key material)', () => {
    const spki = Buffer.from(rq.public_key_spki_b64url, 'base64url');
    expect('rd_' + createHash('sha256').update(spki).digest('hex').slice(0, 32)).toBe(rq.device_id);
  });

  it('signRequest with the vector key produces the vector canonical string, header shape, and a signature that verifies', async () => {
    const out = await signRequest(
      { privateKey: await vectorPrivateKey(), deviceId: rq.device_id, appId: rq.package_name, clock: new Clock() },
      rq.method,
      url,
      utf8(rq.body),
      { ts: rq.ts, nonce: rq.nonce },
    );
    expect(out.canonical).toBe(rq.canonical_string);
    const m = /^Restricto-Sig v1 id=([^,]+),ts=(\d+),nonce=([^,]+),sig=([A-Za-z0-9_-]+)$/.exec(out.headers.Authorization);
    expect(m).not.toBeNull();
    expect(m![1]).toBe(rq.device_id);
    expect(m![3]).toBe(rq.nonce);
    expect(out.headers['X-APP-ID']).toBe(rq.package_name);
    const sig = Buffer.from(m![4]!, 'base64url');
    expect(sig.length).toBe(64); // raw r||s
    const pub = createPublicKey({ key: Buffer.from(rq.public_key_spki_b64url, 'base64url'), format: 'der', type: 'spki' });
    expect(nodeVerify('sha256', Buffer.from(rq.canonical_string), { key: pub, dsaEncoding: 'ieee-p1363' }, sig)).toBe(true);
    // and it is not a signature over something else
    expect(nodeVerify('sha256', Buffer.from(rq.canonical_string + 'x'), { key: pub, dsaEncoding: 'ieee-p1363' }, sig)).toBe(false);
  });

  it('the vector\'s own DER signature verifies under the same path (guards the test harness)', () => {
    const pub = createPublicKey({ key: Buffer.from(rq.public_key_spki_b64url, 'base64url'), format: 'der', type: 'spki' });
    expect(nodeVerify('sha256', Buffer.from(rq.canonical_string), pub, Buffer.from(rq.signature_b64url_der, 'base64url'))).toBe(true);
  });
});

describe('request target edge cases', () => {
  const t = (s: string): string => requestTarget(new URL(s));
  it('keeps only unreserved and "/" raw, upper-case hex, query verbatim', () => {
    expect(t('https://a.com')).toBe('/');
    expect(t('https://a.com/a b/c')).toBe('/a%20b/c');
    expect(t('https://a.com/a+b')).toBe('/a%2Bb');
    expect(t('https://a.com/a%2fb')).toBe('/a/b'); // the server decodes before quoting
    expect(t('https://a.com/%c3%bc/~-._')).toBe('/%C3%BC/~-._');
    expect(t('https://a.com/ü')).toBe('/%C3%BC');
    expect(t('https://a.com/x?')).toBe('/x');
    expect(t('https://a.com/x?a=1&b=%7e#frag')).toBe('/x?a=1&b=%7e');
  });
});

describe('response signing vector', () => {
  const pub = b64urlDecode(rs.ed25519_public_key_b64url);
  const message = utf8(rs.canonical_string);

  it('canonical response string matches and body hash matches', async () => {
    expect(canonicalResponse({ status: rs.status, nonce: rs.request_nonce, deviceId: rs.device_id, ts: rs.resp_ts, bodySha256Hex: rs.body_sha256_hex })).toBe(rs.canonical_string);
    expect(await sha256Hex(utf8(rs.body))).toBe(rs.body_sha256_hex);
  });

  it.each([
    ['WebCrypto (when present)', false],
    ['@noble/curves fallback', true],
  ])('verifies the vector with %s and rejects tampering', async (_n, fallback) => {
    const sig = b64urlDecode(rs.signature_b64url);
    expect(await ed25519Verify(pub, sig, message, fallback)).toBe(true);
    expect(await ed25519Verify(pub, sig, utf8(rs.canonical_string + '!'), fallback)).toBe(false);
    const bad = sig.slice();
    bad[3] = bad[3]! ^ 1;
    expect(await ed25519Verify(pub, bad, message, fallback)).toBe(false);
  });

  const respond = (over: Record<string, string> = {}, body = rs.body, status = rs.status): Response =>
    new Response(body, {
      status,
      headers: { 'X-Restricto-Resp-Kid': 'k1', 'X-Restricto-Resp-Ts': rs.resp_ts, 'X-Restricto-Resp-Sig': rs.signature_b64url, ...over },
    });
  const ctx = (nonce = rs.request_nonce, now = Number(rs.resp_ts)) => {
    const clock = new Clock();
    clock.offset = now - Math.floor(Date.now() / 1000);
    return { nonce, deviceId: rs.device_id, clock, keys: createKeyResolver({ k1: rs.ed25519_public_key_b64url }, async () => ({})) };
  };

  it('verifyResponseSignature accepts the vector and rejects each kind of mismatch', async () => {
    expect((await verifyResponseSignature(respond(), ctx())).ok).toBe(true);
    expect((await verifyResponseSignature(respond({}, '{"ok":false}'), ctx())).ok).toBe(false); // body
    expect((await verifyResponseSignature(respond(), ctx('AAAAAAAAAAAAAAAAAAAAAA'))).ok).toBe(false); // nonce
    expect((await verifyResponseSignature(respond({}, rs.body, 201), ctx())).ok).toBe(false); // status
    expect((await verifyResponseSignature(respond({ 'X-Restricto-Resp-Kid': 'k9' }), ctx())).ok).toBe(false); // kid
    expect((await verifyResponseSignature(respond(), ctx(rs.request_nonce, Number(rs.resp_ts) + 301))).ok).toBe(false); // too old
    expect((await verifyResponseSignature(respond(), ctx(rs.request_nonce, Number(rs.resp_ts) - 301))).ok).toBe(false); // too new
    expect((await verifyResponseSignature(respond(), ctx(rs.request_nonce, Number(rs.resp_ts) + 299))).ok).toBe(true);
    const unsigned = await verifyResponseSignature(new Response(rs.body), ctx());
    expect(unsigned).toMatchObject({ ok: false, unsigned: true });
  });
});
