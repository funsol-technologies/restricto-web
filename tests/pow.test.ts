import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { makeSearcher, solvePow, type WorkerLike } from '../src/pow';

const vectors = JSON.parse(readFileSync('/Users/mac/Documents/funsol_projects/Restricto/docs/web_vectors.json', 'utf8')) as {
  pow: Array<{ challenge: string; bits: number; solution: string; sha256_hex?: string; valid?: boolean }>;
};

function zeroBits(challenge: string, n: string): number {
  const d = createHash('sha256').update(`${challenge}:${n}`).digest();
  let bits = 0;
  for (const b of d) {
    if (b === 0) bits += 8;
    else {
      bits += Math.clz32(b) - 24;
      break;
    }
  }
  return bits;
}

describe('proof of work vectors', () => {
  const good = vectors.pow[0]!;
  const bad = vectors.pow[1]!;

  it('vector solution really has the claimed hash and the bad one is rejected by an independent check', () => {
    expect(createHash('sha256').update(`${good.challenge}:${good.solution}`).digest('hex')).toBe(good.sha256_hex);
    expect(zeroBits(good.challenge, good.solution)).toBeGreaterThanOrEqual(good.bits);
    expect(zeroBits(bad.challenge, bad.solution)).toBeLessThan(bad.bits);
  });

  it('our searcher accepts the vector solution and the first hit from 0 is the vector solution', () => {
    const search = makeSearcher();
    const prefix = new TextEncoder().encode(`${good.challenge}:`);
    expect(search(prefix, good.bits, Number(good.solution), 1)).toBe(Number(good.solution));
    expect(search(prefix, bad.bits, Number(bad.solution), 1)).toBe(-1);
    expect(search(prefix, good.bits, 0, 100000)).toBe(Number(good.solution));
  });

  it('matches Node SHA-256 across prefix lengths that hit every padding case and digit widths', () => {
    const search = makeSearcher();
    for (let len = 1; len < 140; len += 3) {
      const challenge = 'c'.repeat(len);
      const hit = search(new TextEncoder().encode(`${challenge}:`), 8, 0, 5000);
      expect(hit).toBeGreaterThanOrEqual(0);
      expect(zeroBits(challenge, String(hit))).toBeGreaterThanOrEqual(8);
      // and nothing earlier qualified
      for (let n = 0; n < hit; n++) expect(zeroBits(challenge, String(n))).toBeLessThan(8);
    }
    // digit width rollover (9 -> 10, 99 -> 100, ...) with a high threshold so the search spans them
    const big = search(new TextEncoder().encode('width:'), 14, 0, 200000);
    expect(zeroBits('width', String(big))).toBeGreaterThanOrEqual(14);
  });

  it('solvePow returns a valid solution at 16 bits on the main thread, with progress', async () => {
    const progress: number[] = [];
    const started = performance.now();
    const sol = await solvePow('v1.bench.challenge.mac', 16, { useWorker: false, onProgress: (n) => progress.push(n) });
    const ms = performance.now() - started;
    expect(zeroBits('v1.bench.challenge.mac', sol)).toBeGreaterThanOrEqual(16);
    expect(ms).toBeLessThan(2000);
    console.log(`pow 16 bits main thread: ${ms.toFixed(1)} ms (solution ${sol})`);
  });

  it('benchmarks 20 bits (for the README)', async () => {
    const started = performance.now();
    const sol = await solvePow('v1.bench20.challenge.mac', 20, { useWorker: false });
    expect(zeroBits('v1.bench20.challenge.mac', sol)).toBeGreaterThanOrEqual(20);
    console.log(`pow 20 bits main thread: ${(performance.now() - started).toFixed(0)} ms`);
  });

  it('bits 0 is free; abort rejects', async () => {
    expect(await solvePow('x', 0)).toBe('0');
    const ac = new AbortController();
    const p = solvePow('abort-me', 40, { useWorker: false, signal: ac.signal });
    setTimeout(() => ac.abort(), 30);
    await expect(p).rejects.toMatchObject({ code: 'aborted' });
  });
});

describe('worker path', () => {
  /** Runs the exact worker source in-process with the same message protocol a browser Worker uses. */
  function fakeWorker(source: string): WorkerLike {
    const self: { onmessage?: (e: { data: unknown }) => void; postMessage: (m: unknown) => void } = {
      postMessage: (m) => queueMicrotask(() => w.onmessage?.({ data: m as never })),
    };
    new Function('self', source)(self);
    const w: WorkerLike = {
      onmessage: null,
      onerror: null,
      postMessage: (m) => self.onmessage?.({ data: m }),
      terminate: () => undefined,
    };
    return w;
  }

  it('the inline worker source is self-contained and solves', async () => {
    const challenge = 'v1.worker.test.mac';
    const sol = await solvePow(challenge, 14, { createWorker: fakeWorker });
    expect(zeroBits(challenge, sol)).toBeGreaterThanOrEqual(14);
  });

  it('falls back to the main thread when the worker cannot start (CSP)', async () => {
    const sol = await solvePow('v1.csp.mac', 10, {
      createWorker: () => {
        throw new Error('blocked by CSP');
      },
    });
    expect(zeroBits('v1.csp.mac', sol)).toBeGreaterThanOrEqual(10);
  });

  it('falls back when the worker errors asynchronously', async () => {
    const sol = await solvePow('v1.err.mac', 10, {
      createWorker: () => {
        const w: WorkerLike = {
          onmessage: null,
          onerror: null,
          postMessage: () => queueMicrotask(() => w.onerror?.(new Error('boom'))),
          terminate: () => undefined,
        };
        return w;
      },
    });
    expect(zeroBits('v1.err.mac', sol)).toBeGreaterThanOrEqual(10);
  });
});
