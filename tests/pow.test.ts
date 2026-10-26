import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { makeSearcher, solvePow, type WorkerLike } from '../src/pow';

const KEY = 'ab'.repeat(32); // stands for hex(SHA-256(SPKI)) of the key being registered

/** leading zero bits of SHA-256(challenge ":" KEY ":" n) - the key-bound puzzle */
function zeroBits(challenge: string, n: string): number {
  const d = createHash('sha256').update(`${challenge}:${KEY}:${n}`).digest();
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

describe('proof of work', () => {
  it('matches Node SHA-256 across prefix lengths that hit every padding case and digit widths', () => {
    const search = makeSearcher();
    for (let len = 1; len < 140; len += 3) {
      const challenge = 'c'.repeat(len);
      const hit = search(new TextEncoder().encode(`${challenge}:${KEY}:`), 8, 0, 5000);
      expect(hit).toBeGreaterThanOrEqual(0);
      expect(zeroBits(challenge, String(hit))).toBeGreaterThanOrEqual(8);
      // and nothing earlier qualified
      for (let n = 0; n < hit; n++) expect(zeroBits(challenge, String(n))).toBeLessThan(8);
    }
    // digit width rollover (9 -> 10, 99 -> 100, ...) with a high threshold so the search spans them
    const big = search(new TextEncoder().encode(`width:${KEY}:`), 14, 0, 200000);
    expect(zeroBits('width', String(big))).toBeGreaterThanOrEqual(14);
  });

  it('solvePow returns a valid solution at 16 bits on the main thread, with progress', async () => {
    const progress: number[] = [];
    const started = performance.now();
    const sol = await solvePow('v1.bench.challenge.mac', KEY, 16, { useWorker: false, onProgress: (n) => progress.push(n) });
    const ms = performance.now() - started;
    expect(zeroBits('v1.bench.challenge.mac', sol)).toBeGreaterThanOrEqual(16);
    expect(ms).toBeLessThan(2000);
    console.log(`pow 16 bits main thread: ${ms.toFixed(1)} ms (solution ${sol})`);
  });

  it('benchmarks 20 bits (for the README)', async () => {
    const started = performance.now();
    const sol = await solvePow('v1.bench20.challenge.mac', KEY, 20, { useWorker: false });
    expect(zeroBits('v1.bench20.challenge.mac', sol)).toBeGreaterThanOrEqual(20);
    console.log(`pow 20 bits main thread: ${(performance.now() - started).toFixed(0)} ms`);
  });

  it('bits 0 is free; abort rejects', async () => {
    expect(await solvePow('x', KEY, 0)).toBe('0');
    const ac = new AbortController();
    const p = solvePow('abort-me', KEY, 26, { useWorker: false, signal: ac.signal });
    setTimeout(() => ac.abort(), 30);
    await expect(p).rejects.toMatchObject({ code: 'aborted' });
    await expect(solvePow('already', KEY, 8, { signal: ac.signal })).rejects.toMatchObject({ code: 'aborted' });
  });

  it('A-2: refuses more than 26 bits, and gives up after the wall-clock budget (main thread and worker)', async () => {
    await expect(solvePow('x', KEY, 27)).rejects.toThrow(RangeError);
    await expect(solvePow('x', KEY, 40)).rejects.toThrow(RangeError);
    const started = performance.now();
    await expect(solvePow('budget', KEY, 26, { useWorker: false, budgetMs: 80 })).rejects.toMatchObject({ code: 'register_failed', message: expect.stringMatching(/budget/) });
    expect(performance.now() - started).toBeLessThan(1500);
    // a worker that never answers is terminated when the budget is spent
    let terminated = false;
    const silent = (): WorkerLike => ({ onmessage: null, onerror: null, postMessage: () => undefined, terminate: () => void (terminated = true) });
    await expect(solvePow('budget2', KEY, 26, { createWorker: silent, budgetMs: 50 })).rejects.toMatchObject({ code: 'register_failed' });
    expect(terminated).toBe(true);
  });

  it('abort terminates a running worker', async () => {
    let terminated = false;
    const silent = (): WorkerLike => ({ onmessage: null, onerror: null, postMessage: () => undefined, terminate: () => void (terminated = true) });
    const ac = new AbortController();
    const p = solvePow('w-abort', KEY, 26, { createWorker: silent, signal: ac.signal });
    setTimeout(() => ac.abort(), 20);
    await expect(p).rejects.toMatchObject({ code: 'aborted' });
    expect(terminated).toBe(true);
  });

  it('the work is bound to the key: another key hash needs different work', async () => {
    const a = await solvePow('same-challenge', 'a'.repeat(64), 10, { useWorker: false });
    const b = await solvePow('same-challenge', 'b'.repeat(64), 10, { useWorker: false });
    const bitsFor = (key: string, n: string) => {
      const d = createHash('sha256').update(`same-challenge:${key}:${n}`).digest();
      let bits = 0;
      for (const x of d) {
        if (x === 0) bits += 8;
        else {
          bits += Math.clz32(x) - 24;
          break;
        }
      }
      return bits;
    };
    expect(bitsFor('a'.repeat(64), a)).toBeGreaterThanOrEqual(10);
    expect(bitsFor('b'.repeat(64), b)).toBeGreaterThanOrEqual(10);
    expect(a === b && bitsFor('a'.repeat(64), b) >= 10 && bitsFor('b'.repeat(64), a) >= 10).toBe(false);
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
    const sol = await solvePow(challenge, KEY, 14, { createWorker: fakeWorker });
    expect(zeroBits(challenge, sol)).toBeGreaterThanOrEqual(14);
  });

  it('falls back to the main thread when the worker cannot start (CSP)', async () => {
    const sol = await solvePow('v1.csp.mac', KEY, 10, {
      createWorker: () => {
        throw new Error('blocked by CSP');
      },
    });
    expect(zeroBits('v1.csp.mac', sol)).toBeGreaterThanOrEqual(10);
  });

  it('falls back when the worker errors asynchronously', async () => {
    const sol = await solvePow('v1.err.mac', KEY, 10, {
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
