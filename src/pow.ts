import { abortError } from './errors';

/**
 * Self-contained on purpose: `makeSearcher.toString()` is the source of the inline worker, so it must not reference
 * anything outside its own body. Midstate SHA-256: whole 64-byte blocks of "<challenge>:" are compressed once, each
 * candidate then costs one or two compressions. Returns the first n in [from, from+count) with >= bits leading zero
 * bits, else -1.
 */
export function makeSearcher(): (prefix: Uint8Array, bits: number, from: number, count: number) => number {
  const K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
    0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
    0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ]);
  const IV = new Uint32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
  const w = new Uint32Array(64);

  function compress(s: Uint32Array, b: Uint8Array, o: number): void {
    for (let i = 0; i < 16; i++) {
      const j = o + i * 4;
      w[i] = ((b[j]! << 24) | (b[j + 1]! << 16) | (b[j + 2]! << 8) | b[j + 3]!) >>> 0;
    }
    for (let i = 16; i < 64; i++) {
      const a = w[i - 15]!;
      const c = w[i - 2]!;
      const s0 = ((a >>> 7) | (a << 25)) ^ ((a >>> 18) | (a << 14)) ^ (a >>> 3);
      const s1 = ((c >>> 17) | (c << 15)) ^ ((c >>> 19) | (c << 13)) ^ (c >>> 10);
      w[i] = (w[i - 16]! + s0 + w[i - 7]! + s1) | 0;
    }
    let a = s[0]!, b1 = s[1]!, c = s[2]!, d = s[3]!, e = s[4]!, f = s[5]!, g = s[6]!, h = s[7]!;
    for (let i = 0; i < 64; i++) {
      const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
      const t1 = (h + S1 + ((e & f) ^ (~e & g)) + K[i]! + w[i]!) | 0;
      const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
      const t2 = (S0 + ((a & b1) ^ (a & c) ^ (b1 & c))) | 0;
      h = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b1; b1 = a; a = (t1 + t2) | 0;
    }
    s[0] = (s[0]! + a) | 0; s[1] = (s[1]! + b1) | 0; s[2] = (s[2]! + c) | 0; s[3] = (s[3]! + d) | 0;
    s[4] = (s[4]! + e) | 0; s[5] = (s[5]! + f) | 0; s[6] = (s[6]! + g) | 0; s[7] = (s[7]! + h) | 0;
  }

  return function search(prefix, bits, from, count) {
    const mid = new Uint32Array(IV);
    const st = new Uint32Array(8);
    const full = prefix.length - (prefix.length % 64);
    for (let o = 0; o < full; o += 64) compress(mid, prefix, o);
    const tail = prefix.length - full;
    const buf = new Uint8Array(192);
    buf.set(prefix.subarray(full), 0);
    const end = from + count;
    for (let n = from; n < end; n++) {
      let digits = 1;
      for (let t = n; t >= 10; t = Math.floor(t / 10)) digits++;
      const p = tail + digits;
      for (let i = p - 1, x = n; i >= tail; i--, x = Math.floor(x / 10)) buf[i] = 48 + (x % 10);
      const size = (p + 9 + 63) & ~63;
      buf[p] = 0x80;
      buf.fill(0, p + 1, size);
      const bitLen = (full + p) * 8;
      const hi = Math.floor(bitLen / 4294967296);
      const lo = bitLen >>> 0;
      buf[size - 8] = hi >>> 24; buf[size - 7] = hi >>> 16; buf[size - 6] = hi >>> 8; buf[size - 5] = hi;
      buf[size - 4] = lo >>> 24; buf[size - 3] = lo >>> 16; buf[size - 2] = lo >>> 8; buf[size - 1] = lo;
      st.set(mid);
      for (let o = 0; o < size; o += 64) compress(st, buf, o);
      const h0 = st[0]!;
      if (bits <= 32) {
        if (Math.clz32(h0) >= bits) return n;
      } else if (h0 === 0 && Math.clz32(st[1]!) >= bits - 32) return n;
    }
    return -1;
  };
}

const WORKER_SOURCE =
  `var search=(${makeSearcher.toString()})();` +
  `self.onmessage=function(e){var d=e.data,p=new TextEncoder().encode(d.prefix),from=0,step=d.step;` +
  `for(;;){var r=search(p,d.bits,from,step);if(r>=0){self.postMessage({found:String(r)});return}from+=step;self.postMessage({tried:from})}};`;

export interface WorkerLike {
  onmessage: ((e: { data: { found?: string; tried?: number } }) => void) | null;
  onerror: ((e: unknown) => void) | null;
  postMessage(msg: unknown): void;
  terminate(): void;
}

export interface PowOptions {
  signal?: AbortSignal;
  onProgress?: (attempts: number) => void;
  /** false forces the main thread (used by tests and strict-CSP pages). */
  useWorker?: boolean;
  /** Test seam: build a worker from its source text. */
  createWorker?: (source: string) => WorkerLike;
}

const CHUNK = 20000;

function defaultWorker(source: string): WorkerLike | undefined {
  if (typeof Worker === 'undefined' || typeof Blob === 'undefined' || typeof URL === 'undefined' || !URL.createObjectURL) return undefined;
  const url = URL.createObjectURL(new Blob([source], { type: 'text/javascript' }));
  try {
    return new Worker(url) as unknown as WorkerLike;
  } finally {
    URL.revokeObjectURL(url);
  }
}

function solveInWorker(worker: WorkerLike, prefix: string, bits: number, o: PowOptions): Promise<string> {
  return new Promise((resolve, reject) => {
    const done = (fn: () => void): void => {
      o.signal?.removeEventListener('abort', onAbort);
      worker.terminate();
      fn();
    };
    const onAbort = (): void => done(() => reject(abortError()));
    o.signal?.addEventListener('abort', onAbort);
    worker.onmessage = (e) => {
      if (e.data.found !== undefined) {
        const found = e.data.found;
        done(() => resolve(found));
      } else if (e.data.tried !== undefined) o.onProgress?.(e.data.tried);
    };
    worker.onerror = (e) => done(() => reject(e instanceof Error ? e : new Error('pow worker failed')));
    worker.postMessage({ prefix, bits, step: CHUNK * 5 });
  });
}

const tick = (): Promise<void> => new Promise((r) => setTimeout(r, 0));

async function solveOnMainThread(prefix: string, bits: number, o: PowOptions): Promise<string> {
  const search = makeSearcher();
  const bytes = new TextEncoder().encode(prefix);
  for (let from = 0; ; from += CHUNK) {
    if (o.signal?.aborted) throw abortError();
    const hit = search(bytes, bits, from, CHUNK);
    if (hit >= 0) return String(hit);
    o.onProgress?.(from + CHUNK);
    await tick();
  }
}

/**
 * Find a decimal string n so SHA-256(challenge + ":" + n) has >= bits leading zero bits. The main-thread loop is the
 * fallback when Workers or `blob:` workers (CSP) are unavailable; a worker that fails to start also falls back.
 */
export async function solvePow(challenge: string, bits: number, o: PowOptions = {}): Promise<string> {
  if (!(bits > 0)) return '0';
  if (bits > 40) throw new RangeError('pow_bits too large');
  if (o.signal?.aborted) throw abortError();
  const prefix = challenge + ':';
  if (o.useWorker !== false) {
    let worker: WorkerLike | undefined;
    try {
      worker = (o.createWorker ?? defaultWorker)(WORKER_SOURCE);
    } catch {
      worker = undefined;
    }
    if (worker) {
      try {
        return await solveInWorker(worker, prefix, bits, o);
      } catch (e) {
        if (e instanceof Error && e.name === 'RestrictoError') throw e;
      }
    }
  }
  return solveOnMainThread(prefix, bits, o);
}
