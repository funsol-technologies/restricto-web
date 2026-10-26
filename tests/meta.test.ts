import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';
import { build } from 'esbuild';
import { describe, expect, it } from 'vitest';
import { SDK_VERSION } from '../src';

describe('package metadata', () => {
  it('SDK_VERSION equals the package version', () => {
    expect(SDK_VERSION).toBe(JSON.parse(readFileSync('package.json', 'utf8')).version);
  });
});

describe('global (<script>) build', () => {
  async function bundle(): Promise<string> {
    const out = await build({ entryPoints: ['src/global.ts'], bundle: true, format: 'iife', target: 'es2020', write: false, minify: true });
    return out.outputFiles[0]!.text;
  }
  const run = (code: string, attr: string | null) => {
    const sandbox: Record<string, unknown> = {
      document: { currentScript: { getAttribute: (n: string) => (n === 'data-restricto-global' ? attr : null) } },
      TextEncoder,
      TextDecoder,
      URL,
      Headers,
      crypto,
      console,
    };
    sandbox.globalThis = sandbox;
    runInNewContext(code, sandbox);
    return sandbox;
  };

  it('attaches nothing to the global object unless the script tag opts in', async () => {
    const code = await bundle();
    const before = run(code, null);
    expect(Object.keys(before).sort()).toEqual(['TextDecoder', 'TextEncoder', 'URL', 'Headers', 'console', 'crypto', 'document', 'globalThis'].sort());
    expect('Restricto' in before).toBe(false);
    expect('createRestricto' in before).toBe(false);
  });

  it('exposes the API under the name given in data-restricto-global (and refuses odd names)', async () => {
    const code = await bundle();
    const sb = run(code, 'MySecureName');
    expect(Object.keys(sb.MySecureName as object).sort()).toEqual(['RestrictoError', 'createRestricto', 'restrictoAxios', 'solvePow']);
    expect('Restricto' in sb).toBe(false);
    expect('x' in run(code, 'a.b; evil()')).toBe(false);
  });
});
