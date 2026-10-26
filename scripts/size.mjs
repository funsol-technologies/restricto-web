// Core size = everything the entry loads eagerly (its static-import closure) when bundled and minified with code splitting.
// The lazily-imported pieces - proof of work, config document parser, @noble/curves Ed25519 fallback (external) - are listed
// separately, not counted in the core.
import { brotliCompressSync, gzipSync } from 'node:zlib';
import { build } from 'esbuild';

const size = (label, bytes) =>
  console.log(`${label.padEnd(46)} ${String(bytes.length).padStart(6)} B min  ${String(gzipSync(bytes).length).padStart(6)} B gzip  ${String(brotliCompressSync(bytes).length).padStart(6)} B brotli`);

async function measure(label, entry, external) {
  const out = await build({
    entryPoints: [entry], bundle: true, minify: true, format: 'esm', target: 'es2020', splitting: true, outdir: 'out', write: false, external, legalComments: 'none', metafile: true, entryNames: '[name]', chunkNames: 'chunk-[hash]',
  });
  const files = new Map(out.outputFiles.map((f) => [f.path.replace(/.*\/out\//, 'out/'), f]));
  const meta = out.metafile.outputs;
  const entryKey = [...files.keys()].find((k) => meta[k].entryPoint);
  const eager = new Set();
  const walk = (k) => {
    if (eager.has(k)) return;
    eager.add(k);
    for (const i of meta[k].imports) if (i.kind === 'import-statement' && meta[i.path]) walk(i.path);
  };
  walk(entryKey);
  const core = Buffer.concat([...eager].map((k) => Buffer.from(files.get(k).contents)));
  size(`${label} (always loaded)`, core);
  for (const [k, f] of files) {
    if (eager.has(k)) continue;
    const text = f.text;
    const what = /RESTRICTO-CFG-V1/.test(text) ? 'config document parser' : /sha256-lz|makeSearcher|search\(/.test(text) || text.includes('Proof of work') ? 'proof of work' : 'other';
    size(`  lazy chunk: ${what}`, f.contents);
  }
}

await measure('CORE index', 'src/index.ts', ['@noble/curves', '@noble/curves/*']);
await measure('react entry', 'src/react.tsx', ['react', 'react/jsx-runtime', '@noble/curves/*', '@funsol/restricto-web']);
await measure('vue entry', 'src/vue.ts', ['vue', '@funsol/restricto-web']);
const g = await build({ entryPoints: ['src/global.ts'], bundle: true, minify: true, format: 'iife', target: 'es2020', write: false, legalComments: 'none' });
size('global script (all in one, noble bundled)', g.outputFiles[0].contents);
