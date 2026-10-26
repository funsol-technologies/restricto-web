// Core size = src/index.ts bundled and minified with @noble/curves left external (it is lazily imported on demand).
import { gzipSync, brotliCompressSync } from 'node:zlib';
import { build } from 'esbuild';

async function measure(label, entry, external) {
  const out = await build({ entryPoints: [entry], bundle: true, minify: true, format: 'esm', target: 'es2020', write: false, external, legalComments: 'none' });
  const code = out.outputFiles[0].contents;
  console.log(`${label}: ${code.length} B min, ${gzipSync(code).length} B gzip, ${brotliCompressSync(code).length} B brotli`);
}

await measure('core (index, noble external)', 'src/index.ts', ['@noble/curves', '@noble/curves/*']);
await measure('react entry', 'src/react.tsx', ['react', 'react/jsx-runtime', '@noble/curves/*', '@funsol/restricto-web']);
await measure('vue entry', 'src/vue.ts', ['vue', '@funsol/restricto-web']);
await measure('global script with noble bundled', 'src/global.ts', []);
