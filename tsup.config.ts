import { defineConfig } from 'tsup';

export default defineConfig([
  {
    entry: { index: 'src/index.ts', react: 'src/react.tsx', vue: 'src/vue.ts' },
    format: ['esm', 'cjs'],
    dts: true,
    clean: false,
    target: 'es2020',
    external: ['react', 'react/jsx-runtime', 'vue', '@noble/curves', '@funsol/restricto-web'],
    // keep the noble fallback a separate lazily-loaded import in the ESM build
    splitting: true,
    sourcemap: true,
  },
  {
    // <script src> / UMD-style global `Restricto`; noble is bundled so the fallback also works without a bundler
    entry: { restricto: 'src/global.ts' },
    format: ['iife'],
    globalName: 'Restricto',
    minify: true,
    target: 'es2020',
    clean: false,
    splitting: false,
    noExternal: ['@noble/curves'],
  },
]);
