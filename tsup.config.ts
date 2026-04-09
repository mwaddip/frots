import { defineConfig } from 'tsup';

export default defineConfig({
  entry: { 'secp256k1-tr/index': 'src/secp256k1-tr/index.ts' },
  format: ['esm'],
  dts: true,
  clean: true,
  outDir: 'dist',
  splitting: false,
  sourcemap: true,
});
