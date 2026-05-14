import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    worker: 'src/worker.ts',
  },
  format: ['esm'],
  dts: true,
  clean: true,
  target: 'es2022',
  outDir: 'dist',
});
