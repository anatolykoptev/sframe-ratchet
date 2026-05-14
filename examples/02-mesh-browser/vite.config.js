import { defineConfig } from 'vite';

export default defineConfig({
  // No special config needed — Vite handles ESM and node_modules resolution.
  // The sframe-ratchet package is referenced as file:../.. from package.json.
});
