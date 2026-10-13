// Builds the embedded page with stable asset names.
// API transport belongs to src/api; component tests use src/test/setup.ts.
// Read the build and test settings first.

import path from 'node:path'
import { classTables } from './build/classes.ts'
import babel from '@rolldown/plugin-babel'
import tailwindcss from '@tailwindcss/vite'
import react, { reactCompilerPreset } from '@vitejs/plugin-react'
import { defineConfig } from 'vitest/config'

export default defineConfig(({ command, mode }) => ({
  // DEV follows NODE_ENV, which can be inherited even by vite build; use the command instead.
  define: {
    'import.meta.env.NETMON_INCLUDE_MOCK': JSON.stringify(
      command === 'serve' || mode === 'mock' ? '1' : '0',
    ),
  },
  plugins: [
    react(),
    // The compiler handles memoisation without hand-written cache hooks.
    babel({ presets: [reactCompilerPreset()] }),
    tailwindcss(),
    classTables(),
  ],
  resolve: {
    alias: { '@': path.resolve(import.meta.dirname, './src') },
  },
  server: { proxy: { '/api': 'http://127.0.0.1:7979' } },
  build: {
    // Only the explicit mock build may carry fixtures; netmon embeds dist, not dist-mock.
    outDir: mode === 'mock' ? 'dist-mock' : 'dist',
    modulePreload: { polyfill: false },
    rolldownOptions: {
      output: {
        entryFileNames: 'assets/app.js',
        chunkFileNames: 'assets/[name].js',
        assetFileNames: ({ names }) =>
          names.some((name) => name.endsWith('.css')) ? 'assets/app.css' : 'assets/[name][extname]',
      },
    },
  },
  // Four workers leave memory available for the owner's other applications.
  test: { environment: 'jsdom', setupFiles: ['./src/test/setup.ts'], maxWorkers: 4 },
}))
