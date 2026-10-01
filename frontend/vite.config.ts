import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// The Go API listens on :8000 and already allows http://localhost:5173 for CORS,
// but proxying keeps every request same-origin, including the SSE streams.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': { target: process.env.PRAHARI_API ?? 'http://localhost:8000', changeOrigin: true },
    },
  },
  build: {
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (/node_modules\/(framer-motion|motion-dom|motion-utils|lenis)\//.test(id)) return 'motion'
        },
      },
    },
  },
})
