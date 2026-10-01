import react from '@vitejs/plugin-react'
import type { ServerResponse } from 'node:http'
import { createLogger, defineConfig } from 'vite'

// In development every /api request goes through this proxy to the Go API, so
// the browser stays same-origin (no CORS) including the SSE streams.
const API = process.env.PRAHARI_API ?? 'http://127.0.0.1:8000'
const HINT = `The Prahari API is not running at ${API}. Start it with ./dev.sh from the repo root, or: cd backend && go run ./cmd/api`

// When the API is down, Vite would print a full stack trace for every request
// (the live stream retries every few seconds). Print one short hint instead.
const logger = createLogger()
const logError = logger.error.bind(logger)
let lastHint = 0
logger.error = (msg, opts) => {
  if (msg.includes('http proxy error') && msg.includes('ECONNREFUSED')) {
    if (Date.now() - lastHint > 10_000) {
      lastHint = Date.now()
      logger.warn(HINT, { timestamp: true })
    }
    return
  }
  logError(msg, opts)
}

export default defineConfig({
  customLogger: logger,
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: API,
        changeOrigin: true,
        // Answer like the API would, so the sign-in page shows what to do.
        configure: (proxy) => {
          proxy.on('error', (_err, _req, res) => {
            const r = res as ServerResponse
            if (typeof r.writeHead !== 'function' || r.headersSent) return
            r.writeHead(503, { 'Content-Type': 'application/problem+json' })
            r.end(JSON.stringify({ title: 'API not running', status: 503, code: 'API_UNREACHABLE', detail: HINT }))
          })
        },
      },
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
