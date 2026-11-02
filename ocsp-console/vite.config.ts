import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

/**
 * Vite dev-server configuration for the OCSP Admin Console.
 *
 * ─── API routing ────────────────────────────────────────────────────────────
 * All /api/** requests are proxied to the Spring Boot ocsp-admin-api service.
 *
 * Default target: http://localhost:8082 (local Spring Boot process).
 * Override via the VITE_API_BASE_URL environment variable:
 *
 *   VITE_API_BASE_URL=https://ocsp-admin.internal npm run dev
 *
 * ─── Authentication ──────────────────────────────────────────────────────────
 * The admin API requires a valid OIDC JWT Bearer token.  During local
 * development you can obtain a token from your OIDC provider (e.g. Keycloak)
 * and inject it in the Axios client (src/api/client.ts).
 *
 * For convenience, set VITE_DEV_BEARER_TOKEN to skip the login redirect during
 * local development only.  Never use this in production.
 */
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: process.env.VITE_API_BASE_URL || 'http://localhost:8082',
        changeOrigin: true,
        // Rewrite the path if needed (uncomment if the API is behind a prefix)
        // rewrite: (path) => path.replace(/^\/api/, ''),
      },
      // Dev token endpoint (local ocsp-auth). Used by src/api/client.ts in dev mode only.
      '/oauth2': {
        target: process.env.VITE_AUTH_BASE_URL || 'http://localhost:9000',
        changeOrigin: true,
      },
    },
  },
})
