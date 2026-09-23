import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, '.', '')
  const authnTarget = env.AUTHGUARD_AUTHN_TARGET || 'http://127.0.0.1:8082'
  const authzTarget = env.AUTHGUARD_AUTHZ_TARGET || 'http://127.0.0.1:9090'
  return {
    // The production gateway reserves this namespace for Hosted Login assets.
    // Dashboard routes continue to resolve from `/` in the same SPA.
    base: '/auth/',
    plugins: [react()],
    server: {
      port: 4173,
      proxy: {
        '^/auth/(?!login(?:/|$)|account/security(?:/|$)|assets/)': authnTarget,
        '/.well-known': authnTarget,
        '/api': authzTarget,
      },
    },
  }
})
