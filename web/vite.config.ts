import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'
import { federation as authguard_federation } from '@module-federation/vite'

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, '.', '')
  const authnTarget = env.AUTHGUARD_AUTHN_TARGET || 'http://127.0.0.1:8082'
  const authzTarget = env.AUTHGUARD_AUTHZ_TARGET || 'http://127.0.0.1:9090'
  return {
    // The production gateway reserves this namespace for Hosted Login assets.
    // Dashboard routes continue to resolve from `/` in the same SPA.
    base: '/auth/',
    plugins: [react(), {
      name: 'authguard-namespace-icons',
      // Lucide emits generic classes even when className is supplied.
      transform(authguard_code, authguard_id) {
        if (authguard_id.includes('lucide-react')) return authguard_code.replace(/(["'`])lucide(?=["'`-])/g, '$1authguard-icon')
      },
    }, authguard_federation({
      name: 'authguard',
      shareStrategy: 'loaded-first',
      filename: 'assets/authguard-remoteEntry.js',
      exposes: {
        './AccessManagement': './src/federation/authguard_access_management.tsx',
        './Overview': './src/federation/authguard_overview.tsx',
        './Policy': './src/federation/authguard_policy.tsx',
        './Principals': './src/federation/authguard_principals.tsx',
        './AccountSecurity': './src/federation/authguard_account_security.tsx',
        './settings': './src/shared/authguard_settings.ts',
      },
      shared: { react: { singleton: true }, 'react-dom': { singleton: true }, 'react/jsx-runtime': { singleton: true } },
      dts: false,
    })],
    build: { target: 'esnext' },
    server: {
      port: 4173,
      proxy: {
        '^/auth/(?!login(?:/|$)|account/security(?:/|$)|assets/|management/|@|src/|node_modules/)': authnTarget,
        '/.well-known': authnTarget,
        '/auth/management': { target: authzTarget, rewrite: authguard_path => authguard_path.replace(/^\/auth\/management/, '') },
        '/api': authzTarget,
      },
    },
  }
})
