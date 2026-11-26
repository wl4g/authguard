import { defineConfig as authguard_define_config } from 'vite'
import authguard_react from '@vitejs/plugin-react'
import { federation as authguard_federation } from '@module-federation/vite'

export default authguard_define_config({
  plugins: [authguard_react(), authguard_federation({
    name: 'authguard_business_verifier',
    shareStrategy: 'loaded-first',
    remotes: { authguard: { type: 'module', name: 'authguard', entry: '/auth/assets/authguard-remoteEntry.js' } },
    shared: { react: { singleton: true }, 'react-dom': { singleton: true }, 'react/jsx-runtime': { singleton: true } },
    dts: false,
  })],
  resolve: { dedupe: ['react', 'react-dom'] },
  build: { target: 'esnext' },
})
