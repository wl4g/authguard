import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
export default defineConfig({ plugins:[react()], server:{ port:4180, proxy:{ '/auth':'http://127.0.0.1:8082', '/.well-known/authn.json':'http://127.0.0.1:8082' } } })
