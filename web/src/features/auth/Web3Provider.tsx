import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { createAppKit } from '@reown/appkit/react'
import { WagmiAdapter } from '@reown/appkit-adapter-wagmi'
import { mainnet, sepolia } from '@reown/appkit/networks'
import { WagmiProvider } from 'wagmi'
import type { ReactNode } from 'react'

export const reownProjectId = import.meta.env.VITE_REOWN_PROJECT_ID || 'AUTHGUARD_REOWN_PROJECT_ID'
export const walletConfigured = reownProjectId !== 'AUTHGUARD_REOWN_PROJECT_ID'
const networks: [typeof mainnet, typeof sepolia] = [mainnet, sepolia]
const adapter = new WagmiAdapter({ networks, projectId: reownProjectId, ssr: false })

createAppKit({
  adapters: [adapter],
  networks,
  projectId: reownProjectId,
  metadata: {
    name: 'AuthGuard',
    description: 'Protocol-neutral authentication control plane',
    url: typeof window === 'undefined' ? 'https://authguard.example' : window.location.origin,
    icons: [],
  },
  features: { analytics: false, email: false, socials: false },
})

const queryClient = new QueryClient()

export function Web3Provider({ children }: { children: ReactNode }) {
  return <WagmiProvider config={adapter.wagmiConfig}><QueryClientProvider client={queryClient}>{children}</QueryClientProvider></WagmiProvider>
}
