import { useAppKit, useAppKitAccount } from '@reown/appkit/react'
import { WalletCards } from 'lucide-react'
import { getAddress } from 'viem'
import { useChainId, useSignMessage } from 'wagmi'
import { useState } from 'react'
import { authn, type AuthMetadata, type LoginResponse } from '../../lib/api'
import { useI18n } from '../../lib/i18n'
import { walletConfigured } from './Web3Provider'

type Challenge = { challengeId: string; accountId: string; message: string; expiresAt: string; signatureEncoding: string }

export function WalletLogin({ metadata, onAuthenticated }: { metadata: AuthMetadata; onAuthenticated: (result: LoginResponse) => void }) {
  const { t } = useI18n()
  const { open } = useAppKit()
  const { address, isConnected } = useAppKitAccount()
  const chainId = useChainId()
  const { signMessageAsync } = useSignMessage()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  async function authenticate() {
    setError('')
    if (!walletConfigured) { setError(t('configureWallet')); return }
    if (!isConnected || !address) { await open(); return }
    setBusy(true)
    try {
      const accountId = `eip155:${chainId}:${getAddress(address as `0x${string}`)}`
      if (!metadata.wallet.chains.includes(`eip155:${chainId}`)) throw new Error('Connected chain is not enabled by AuthGuard')
      const challenge = await authn<Challenge>(metadata.wallet.challengeEndpoint, {
        method: 'POST', body: JSON.stringify({ accountId }),
      })
      const signature = await signMessageAsync({ message: challenge.message })
      const result = await authn<LoginResponse>(metadata.wallet.verifyEndpoint, {
        method: 'POST', body: JSON.stringify({ challengeId: challenge.challengeId, signature }),
      })
      onAuthenticated(result)
    } catch (cause) { setError(cause instanceof Error ? cause.message : t('apiError')) }
    finally { setBusy(false) }
  }

  return <div>
    <button className="auth-method wallet" type="button" disabled={busy || !metadata.wallet.enabled} onClick={authenticate}>
      <WalletCards size={19} /><span>{busy ? t('connecting') : t('wallet')}</span><i>CAIP</i>
    </button>
    {error && <p className="field-error">{error}</p>}
  </div>
}
