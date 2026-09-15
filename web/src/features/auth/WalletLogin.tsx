import { useAppKit, useAppKitAccount } from '@reown/appkit/react'
import { WalletCards } from 'lucide-react'
import { getAddress, stringToHex } from 'viem'
import { useChainId, useSignMessage } from 'wagmi'
import { useState } from 'react'
import { authn, type AuthMetadata, type LoginResponse } from '../../lib/api'
import { useI18n } from '../../lib/i18n'
import { walletConfigured } from './Web3Provider'

type Challenge = { challengeId: string; accountId: string; message: string; expiresAt: string; signatureEncoding: string; verificationMethods: string[] }

type InjectedWallet = { request: (request: { method: string; params?: unknown[] }) => Promise<unknown> }
const ERC6492_MAGIC_SUFFIX = '6492'.repeat(16)

export function WalletLogin({ metadata, onAuthenticated }: { metadata: AuthMetadata; onAuthenticated: (result: LoginResponse) => void }) {
  const { t } = useI18n()
  const { open } = useAppKit()
  const { address, isConnected, allAccounts, embeddedWalletInfo } = useAppKitAccount()
  const chainId = useChainId()
  const { signMessageAsync } = useSignMessage()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  async function authenticate() {
    setError('')
    setBusy(true)
    try {
      const injected = (window as Window & { ethereum?: InjectedWallet }).ethereum
      let selectedAddress = address
      let selectedChainId = chainId
      if (!walletConfigured && injected) {
        const accounts = await injected.request({ method: 'eth_requestAccounts' }) as string[]
        selectedAddress = accounts[0]
        selectedChainId = Number.parseInt(await injected.request({ method: 'eth_chainId' }) as string, 16)
      } else if (!walletConfigured) {
        throw new Error(t('configureWallet'))
      } else if (!isConnected || !selectedAddress) {
        setBusy(false); await open(); return
      }
      if (!selectedAddress) throw new Error('Wallet returned no account')
      const normalizedAddress = getAddress(selectedAddress as `0x${string}`)
      const accountId = `eip155:${selectedChainId}:${normalizedAddress}`
      if (!metadata.wallet.chains.includes(`eip155:${selectedChainId}`)) throw new Error('Connected chain is not enabled by AuthGuard')
      const challenge = await authn<Challenge>(metadata.wallet.challengeEndpoint, {
        method: 'POST', body: JSON.stringify({ accountId }),
      })
      const signature = !walletConfigured && injected
        ? await injected.request({ method: 'personal_sign', params: [stringToHex(challenge.message), normalizedAddress] }) as string
        : await signMessageAsync({ message: challenge.message })
      const account = allAccounts.find(candidate =>
        candidate.namespace === 'eip155'
        && candidate.address.toLowerCase() === normalizedAddress.toLowerCase()
      )
      const isSmartAccount = account?.type === 'smartAccount'
        || embeddedWalletInfo?.accountType === 'smartAccount'
      const verificationMethod = signature.toLowerCase().endsWith(ERC6492_MAGIC_SUFFIX)
        ? 'erc6492'
        : isSmartAccount ? 'erc1271' : undefined
      const result = await authn<LoginResponse>(metadata.wallet.verifyEndpoint, {
        method: 'POST', body: JSON.stringify({
          challengeId: challenge.challengeId,
          signature,
          ...(verificationMethod && { verificationMethod }),
        }),
      })
      onAuthenticated(result)
    } catch (cause) { setError(cause instanceof Error ? cause.message : t('apiError')) }
    finally { setBusy(false) }
  }

  return <div>
    <button data-testid="login-wallet" className="auth-method wallet" type="button" disabled={busy || !metadata.wallet.enabled} onClick={authenticate}>
      <WalletCards size={19} /><span>{busy ? t('connecting') : t('wallet')}</span><i>CAIP</i>
    </button>
    {error && <p className="field-error">{error}</p>}
  </div>
}
