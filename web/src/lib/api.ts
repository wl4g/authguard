export type Principal = {
  id: string
  kind: 'USER' | 'WORKLOAD' | 'GROUP'
  display_name: string
  status: 'ACTIVE' | 'DISABLED'
  authorization_state: Record<string, unknown>
}

export type LoginResponse = {
  accessToken: string
  tokenType: 'Bearer'
  expiresIn: number
  returnUri: string
  principal: { principalId: string; kind: string; stableGroupIds: string[]; trustedClaims: Record<string, string>; acr?: string; amr: string[] }
}

export type AuthMetadata = {
  version: string
  oauth2: { providers: Array<{ id: string; protocol: string; issuer: string; authorizationEndpoint: string }> }
  standalone: {
    enabled: boolean; password: boolean; totp: boolean; webauthn: boolean
    loginEndpoint: string; registrationEndpoint: string
    webauthnRegistrationChallengeEndpoint: string; webauthnRegistrationVerifyEndpoint: string
    webauthnAuthenticationChallengeEndpoint: string; webauthnAuthenticationVerifyEndpoint: string
  }
  wallet: { enabled: boolean; chains: string[]; contractVerificationChains: string[]; challengeEndpoint: string; verifyEndpoint: string; linkEndpoint: string }
}

const authnBase = (import.meta.env.VITE_AUTHN_BASE_URL || '').replace(/\/$/, '')
const authzBase = (import.meta.env.VITE_AUTHZ_BASE_URL || '').replace(/\/$/, '')

async function json<T>(url: string, init?: RequestInit): Promise<T> {
  const response = await fetch(url, {
    ...init,
    headers: { 'content-type': 'application/json', ...init?.headers },
  })
  if (!response.ok) {
    const body = await response.json().catch(() => ({})) as { message?: string; code?: string }
    throw new Error(body.message || body.code || `${response.status} ${response.statusText}`)
  }
  if (response.status === 204) return undefined as T
  return response.json() as Promise<T>
}

export function authn<T>(path: string, init?: RequestInit) { return json<T>(`${authnBase}${path}`, init) }
export function authnUrl(path: string) { return `${authnBase}${path}` }
export function metadata() { return authn<AuthMetadata>('/.well-known/authn.json') }

export function control<T>(path: string, token: string, init?: RequestInit) {
  return json<T>(`${authzBase}${path}`, {
    ...init,
    headers: { authorization: `Bearer ${token}`, ...init?.headers },
  })
}
