import { StrictMode, useEffect, useState, type FormEvent, type ReactNode } from 'react'
import { createRoot } from 'react-dom/client'
import { createAppKit, useAppKit, useAppKitAccount } from '@reown/appkit/react'
import { WagmiAdapter } from '@reown/appkit-adapter-wagmi'
import { mainnet, sepolia } from '@reown/appkit/networks'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { WagmiProvider, useChainId, useSignMessage } from 'wagmi'
import { getAddress } from 'viem'
import './styles.css'

type Meta = { oauth2:{providers:Array<{id:string;authorizationEndpoint:string}>}; standalone:{password:boolean;loginEndpoint:string}; wallet:{enabled:boolean;chains:string[];challengeEndpoint:string;verifyEndpoint:string} }
type Login = { accessToken:string; principal:{principalId:string;amr:string[]} }
const projectId = import.meta.env.VITE_REOWN_PROJECT_ID || 'AUTHGUARD_REOWN_PROJECT_ID'
const networks: [typeof mainnet, typeof sepolia] = [mainnet,sepolia]
const adapter = new WagmiAdapter({ networks, projectId, ssr:false })
createAppKit({ adapters:[adapter], networks, projectId, metadata:{name:'Customer Growth',description:'AuthGuard E2E application',url:location.origin,icons:[]}, features:{analytics:false,email:false,socials:false} })
const queryClient = new QueryClient()

async function request<T>(path:string, init?:RequestInit):Promise<T>{const response=await fetch(path,{...init,headers:{'content-type':'application/json',...init?.headers}});if(!response.ok){const body=await response.json().catch(()=>({})) as {message?:string};throw new Error(body.message||response.statusText)}return response.json() as Promise<T>}

function WalletButton({meta,onLogin}:{meta:Meta;onLogin:(login:Login)=>void}){
  const {open}=useAppKit();const {address,isConnected}=useAppKitAccount();const chainId=useChainId();const {signMessageAsync}=useSignMessage();const [busy,setBusy]=useState(false);const [error,setError]=useState('')
  async function login(){setError('');try{if(projectId==='AUTHGUARD_REOWN_PROJECT_ID')throw new Error('VITE_REOWN_PROJECT_ID is required');if(!isConnected||!address){await open();return}setBusy(true);const accountId=`eip155:${chainId}:${getAddress(address as `0x${string}`)}`;if(!meta.wallet.chains.includes(`eip155:${chainId}`))throw new Error('Connected chain is not enabled by AuthGuard');const challenge=await request<{challengeId:string;message:string}>(meta.wallet.challengeEndpoint,{method:'POST',body:JSON.stringify({accountId})});const signature=await signMessageAsync({message:challenge.message});onLogin(await request<Login>(meta.wallet.verifyEndpoint,{method:'POST',body:JSON.stringify({challengeId:challenge.challengeId,signature})}))}catch(cause){setError(cause instanceof Error?cause.message:String(cause))}finally{setBusy(false)}}
  return <div><button data-testid="login-wallet" disabled={!meta.wallet.enabled||busy} onClick={()=>login()}>{busy?'Signing…':'Wallet / CAIP'}</button>{error&&<p className="error" data-testid="login-wallet-error">{error}</p>}</div>
}

function Providers({children}:{children:ReactNode}){return <WagmiProvider config={adapter.wagmiConfig}><QueryClientProvider client={queryClient}>{children}</QueryClientProvider></WagmiProvider>}

function App(){
  const [meta,setMeta]=useState<Meta|null>(null);const [result,setResult]=useState<Login|null>(null);const [login,setLogin]=useState('');const [password,setPassword]=useState('');const [totp,setTotp]=useState('');const [error,setError]=useState('')
  useEffect(()=>{request<Meta>('/.well-known/authn.json').then(setMeta).catch(error=>setError(String(error)))},[])
  async function passwordLogin(event:FormEvent){event.preventDefault();if(!meta)return;try{setResult(await request<Login>(meta.standalone.loginEndpoint,{method:'POST',body:JSON.stringify({login,password,totp:totp||null})}))}catch(cause){setError(String(cause))}}
  function oauth(provider:Meta['oauth2']['providers'][number]){const popup=open(`${provider.authorizationEndpoint}?return_uri=${encodeURIComponent(location.origin)}`,provider.id,'popup,width=520,height=720');if(!popup)return;const timer=setInterval(()=>{if(popup.closed){clearInterval(timer);return}try{const text=popup.document.body?.innerText?.trim();if(text?.startsWith('{')){const value=JSON.parse(text) as Login;if(value.accessToken){setResult(value);popup.close();clearInterval(timer)}}}catch{/* provider remains cross-origin until callback */}},300)}
  if(result)return <main className="home" data-testid="customer-home"><div className="mark">CG</div><h1>Customer Growth</h1><p>Authenticated as <code>{result.principal.principalId}</code></p><small>{result.principal.amr.join(' · ')}</small><button onClick={()=>setResult(null)}>Sign out</button></main>
  return <main className="login"><section><div className="mark">CG</div><span>Customer Growth Platform</span><h1>Build the next relationship.</h1><p>Sign in through the AuthGuard identity fabric.</p></section><article><h2>Welcome back</h2><form onSubmit={passwordLogin}><input data-testid="login-id" value={login} onChange={e=>setLogin(e.target.value)} placeholder="Email"/><input data-testid="login-password" type="password" value={password} onChange={e=>setPassword(e.target.value)} placeholder="Password"/><input data-testid="login-totp" value={totp} onChange={e=>setTotp(e.target.value)} placeholder="TOTP (optional)"/><button data-testid="login-password-submit" disabled={!meta?.standalone.password}>Password</button></form>{meta&&<WalletButton meta={meta} onLogin={setResult}/>}<div className="providers">{meta?.oauth2.providers.filter(item=>['github','google','wechat','qq'].includes(item.id.toLowerCase())).map(item=><button data-testid={`login-${item.id}`} onClick={()=>oauth(item)} key={item.id}>{item.id}</button>)}</div>{error&&<p className="error">{error}</p>}<footer>OIDC · OAuth2 · CAIP-122 · Password</footer></article></main>
}

createRoot(document.getElementById('root')!).render(<StrictMode><Providers><App/></Providers></StrictMode>)
