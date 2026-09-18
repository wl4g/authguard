import { Navigate, Outlet, Route, Routes, useLocation } from 'react-router-dom'
import { SecurityPage } from './account/SecurityPage'
import { Layout } from './console/Layout'
import { OverviewPage } from './console/OverviewPage'
import { PolicyPage } from './console/PolicyPage'
import { PrincipalPage } from './console/PrincipalPage'
import { useAuth } from './core/AuthContext'
import { LoginPage } from './login/LoginPage'

function Protected() {
  const { authentication, ready } = useAuth()
  if (!ready) return null
  return authentication ? <Outlet/> : <Navigate to="/login" replace/>
}

function HostedProtected() {
  const { authentication, ready } = useAuth()
  const location = useLocation()
  if (!ready) return null
  if (authentication) return <Outlet/>
  const destination = `${location.pathname}${location.search}`
  return <Navigate to={`/auth/login?return_to=${encodeURIComponent(destination)}`} replace/>
}

export function App() {
  return <Routes>
    <Route path="/auth/login" element={<LoginPage/>}/>
    <Route element={<HostedProtected/>}><Route path="/auth/account/security" element={<SecurityPage/>}/></Route>
    <Route path="/login" element={<LoginPage/>}/>
    <Route element={<Protected/>}><Route element={<Layout/>}>
      <Route index element={<OverviewPage/>}/>
      <Route path="policy" element={<PolicyPage/>}/>
      <Route path="principals" element={<PrincipalPage/>}/>
    </Route></Route>
    <Route path="*" element={<Navigate to="/" replace/>}/>
  </Routes>
}
