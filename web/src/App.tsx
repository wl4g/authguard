import { Navigate, Outlet, Route, Routes } from 'react-router-dom'
import { Layout } from './components/Layout'
import { useAuth } from './features/auth/AuthContext'
import { LoginPage } from './pages/LoginPage'
import { OverviewPage } from './pages/OverviewPage'
import { PolicyPage } from './pages/PolicyPage'
import { PrincipalPage } from './pages/PrincipalPage'

function Protected() {
  return useAuth().authentication ? <Outlet/> : <Navigate to="/login" replace/>
}

export function App() {
  return <Routes>
    <Route path="/login" element={<LoginPage/>}/>
    <Route element={<Protected/>}><Route element={<Layout/>}>
      <Route index element={<OverviewPage/>}/>
      <Route path="policy" element={<PolicyPage/>}/>
      <Route path="principals" element={<PrincipalPage/>}/>
    </Route></Route>
    <Route path="*" element={<Navigate to="/" replace/>}/>
  </Routes>
}
