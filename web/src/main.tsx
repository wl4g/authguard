import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import { App } from './App'
import { AuthProvider } from './features/auth/AuthContext'
import { ControlProvider } from './features/control/ControlContext'
import { Web3Provider } from './features/auth/Web3Provider'
import { I18nProvider } from './lib/i18n'
import { ThemeProvider } from './lib/theme'
import './styles.css'

createRoot(document.getElementById('root')!).render(
  <StrictMode><ThemeProvider><I18nProvider><Web3Provider><AuthProvider><ControlProvider><BrowserRouter><App/></BrowserRouter></ControlProvider></AuthProvider></Web3Provider></I18nProvider></ThemeProvider></StrictMode>,
)
