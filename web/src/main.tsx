import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import { App } from './App'
import { AuthProvider } from './core/AuthContext'
import { ControlProvider } from './core/ControlContext'
import { Web3Provider } from './login/Web3Provider'
import { I18nProvider } from './shared/i18n'
import { ThemeProvider } from './shared/theme'
import './shared/styles.css'

createRoot(document.getElementById('root')!).render(
  <StrictMode><ThemeProvider><I18nProvider><Web3Provider><AuthProvider><ControlProvider><BrowserRouter><App/></BrowserRouter></ControlProvider></AuthProvider></Web3Provider></I18nProvider></ThemeProvider></StrictMode>,
)
