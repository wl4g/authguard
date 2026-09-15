import { Languages, Moon, Sun } from 'lucide-react'
import { useI18n } from '../lib/i18n'
import { useTheme, type Theme } from '../lib/theme'

export function Preferences() {
  const { locale, setLocale, t } = useI18n()
  const { theme, setTheme } = useTheme()
  return <div className="preferences">
    <label title={t('language')}><Languages size={16}/><select data-testid="locale-select" value={locale} onChange={event => setLocale(event.target.value as typeof locale)}><option value="zh_CN">简体中文</option><option value="en_US">English</option></select></label>
    <label>{theme === 'dark' ? <Moon size={16}/> : <Sun size={16}/>}<select data-testid="theme-select" value={theme} onChange={event => setTheme(event.target.value as Theme)}><option value="system">{t('system')}</option><option value="dark">{t('dark')}</option><option value="light">{t('light')}</option></select></label>
  </div>
}
