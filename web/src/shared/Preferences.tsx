import { Languages, Moon, Sun } from 'lucide-react'
import { useI18n } from './i18n'
import { authguard_locale_options } from './authguard_locales'
import { useTheme } from './theme'

export function Preferences() {
  const { locale, setLocale, t } = useI18n()
  const { authguard_resolved_theme, setTheme } = useTheme()
  return <div className="authguard-preferences">
    <div className="authguard-preference-row authguard-language-row"><span><Languages size={16}/>{t('language')}</span>
      <div className="authguard-segmented authguard-language-switch" role="group" aria-label={t('language')} data-testid="locale-switch">
        {authguard_locale_options.map(authguard_option => <button type="button" key={authguard_option.value} data-testid={`locale-${authguard_option.value}`} title={authguard_option.name} aria-label={authguard_option.name} aria-pressed={locale === authguard_option.value} onClick={() => setLocale(authguard_option.value)}>{authguard_option.label}</button>)}
      </div>
    </div>
    <div className="authguard-preference-row"><span>{t('authguard_appearance')}</span>
      <div className="authguard-segmented" role="group" aria-label={t('authguard_appearance')} data-testid="theme-switch">
        <button type="button" data-testid="theme-light" aria-pressed={authguard_resolved_theme === 'light'} onClick={() => setTheme('light')}><Sun size={14}/>{t('light')}</button>
        <button type="button" data-testid="theme-dark" aria-pressed={authguard_resolved_theme === 'dark'} onClick={() => setTheme('dark')}><Moon size={14}/>{t('dark')}</button>
      </div>
    </div>
  </div>
}
