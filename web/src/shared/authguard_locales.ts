/** Stable locale codes and compact labels shared by the standalone and federation APIs. */
export const authguard_locale_options = [
  { value: 'en_US', label: 'EN', name: 'English' },
  { value: 'zh_CN', label: '中', name: '简体中文' },
  { value: 'zh_TW', label: '繁', name: '繁體中文' },
  { value: 'ja_JP', label: '日語', name: '日本語' },
  { value: 'ko_KR', label: '한글', name: '한국어' },
  { value: 'de_DE', label: 'DE', name: 'Deutsch' },
  { value: 'fr_FR', label: 'FR', name: 'Français' },
] as const
export type authguard_locale = typeof authguard_locale_options[number]['value']

export function authguard_is_locale(authguard_value: unknown): authguard_value is authguard_locale {
  return authguard_locale_options.some(authguard_option => authguard_option.value === authguard_value)
}

export function authguard_browser_locale(authguard_value: string): authguard_locale {
  const authguard_tag = authguard_value.replaceAll('_', '-').toLowerCase()
  if (/^zh-(tw|hk|mo|hant)(-|$)/.test(authguard_tag)) return 'zh_TW'
  const authguard_languages: Record<string, authguard_locale> = { en: 'en_US', zh: 'zh_CN', ja: 'ja_JP', ko: 'ko_KR', de: 'de_DE', fr: 'fr_FR' }
  return authguard_languages[authguard_tag.split('-')[0]] ?? 'en_US'
}
