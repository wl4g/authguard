declare module 'authguard/AccessManagement' {
  import type { ComponentType as authguard_component } from 'react'
  export type authguard_module_id = 'overview' | 'policy' | 'principals' | 'accountSecurity'
  export type authguard_remote_props = {
    authguard_locale?: 'en_US' | 'zh_CN' | 'zh_TW' | 'ja_JP' | 'ko_KR' | 'de_DE' | 'fr_FR'
    authguard_theme?: 'dark' | 'light' | 'system'
    authguard_api_token?: string
    authguard_on_return: () => void
    authguard_modules?: readonly authguard_module_id[]
  }
  const authguard_remote: authguard_component<authguard_remote_props>
  export default authguard_remote
}
declare module 'authguard/Overview' {
  import type { ComponentType as authguard_component } from 'react'
  import type { authguard_remote_props } from 'authguard/AccessManagement'
  const authguard_remote: authguard_component<authguard_remote_props>
  export default authguard_remote
}
declare module 'authguard/Policy' { export { default } from 'authguard/Overview' }
declare module 'authguard/Principals' { export { default } from 'authguard/Overview' }
declare module 'authguard/AccountSecurity' { export { default } from 'authguard/Overview' }
declare module 'authguard/settings' {
  export function authguard_set_locale(authguard_value: 'en_US' | 'zh_CN' | 'zh_TW' | 'ja_JP' | 'ko_KR' | 'de_DE' | 'fr_FR'): void
  export function authguard_set_theme(authguard_value: 'dark' | 'light' | 'system'): void
}
