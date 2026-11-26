import type { ReactNode as authguard_node } from 'react'
import { useI18n as authguard_use_i18n } from '../shared/i18n'

export function authguard_page_frame({ children: authguard_children, authguard_on_return }: { children: authguard_node; authguard_on_return: () => void }) {
  const { t: authguard_t } = authguard_use_i18n()
  return <div className="authguard-page-frame"><main className="authguard-page">{authguard_children}</main><button className="authguard-return" data-testid="authguard-return" onClick={authguard_on_return}>{authguard_t('authguard_back')}</button></div>
}
