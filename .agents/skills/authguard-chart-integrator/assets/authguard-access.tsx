import * as authguard_react from 'react'
import type { authguard_remote_props } from 'authguard/AccessManagement'

const authguard_feedback: Record<NonNullable<authguard_remote_props['authguard_locale']>, readonly [string, string, string]> = {
  en_US: ['Access Management is temporarily unavailable', 'Back to workspace', 'Loading Access Management…'],
  zh_CN: ['访问管理暂时无法加载', '返回工作台', '正在加载访问管理…'],
  zh_TW: ['暫時無法載入存取管理', '返回工作台', '正在載入存取管理…'],
  ja_JP: ['アクセス管理を一時的に読み込めません', 'ワークスペースに戻る', 'アクセス管理を読み込み中…'],
  ko_KR: ['현재 접근 관리를 불러올 수 없습니다', '작업 공간으로 돌아가기', '접근 관리 로딩 중…'],
  de_DE: ['Die Zugriffsverwaltung ist vorübergehend nicht verfügbar', 'Zurück zum Arbeitsbereich', 'Zugriffsverwaltung wird geladen…'],
  fr_FR: ['La gestion des accès est temporairement indisponible', 'Retour à l’espace de travail', 'Chargement de la gestion des accès…'],
}

class authguard_error_boundary extends authguard_react.Component<{
  children: authguard_react.ReactNode
  authguard_on_return: () => void
  authguard_locale?: authguard_remote_props['authguard_locale']
}, { authguard_error: boolean }> {
  state = { authguard_error: false }
  static getDerivedStateFromError() { return { authguard_error: true } }
  render() {
    if (!this.state.authguard_error) return this.props.children
    return <div role="alert" className="authguard-load-error">
      <p>{authguard_feedback[this.props.authguard_locale ?? 'en_US'][0]}</p>
      <button onClick={this.props.authguard_on_return}>{authguard_feedback[this.props.authguard_locale ?? 'en_US'][1]}</button>
    </div>
  }
}
const authguard_components = {
  boundary: authguard_error_boundary,
  remote: authguard_react.lazy(() => import('authguard/AccessManagement')),
}

/** Place this in the host body in place of its sidebar + content. Keep the host header mounted. */
export function authguard_access(authguard_props: authguard_remote_props) {
  return <authguard_components.boundary {...authguard_props}>
    <authguard_react.Suspense fallback={<div className="authguard-loading" role="status">{authguard_feedback[authguard_props.authguard_locale ?? 'en_US'][2]}</div>}>
      <authguard_components.remote {...authguard_props}/>
    </authguard_react.Suspense>
  </authguard_components.boundary>
}
