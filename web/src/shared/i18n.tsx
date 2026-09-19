import { createContext, useContext, useMemo, useState, type ReactNode } from 'react'

export type Locale = 'zh_CN' | 'en_US'

const messages = {
  en_US: {
    product: 'AuthGuard', tagline: 'Identity control plane', loginTitle: 'Enter the trust fabric',
    loginHint: 'One Principal. One token. Every authentication protocol.', login: 'Sign in', signInTo: 'Sign in to',
    loginId: 'Email or login ID', password: 'Password', totp: 'TOTP code (optional)',
    passkey: 'Continue with passkey', registerPasskey: 'Add passkey', wallet: 'Continue with wallet', connecting: 'Connecting…',
    orFederated: 'or continue with', notEnabled: 'This method is not enabled by the server.',
    policy: 'Policy', principals: 'Principals', overview: 'Overview', signOut: 'Sign out',
    controlToken: 'Control-plane token', saveToken: 'Use token', revision: 'Revision',
    actions: 'Actions', roles: 'Roles', bindings: 'Role bindings', add: 'Create', edit: 'Edit',
    remove: 'Delete', refresh: 'Refresh', cancel: 'Cancel', save: 'Save', json: 'Resource JSON',
    status: 'Status', kind: 'Kind', displayName: 'Display name', search: 'Search',
    localCreate: 'Create standalone account', federatedSearch: 'Federated search',
    materialize: 'Materialize', principalId: 'Canonical Principal ID', active: 'Active',
    disabled: 'Disabled', loginSuccess: 'Authentication succeeded', apiError: 'Request failed',
    empty: 'No resources yet', authenticatedAs: 'Authenticated as', secureBoundary: 'Protocol boundary',
    securityCopy: 'Passwords, wallet proofs and provider tokens stop at AuthN. Authorization only sees the canonical Principal.',
    localAccount: 'Standalone account', createAccount: 'Create account', provider: 'Provider',
    username: 'Login identifier', next: 'Next', welcome: 'Control plane ready',
    welcomeCopy: 'Manage canonical identities and policy without leaking authentication protocols into authorization.',
    system: 'System', dark: 'Dark', light: 'Light', language: 'Language', configureWallet: 'Configure Reown project ID',
    accountSecurity: 'Account security', manageCredentials: 'Manage your credentials', stepUpHint: 'Confirm your standalone password and TOTP, if enabled, before adding a passkey to the authenticated Principal.',
    passkeyAdded: 'Passkey added', backToApplication: 'Back to application', copyId: 'Copy ID',
  },
  zh_CN: {
    product: 'AuthGuard', tagline: '身份与授权控制平面', loginTitle: '进入可信身份网络',
    loginHint: '统一 Principal、统一 Token，认证协议彼此独立。', login: '登录', signInTo: '登录',
    loginId: '邮箱或登录标识', password: '密码', totp: 'TOTP 验证码（可选）',
    passkey: '使用通行密钥', registerPasskey: '添加通行密钥', wallet: '使用钱包登录', connecting: '正在连接…',
    orFederated: '或使用以下方式', notEnabled: '服务端尚未启用此认证方式。',
    policy: '策略管理', principals: '身份主体', overview: '概览', signOut: '退出登录',
    controlToken: '控制面令牌', saveToken: '应用令牌', revision: '版本',
    actions: '动作', roles: '角色', bindings: '角色绑定', add: '新建', edit: '编辑',
    remove: '删除', refresh: '刷新', cancel: '取消', save: '保存', json: '资源 JSON',
    status: '状态', kind: '类型', displayName: '显示名称', search: '搜索',
    localCreate: '创建 Standalone 账号', federatedSearch: '联邦搜索', materialize: '物化',
    principalId: 'Canonical Principal ID', active: '启用', disabled: '禁用',
    loginSuccess: '认证成功', apiError: '请求失败', empty: '暂无资源',
    authenticatedAs: '当前身份', secureBoundary: '协议安全边界',
    securityCopy: '密码、钱包证明和上游 Provider Token 均止于 AuthN；AuthZ 只接收 canonical Principal。',
    localAccount: 'Standalone 本地账号', createAccount: '创建账号', provider: '来源',
    username: '登录标识', next: '下一步', welcome: '控制平面已就绪',
    welcomeCopy: '管理 canonical identity 与策略，认证协议不会泄漏到授权边界。',
    system: '跟随系统', dark: '酷黑', light: '白天', language: '语言', configureWallet: '请配置 Reown Project ID',
    accountSecurity: '账号安全', manageCredentials: '管理认证凭据', stepUpHint: '添加通行密钥前，请使用本地账号密码及已启用的 TOTP 再次确认当前 Principal。',
    passkeyAdded: '通行密钥已添加', backToApplication: '返回应用', copyId: '复制 ID',
  },
} as const

export type MessageKey = keyof typeof messages.en_US

type I18nValue = { locale: Locale; setLocale: (locale: Locale) => void; t: (key: MessageKey) => string }
const I18nContext = createContext<I18nValue | null>(null)

export function I18nProvider({ children }: { children: ReactNode }) {
  const [locale, setLocaleState] = useState<Locale>(() =>
    localStorage.getItem('authguard.locale') === 'zh_CN' || navigator.language.startsWith('zh') ? 'zh_CN' : 'en_US',
  )
  const value = useMemo<I18nValue>(() => ({
    locale,
    setLocale(next) { localStorage.setItem('authguard.locale', next); setLocaleState(next) },
    t: (key) => messages[locale][key],
  }), [locale])
  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>
}

export function useI18n() {
  const value = useContext(I18nContext)
  if (!value) throw new Error('I18nProvider is missing')
  return value
}
