import { useEffect } from 'react'
import type { ApplicationBrand } from '../core/api'

const THEME_LINK_ID = 'authguard-application-theme'

/** Applies only server-approved, same-origin application presentation assets. */
export function useApplicationTheme(application?: ApplicationBrand | null) {
  const themeId = application?.theme?.id
  const stylesheet = application?.theme?.stylesheet

  useEffect(() => {
    const root = document.documentElement
    document.getElementById(THEME_LINK_ID)?.remove()
    if (!themeId || !stylesheet) {
      delete root.dataset.applicationTheme
      return
    }
    root.dataset.applicationTheme = themeId
    const link = document.createElement('link')
    link.id = THEME_LINK_ID
    link.rel = 'stylesheet'
    link.href = stylesheet
    document.head.append(link)
    return () => {
      link.remove()
      delete root.dataset.applicationTheme
    }
  }, [stylesheet, themeId])
}
