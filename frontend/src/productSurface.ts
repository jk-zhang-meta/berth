/** Visible product surface for this fork. Upstream pages stay in the tree for absorb. */

export const SHOW_LEGACY_SAAS_CHROME = false

const PUBLIC_EXACT = new Set([
  '/login',
  '/register',
  '/forgot-password',
  '/reset-password',
  '/email-verify',
  '/setup',
])

const PUBLIC_PREFIXES = [
  '/auth/callback',
  '/auth/linuxdo/callback',
  '/auth/wechat/callback',
  '/auth/wechat/payment/callback',
  '/auth/dingtalk/callback',
  '/auth/dingtalk/email-completion',
  '/auth/oidc/callback',
  '/payment',
]

const APP_EXACT = new Set([
  '/',
  '/dashboard',
  '/keys',
  '/usage',
  '/sessions',
  '/accounts',
  '/market',
  '/proxies',
  '/redeem',
  '/purchase',
  '/orders',
  '/profile',
  '/admin',
  '/admin/dashboard',
  '/admin/accounts',
  '/admin/sessions',
  '/admin/rentals',
  '/admin/proxies',
  '/admin/usage',
  '/admin/users',
])

function hasPrefix(path: string, prefixes: string[]) {
  return prefixes.some((prefix) => path === prefix || path.startsWith(`${prefix}/`))
}

export function isProductPublicPath(path: string) {
  return PUBLIC_EXACT.has(path) || hasPrefix(path, PUBLIC_PREFIXES)
}

export function isProductAppPath(path: string) {
  return APP_EXACT.has(path)
}

export function isProductSurfacePath(path: string) {
  return isProductPublicPath(path) || isProductAppPath(path)
}

export function productFallbackPath(isAuthenticated: boolean, isAdmin: boolean) {
  if (!isAuthenticated) return '/login'
  return isAdmin ? '/admin/dashboard' : '/dashboard'
}
