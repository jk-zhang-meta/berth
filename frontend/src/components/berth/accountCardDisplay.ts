import { platformLabel } from '@/utils/platformColors'
import type { AccountListItem } from '@/types'

function firstString(...values: unknown[]): string {
  for (const value of values) {
    if (typeof value === 'string' && value.trim()) return value.trim()
  }
  return ''
}

export function formatFirstTokenMs(ms?: number | null): string {
  if (ms == null || !Number.isFinite(ms) || ms <= 0) return '--'
  if (ms >= 1000) return `${(ms / 1000).toFixed(2)}s`
  return `${Math.round(ms)}ms`
}

export type FirstTokenTone = 'none' | 'good' | 'ok' | 'slow' | 'bad'

// Chat/streaming UX for TTFT (Together AI TTFT docs; NVIDIA GenAI-Perf;
// RAIL-style <500ms). Usage-table 10s buckets are for whole-request logs.
export function firstTokenTone(ms?: number | null): FirstTokenTone {
  if (ms == null || !Number.isFinite(ms) || ms <= 0) return 'none'
  if (ms < 500) return 'good'
  if (ms < 1000) return 'ok'
  if (ms < 2000) return 'slow'
  return 'bad'
}

export function providerMark(platform: string): string {
  const ch = platformLabel(platform).trim().charAt(0)
  return ch ? ch.toUpperCase() : '?'
}

export function accountEmail(
  account: Pick<AccountListItem, 'name' | 'extra' | 'credentials' | 'parent_email'>
): string {
  const extra = (account.extra || {}) as Record<string, unknown>
  const cred = (account.credentials || {}) as Record<string, unknown>
  return (
    firstString(extra.email_address, extra.email, cred.email, account.parent_email, account.name) ||
    account.name
  )
}

export function accountPlan(
  account: Pick<AccountListItem, 'credentials' | 'extra' | 'parent_plan_type'>
): string {
  const extra = (account.extra || {}) as Record<string, unknown>
  const cred = (account.credentials || {}) as Record<string, unknown>
  const billing = extra.grok_billing_snapshot as Record<string, unknown> | undefined
  const usage = extra.grok_usage_snapshot as Record<string, unknown> | undefined
  const raw = firstString(
    cred.plan_type,
    extra.subscription_tier,
    billing?.plan,
    usage?.subscription_tier,
    account.parent_plan_type
  )
  if (!raw) return '--'
  const lower = raw.toLowerCase()
  if (lower === 'plus') return 'Plus'
  if (lower === 'pro' || lower.startsWith('pro')) return 'Pro'
  if (lower === 'free' || lower === 'free-tier') return 'Free'
  if (lower.includes('ultra')) return 'Ultra'
  return raw
}

export function planClass(plan: string): string {
  const lower = plan.toLowerCase()
  if (lower === 'plus') return 'plan-plus'
  if (lower === 'pro' || lower.startsWith('pro') || lower === 'ultra') return 'plan-pro'
  return 'plan-other'
}

export function cardStatusKind(
  account: Pick<AccountListItem, 'status' | 'schedulable' | 'rate_limit_reset_at'>
): string {
  if (account.status === 'error') return 'error'
  if (account.rate_limit_reset_at) return 'rate-limited'
  if (account.status === 'inactive' || !account.schedulable) return 'inactive'
  return 'active'
}

export function formatCompactCount(value: number | null | undefined): string {
  if (value == null || !Number.isFinite(value)) return '--'
  const amount = Number(value) || 0
  const sign = amount < 0 ? '-' : ''
  const size = Math.abs(amount)
  if (size >= 1e9) return `${sign}${(size / 1e9).toFixed(2)}B`
  if (size >= 1e6) return `${sign}${(size / 1e6).toFixed(1)}M`
  if (size >= 1e3) return `${sign}${(size / 1e3).toFixed(1)}K`
  return `${sign}${size}`
}

export function formatCostNumber(value: number | null | undefined): string {
  if (value == null || !Number.isFinite(Number(value))) return '--'
  const number = Number(value)
  const digits = number > 0 && number < 0.01 ? 6 : 2
  return number.toLocaleString('en-US', {
    minimumFractionDigits: 2,
    maximumFractionDigits: digits
  })
}

export function hasUsageWindows(account: Pick<AccountListItem, 'platform' | 'type'>): boolean {
  if (account.platform === 'gemini') return true
  if (
    account.platform === 'kimi' ||
    account.platform === 'zhipu' ||
    account.platform === 'deepseek' ||
    account.platform === 'minimax'
  ) {
    return true
  }
  return account.type === 'oauth' || account.type === 'setup-token'
}
