import { describe, expect, it } from 'vitest'
import {
  accountEmail,
  accountPlan,
  cardStatusKind,
  firstTokenTone,
  formatCompactCount,
  formatCostNumber,
  formatFirstTokenMs,
  planClass,
  providerMark
} from '../accountCardDisplay'

describe('accountCardDisplay', () => {
  it('formats TTFT as ms under 1s and seconds at/after 1s', () => {
    expect(formatFirstTokenMs(null)).toBe('--')
    expect(formatFirstTokenMs(0)).toBe('--')
    expect(formatFirstTokenMs(342)).toBe('342ms')
    expect(formatFirstTokenMs(1000)).toBe('1.00s')
    expect(formatFirstTokenMs(1240)).toBe('1.24s')
  })

  it('colors TTFT with chat-perception buckets, not usage-log 10s buckets', () => {
    expect(firstTokenTone(null)).toBe('none')
    expect(firstTokenTone(420)).toBe('good')
    expect(firstTokenTone(800)).toBe('ok')
    expect(firstTokenTone(1500)).toBe('slow')
    expect(firstTokenTone(2400)).toBe('bad')
  })

  it('uses the platform label first letter as the provider mark', () => {
    expect(providerMark('openai')).toBe('O')
    expect(providerMark('anthropic')).toBe('A')
    expect(providerMark('gemini')).toBe('G')
  })

  it('prefers email over account name and maps plan pills', () => {
    expect(
      accountEmail({
        name: 'codex-1',
        extra: { email: 'plus@example.com' },
        credentials: {},
        parent_email: undefined
      })
    ).toBe('plus@example.com')
    expect(
      accountPlan({
        credentials: { plan_type: 'plus' },
        extra: {},
        parent_plan_type: undefined
      })
    ).toBe('Plus')
    expect(planClass('Plus')).toBe('plan-plus')
    expect(planClass('Pro')).toBe('plan-pro')
  })

  it('marks rate-limited and unschedulable cards separately from active', () => {
    expect(cardStatusKind({ status: 'active', schedulable: true, rate_limit_reset_at: null })).toBe('active')
    expect(
      cardStatusKind({ status: 'active', schedulable: true, rate_limit_reset_at: '2026-09-11T12:00:00Z' })
    ).toBe('rate-limited')
    expect(cardStatusKind({ status: 'active', schedulable: false, rate_limit_reset_at: null })).toBe('inactive')
    expect(cardStatusKind({ status: 'error', schedulable: true, rate_limit_reset_at: null })).toBe('error')
  })

  it('compacts request/token/cost the way Personal Web cards do', () => {
    expect(formatCompactCount(12)).toBe('12')
    expect(formatCompactCount(15600)).toBe('15.6K')
    expect(formatCostNumber(null)).toBe('--')
    expect(formatCostNumber(1.5)).toBe('1.50')
  })
})
