import { beforeEach, describe, expect, it, vi } from 'vitest'
import { extractShortfallMetadata, marketplaceAPI, parseQuotaLimit, percentToBps, priceToCents } from '../api'
import { apiClient } from '@/api/client'

vi.mock('@/api/client', () => ({ apiClient: { get: vi.fn(), post: vi.fn(), patch: vi.fn(), put: vi.fn() } }))

describe('marketplace API contract', () => {
  beforeEach(() => { vi.resetAllMocks() })
  it('reads public rates and saves integer basis points', async () => {
    const settings = { rent_commission_bps: 125, usage_commission_bps: 10000 }
    vi.mocked(apiClient.get).mockResolvedValue({ data: settings })
    vi.mocked(apiClient.put).mockResolvedValue({ data: settings })
    expect(await marketplaceAPI.settings()).toEqual(settings)
    expect(apiClient.get).toHaveBeenCalledWith('/marketplace/settings')
    expect(await marketplaceAPI.updateSettings(settings)).toEqual(settings)
    expect(apiClient.put).toHaveBeenCalledWith('/marketplace/settings', settings)
  })
  it.each([['0', 0], ['1.25', 125], ['100', 10000], ['100.01', null], ['-1', null], ['1.001', null], ['', null], ['NaN', null]])('validates commission percent %s', (input, expected) => {
    expect(percentToBps(String(input))).toBe(expected)
  })
  it('passes explicit scope and unwraps list items', async () => {
    vi.mocked(apiClient.get).mockResolvedValue({ data: { items: [{ id: 7 }] } })
    expect(await marketplaceAPI.listings('mine')).toEqual([{ id: 7 }])
    expect(apiClient.get).toHaveBeenCalledWith('/marketplace/listings', { params: { scope: 'mine' } })
  })
  it('passes caller-owned idempotency key unchanged', async () => {
    vi.mocked(apiClient.post).mockResolvedValue({ data: { id: 2 } })
    expect(await marketplaceAPI.checkout(7, 'attempt-key')).toEqual({ id: 2 })
    expect(apiClient.post).toHaveBeenCalledWith('/marketplace/listings/7/checkout', { idempotency_key: 'attempt-key' })
  })
  it.each([['0.29', 29], ['12.50', 1250], ['1', 100], ['01.2', 120], ['0', null], ['-1', null], ['1.234', null], ['NaN', null], ['1e2', null], ['9007199254749992', null]] as const)('converts price %s to %s cents without rounding', (input, expected) => {
    expect(priceToCents(input)).toBe(expected)
  })
  it.each([['0.01', 0.01], ['25.5', 25.5], ['100.12345678', 100.12345678], ['0', null], ['0.001', null], ['-5', null], ['1000001', null], ['', null]] as const)('validates quota limit %s', (input, expected) => {
    expect(parseQuotaLimit(input)).toBe(expected)
  })
  it('calls Track C targeted decline, order usage, and payment intent endpoints', async () => {
    vi.mocked(apiClient.post).mockResolvedValueOnce({ data: { id: 9, status: 'removed' } })
    expect(await marketplaceAPI.decline(9)).toEqual({ id: 9, status: 'removed' })
    expect(apiClient.post).toHaveBeenLastCalledWith('/marketplace/listings/9/decline')

    vi.mocked(apiClient.post).mockResolvedValueOnce({ data: { mode: 'payment_required', intent_id: 55, shortfall_cents: 650 } })
    expect(await marketplaceAPI.checkoutPayment(9, { idempotency_key: 'k1', payment_type: 'alipay' })).toEqual({ mode: 'payment_required', intent_id: 55, shortfall_cents: 650 })
    expect(apiClient.post).toHaveBeenLastCalledWith('/marketplace/listings/9/checkout-payment', { idempotency_key: 'k1', payment_type: 'alipay' })

    vi.mocked(apiClient.get).mockResolvedValueOnce({ data: { id: 55, status: 'pending' } })
    expect(await marketplaceAPI.getPaymentIntent(55)).toEqual({ id: 55, status: 'pending' })
    expect(apiClient.get).toHaveBeenLastCalledWith('/marketplace/payment-intents/55')

    vi.mocked(apiClient.post).mockResolvedValueOnce({ data: { id: 55, status: 'completed' } })
    expect(await marketplaceAPI.verifyPaymentIntent(55)).toEqual({ id: 55, status: 'completed' })
    expect(apiClient.post).toHaveBeenLastCalledWith('/marketplace/payment-intents/55/verify')

    vi.mocked(apiClient.get).mockResolvedValueOnce({ data: { order_id: 30, total: 1, items: [] } })
    expect(await marketplaceAPI.orderUsage(30, 2, 10)).toEqual({ order_id: 30, total: 1, items: [] })
    expect(apiClient.get).toHaveBeenLastCalledWith('/marketplace/orders/30/usage', { params: { page: 2, page_size: 10 } })
  })
  it('extracts structured shortfall metadata from 402 balance errors', () => {
    expect(extractShortfallMetadata({
      status: 402,
      reason: 'MARKETPLACE_BALANCE',
      metadata: { price_cents: '1250', available_balance_cents: '400', shortfall_cents: '850', payment_enabled: 'true' },
    })).toEqual({
      price_cents: 1250,
      available_balance_cents: 400,
      shortfall_cents: 850,
      payment_enabled: true,
    })
    expect(extractShortfallMetadata({ status: 400, reason: 'BAD_REQUEST' })).toBeNull()
    expect(extractShortfallMetadata(new Error('network'))).toBeNull()
  })
})
