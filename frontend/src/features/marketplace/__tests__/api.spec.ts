import { beforeEach, describe, expect, it, vi } from 'vitest'
import { marketplaceAPI, priceToCents, percentToBps } from '../api'
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
  it.each([['0.29', 29], ['12.50', 1250], ['1', 100], ['01.2', 120], ['0', null], ['-1', null], ['1.234', null], ['NaN', null], ['1e2', null], ['9007199254740992', null]] as const)('converts price %s to %s cents without rounding', (input, expected) => {
    expect(priceToCents(input)).toBe(expected)
  })
})
