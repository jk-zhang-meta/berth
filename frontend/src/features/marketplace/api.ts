import { apiClient } from '@/api/client'
import type {
  CheckoutPaymentPayload,
  CheckoutPaymentResult,
  CheckoutShortfallMetadata,
  CommissionSettings,
  Listing,
  ListingScope,
  MarketplacePaymentIntent,
  OrderUsagePage,
  OwnedResources,
  PublishListing,
  RentalOrder,
  RentalService,
  UsageRevenue,
} from './types'

const base = '/marketplace'

export const marketplaceAPI = {
  async revenue(): Promise<UsageRevenue> {
    const { data } = await apiClient.get<UsageRevenue>(`${base}/revenue`)
    return data
  },
  async settings(): Promise<CommissionSettings> {
    const { data } = await apiClient.get<CommissionSettings>(`${base}/settings`)
    return data
  },
  async updateSettings(settings: CommissionSettings): Promise<CommissionSettings> {
    const { data } = await apiClient.put<CommissionSettings>(`${base}/settings`, settings)
    return data
  },
  async listings(scope: ListingScope): Promise<Listing[]> {
    const { data } = await apiClient.get<{ items: Listing[] }>(`${base}/listings`, { params: { scope } })
    return data.items
  },
  async orders(): Promise<RentalOrder[]> {
    const { data } = await apiClient.get<{ items: RentalOrder[] }>(`${base}/orders`)
    return data.items
  },
  async resources(): Promise<OwnedResources> {
    const { data } = await apiClient.get<OwnedResources>(`${base}/resources`)
    return data
  },
  async publish(payload: PublishListing): Promise<Listing> {
    const { data } = await apiClient.post<Listing>(`${base}/listings`, payload)
    return data
  },
  async decline(id: number): Promise<Listing> {
    const { data } = await apiClient.post<Listing>(`${base}/listings/${id}/decline`)
    return data
  },
  async checkout(id: number, idempotencyKey: string): Promise<RentalOrder> {
    const { data } = await apiClient.post<RentalOrder>(`${base}/listings/${id}/checkout`, { idempotency_key: idempotencyKey })
    return data
  },
  async checkoutPayment(id: number, payload: CheckoutPaymentPayload): Promise<CheckoutPaymentResult> {
    const { data } = await apiClient.post<CheckoutPaymentResult>(`${base}/listings/${id}/checkout-payment`, payload)
    return data
  },
  async getPaymentIntent(id: number): Promise<MarketplacePaymentIntent> {
    const { data } = await apiClient.get<MarketplacePaymentIntent>(`${base}/payment-intents/${id}`)
    return data
  },
  async verifyPaymentIntent(id: number): Promise<MarketplacePaymentIntent> {
    const { data } = await apiClient.post<MarketplacePaymentIntent>(`${base}/payment-intents/${id}/verify`)
    return data
  },
  async setStatus(id: number, status: Listing['status']): Promise<Listing> {
    const { data } = await apiClient.patch<Listing>(`${base}/listings/${id}`, { status })
    return data
  },
  async terminate(id: number): Promise<RentalOrder> {
    const { data } = await apiClient.post<RentalOrder>(`${base}/orders/${id}/terminate`)
    return data
  },
  async service(id: number): Promise<RentalService> {
    const { data } = await apiClient.get<RentalService>(`${base}/orders/${id}/service`)
    return data
  },
  async orderUsage(id: number, page = 1, pageSize = 20): Promise<OrderUsagePage> {
    const { data } = await apiClient.get<OrderUsagePage>(`${base}/orders/${id}/usage`, { params: { page, page_size: pageSize } })
    return data
  },
}

export function percentToBps(value: string): number | null {
  if (!/^\d+(?:\.\d{1,2})?$/.test(value)) return null
  const [whole, fraction = ''] = value.split('.')
  const bps = Number(whole) * 100 + Number(fraction.padEnd(2, '0'))
  return Number.isSafeInteger(bps) && bps >= 0 && bps <= 10000 ? bps : null
}

export function priceToCents(value: string): number | null {
  if (!/^\d+(?:\.\d{1,2})?$/.test(value)) return null
  const [whole, fraction = ''] = value.split('.')
  const cents = Number(whole) * 100 + Number(fraction.padEnd(2, '0'))
  return Number.isSafeInteger(cents) && cents > 0 ? cents : null
}

export function parseQuotaLimit(value: string): number | null {
  const trimmed = value.trim()
  if (!/^\d+(?:\.\d{1,8})?$/.test(trimmed)) return null
  const amount = Number(trimmed)
  if (!Number.isFinite(amount) || amount < 0.01 || amount > 1000000) return null
  return amount
}

export function extractShortfallMetadata(error: unknown): CheckoutShortfallMetadata | null {
  if (!error || typeof error !== 'object') return null
  const err = error as { status?: number; code?: number | string; reason?: string; metadata?: Record<string, unknown> }
  const isBalance402 = err.status === 402 || err.code === 402 || err.reason === 'MARKETPLACE_BALANCE'
  if (!isBalance402 || !err.metadata) return null
  const priceCents = Number(err.metadata.price_cents)
  const availCents = Number(err.metadata.available_balance_cents)
  const shortfallCents = Number(err.metadata.shortfall_cents)
  const paymentEnabled = err.metadata.payment_enabled === true || err.metadata.payment_enabled === 'true'
  if (!Number.isFinite(shortfallCents) || shortfallCents <= 0) return null
  return {
    price_cents: Number.isFinite(priceCents) ? priceCents : shortfallCents,
    available_balance_cents: Number.isFinite(availCents) ? availCents : 0,
    shortfall_cents: shortfallCents,
    payment_enabled: paymentEnabled,
  }
}
