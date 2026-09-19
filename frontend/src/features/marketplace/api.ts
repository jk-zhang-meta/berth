import { apiClient } from '@/api/client'
import type { UsageRevenue, CommissionSettings, Listing, ListingScope, OwnedResources, PublishListing, RentalOrder, RentalService } from './types'

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
  async checkout(id: number, idempotencyKey: string): Promise<RentalOrder> {
    const { data } = await apiClient.post<RentalOrder>(`${base}/listings/${id}/checkout`, { idempotency_key: idempotencyKey })
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
