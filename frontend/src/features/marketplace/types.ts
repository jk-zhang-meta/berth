export type ResourceType = 'account' | 'proxy'
export type ListingScope = 'market' | 'mine' | 'all'
export interface UsageRevenue {
  gross_amount: number
  available_income: number
  pending_income: number
  platform_amount: number
}
export interface CommissionSettings {
  rent_commission_bps: number
  usage_commission_bps: number
}

// Public market DTOs intentionally exclude account credentials and proxy addresses.
export interface Listing {
  id: number
  seller_id: number
  resource_type: ResourceType
  title: string
  description: string
  duration_hours: number
  price_cents: number
  capacity: number
  active_rentals: number
  usage_rate_multiplier?: number
  status: 'active' | 'inactive' | 'paused' | 'removed'
  admin_suspended?: boolean
  group_id?: number
}

export interface RentalOrder {
  id: number
  listing_id: number
  buyer_id: number
  seller_id: number
  title: string
  resource_type: ResourceType
  price_cents: number
  status: 'active' | 'completed' | 'terminated'
  starts_at: string
  ends_at: string
  group_id?: number
  rental_proxy_id?: number
  seller_earned_cents: number
  platform_commission_cents?: number
  rent_commission_bps?: number
  refund_cents: number
}

export interface OwnedResources {
  accounts: { id: number; name: string; platform: string }[]
  proxies: { id: number; name: string }[]
}

export interface PublishListing {
  usage_rate_multiplier?: number
  resource_type: ResourceType
  resource_id: number
  title: string
  description: string
  duration_hours: number
  price_cents: number
  capacity: number
}

export interface RentalService {
  group_id: number
  group_name: string
  platform: string
  accounts: {
    id: string
    name: string
    status: string
    first_token_ms?: number
    duration_ms?: number
  }[]
  test_reports: { kind: string; status: string; latency_ms?: number; created_at: string }[]
}
