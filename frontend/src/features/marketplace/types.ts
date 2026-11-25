import type { CreateOrderResult } from '@/types/payment'

export type ResourceType = 'account' | 'proxy'
export type RentalMode = 'duration' | 'quota' | 'hybrid'
export type ListingVisibility = 'public' | 'targeted'
export type ListingScope = 'market' | 'offers' | 'mine' | 'all'
export type CompletionReason =
  | 'time_expired'
  | 'quota_exhausted'
  | 'buyer_terminated'
  | 'seller_terminated'
  | 'admin_terminated'
export type PaymentIntentStatus = 'pending' | 'completed' | 'checkout_failed' | 'cancelled' | 'expired'

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
  rental_mode?: RentalMode
  duration_hours?: number | null
  quota_limit_usd?: number | null
  price_cents: number
  capacity: number
  active_rentals: number
  usage_rate_multiplier?: number
  visibility?: ListingVisibility
  target_buyer_id?: number | null
  target_buyer_label?: string
  declined_at?: string | null
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
  rental_mode?: RentalMode
  duration_hours?: number | null
  quota_limit_usd?: number | null
  quota_used_usd?: number
  quota_reserved_usd?: number
  price_cents: number
  status: 'active' | 'completed' | 'terminated'
  completion_reason?: CompletionReason | null
  starts_at: string
  ends_at?: string | null
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
  rental_mode?: RentalMode
  duration_hours?: number
  quota_limit_usd?: number
  price_cents: number
  capacity: number
  visibility?: ListingVisibility
  target_buyer?: string
  target_buyer_id?: number
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

export interface OrderUsageItem {
  request_id: string
  amount_usd: number
  quota_used_after_usd: number
  admitted_at: string
  created_at: string
}

export interface OrderUsagePage {
  items: OrderUsageItem[]
  total: number
  page: number
  page_size: number
  quota_used_usd: number
  quota_limit_usd?: number | null
}

export interface CheckoutShortfallMetadata {
  price_cents: number
  available_balance_cents: number
  shortfall_cents: number
  payment_enabled: boolean
}

export interface CheckoutPaymentPayload {
  idempotency_key: string
  payment_type: string
  return_url?: string
  openid?: string
  wechat_resume_token?: string
  payment_source?: string
  is_mobile?: boolean
}

export interface CheckoutPaymentResult {
  mode: 'balance_completed' | 'payment_required'
  intent_id?: number
  shortfall_cents?: number
  order?: RentalOrder
  payment?: CreateOrderResult
}

export interface MarketplacePaymentIntent {
  id: number
  payment_order_id: number
  out_trade_no: string
  payment_status: string
  payment_type: string
  pay_amount: number
  buyer_id: number
  listing_id: number
  listing_price_cents: number
  shortfall_cents: number
  topup_credited_usd: number
  status: PaymentIntentStatus
  marketplace_order_id?: number | null
  marketplace_order?: RentalOrder | null
  failure_code?: string
  failure_message?: string
  created_at: string
  updated_at: string
  completed_at?: string | null
}
