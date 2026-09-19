import type { marketplaceAPI } from './api'
import type { Listing, RentalOrder } from './types'

// Preview fixtures never reach the server or change a wallet.
export function createMarketplaceDemo(userID: number): typeof marketplaceAPI {
  const seller = userID + 1000000
  const now = Date.now()
  const date = (hours: number) => new Date(now + hours * 3600000).toISOString()
  const listings: Listing[] = [
    { id: 901, seller_id: seller, resource_type: 'account', title: 'Claude · 日常编程', description: '演示 · 适合代码补全、文档整理与日常问答。按天租用，轻量开始。', duration_hours: 24, price_cents: 390, capacity: 5, active_rentals: 2, usage_rate_multiplier: 1, status: 'active' },
    { id: 902, seller_id: seller, resource_type: 'account', title: 'Codex · 团队开发周卡', description: '演示 · 连续一周的开发窗口，查看满额时的卡片与操作状态。', duration_hours: 168, price_cents: 2490, capacity: 3, active_rentals: 3, usage_rate_multiplier: 1.2, status: 'active' },
    { id: 903, seller_id: userID, resource_type: 'account', title: 'Gemini · 长上下文体验', description: '演示 · 这是你上架的服务，适合查看自己的商品与收入区域。', duration_hours: 72, price_cents: 890, capacity: 4, active_rentals: 1, usage_rate_multiplier: 0.8, status: 'active' },
    { id: 904, seller_id: seller, resource_type: 'proxy', title: '日本东京 · HTTP 代理', description: '演示 · 仅供本站账号绑定，租用方不接触代理密码。', duration_hours: 24, price_cents: 150, capacity: 10, active_rentals: 4, status: 'active' },
    { id: 905, seller_id: userID, resource_type: 'proxy', title: '美国西部 · SOCKS5 代理', description: '演示 · 一周固定租期，适合查看自己出租的代理资源。', duration_hours: 168, price_cents: 690, capacity: 6, active_rentals: 0, status: 'active' },
    { id: 906, seller_id: userID, resource_type: 'account', title: 'Grok · 暂停出租', description: '演示 · 管理员已下架，展示暂停状态与管理权限。', duration_hours: 48, price_cents: 590, capacity: 2, active_rentals: 0, usage_rate_multiplier: 1.1, status: 'paused', admin_suspended: true },
  ]
  const orders: RentalOrder[] = [
    { id: 1001, listing_id: 901, buyer_id: userID, seller_id: seller, title: '演示 · Claude 日常编程', resource_type: 'account', price_cents: 390, status: 'active', starts_at: date(-6), ends_at: date(18), group_id: 901, seller_earned_cents: 0, refund_cents: 0, platform_commission_cents: 0, rent_commission_bps: 500 },
    { id: 1002, listing_id: 904, buyer_id: userID, seller_id: seller, title: '演示 · 东京 HTTP 代理', resource_type: 'proxy', price_cents: 150, status: 'active', starts_at: date(-20), ends_at: date(4), rental_proxy_id: 904, seller_earned_cents: 0, refund_cents: 0, platform_commission_cents: 0, rent_commission_bps: 500 },
    { id: 1003, listing_id: 903, buyer_id: seller, seller_id: userID, title: '演示 · Gemini 已完成订单', resource_type: 'account', price_cents: 890, status: 'completed', starts_at: date(-96), ends_at: date(-24), group_id: 903, seller_earned_cents: 846, refund_cents: 0, platform_commission_cents: 44, rent_commission_bps: 500 },
    { id: 1004, listing_id: 905, buyer_id: seller, seller_id: userID, title: '演示 · 西部代理提前退款', resource_type: 'proxy', price_cents: 690, status: 'terminated', starts_at: date(-120), ends_at: date(-24), rental_proxy_id: 905, seller_earned_cents: 328, refund_cents: 345, platform_commission_cents: 17, rent_commission_bps: 500 },
  ]
  const readonly = async (): Promise<never> => { throw new Error('演示数据仅供预览，请返回真实市场后操作。') }
  return {
    listings: async scope => structuredClone(listings.filter(v => scope === 'mine' ? v.seller_id === userID : scope === 'market' ? v.status === 'active' : true)),
    orders: async () => structuredClone(orders),
    settings: async () => ({ rent_commission_bps: 500, usage_commission_bps: 1000 }),
    revenue: async () => ({ gross_amount: 128.4567, available_income: 105.61, pending_income: 10.00103, platform_amount: 12.84567 }),
    resources: async () => ({ accounts: [{ id: 903, name: '演示 Gemini 账号', platform: 'gemini' }], proxies: [{ id: 905, name: '演示 SOCKS5 代理' }] }),
    service: async () => ({ group_id: 901, group_name: '演示 · Claude 服务组', platform: 'claude', accounts: [{ id: 'resource-1', name: '演示账号', status: 'active', first_token_ms: 680, duration_ms: 3240 }], test_reports: [{ kind: 'scheduled', status: 'success', latency_ms: 720, created_at: date(-2) }] }),
    publish: readonly, checkout: readonly, setStatus: readonly, terminate: readonly, updateSettings: readonly,
  }
}
