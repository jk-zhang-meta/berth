import { expect, it } from 'vitest'
import { createMarketplaceDemo } from '../demo'

it('keeps all preview mutations read-only and settlement examples balanced', async () => {
  const demo = createMarketplaceDemo(7)
  for (const mutation of [() => demo.checkout(901, 'test'), () => demo.terminate(1001), () => demo.setStatus(901, 'paused'), () => demo.updateSettings({ rent_commission_bps: 0, usage_commission_bps: 0 }), () => demo.publish({ resource_type: 'account', resource_id: 903, title: 'x', description: '', duration_hours: 24, price_cents: 100, capacity: 1 })]) {
    await expect(mutation()).rejects.toThrow('演示数据仅供预览')
  }
  for (const order of await demo.orders()) if (order.status !== 'active') expect(order.seller_earned_cents + order.refund_cents + (order.platform_commission_cents ?? 0)).toBe(order.price_cents)
  expect(await demo.listings('mine')).toHaveLength(3)
  expect(await demo.listings('all')).toHaveLength(6)
})
