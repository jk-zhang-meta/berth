import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import MarketplaceCheckoutDialog from '../MarketplaceCheckoutDialog.vue'
import type { Listing } from '../types'

const { paymentAPI, marketAPI } = vi.hoisted(() => ({
  paymentAPI: { getCheckoutInfo: vi.fn() },
  marketAPI: {
    checkoutPayment: vi.fn(),
    getPaymentIntent: vi.fn(),
    verifyPaymentIntent: vi.fn(),
  },
}))

vi.mock('@/api/payment', () => ({ paymentAPI }))
vi.mock('../api', async importOriginal => ({
  ...await importOriginal<typeof import('../api')>(),
  marketplaceAPI: marketAPI,
}))
vi.mock('qrcode', () => ({ default: { toCanvas: vi.fn().mockResolvedValue(undefined) } }))

const listing: Listing = {
  id: 10,
  seller_id: 2,
  resource_type: 'account',
  title: '按额度账号',
  description: '',
  rental_mode: 'quota',
  duration_hours: null,
  quota_limit_usd: 20,
  price_cents: 1250,
  capacity: 2,
  active_rentals: 0,
  status: 'active',
}

function mountDialog(props: Record<string, unknown> = {}) {
  return mount(MarketplaceCheckoutDialog, {
    props: {
      show: true,
      listing,
      idempotencyKey: 'idem-1',
      shortfall: { price_cents: 1250, available_balance_cents: 400, shortfall_cents: 850, payment_enabled: true },
      ...props,
    },
    global: {
      stubs: {
        BaseDialog: {
          props: ['show', 'title'],
          template: '<section v-if="show" role="dialog"><h2>{{ title }}</h2><slot /><slot name="footer" /></section>',
        },
        PaymentMethodSelector: {
          props: ['methods', 'selected'],
          emits: ['select'],
          template: '<div><button v-for="m in methods" :key="m.type" type="button" :data-method="m.type" @click="$emit(\'select\', m.type)">{{ m.display_name || m.type }}</button></div>',
        },
        StripePaymentInline: { template: '<div data-testid="stripe-inline"></div>' },
      },
    },
  })
}

describe('MarketplaceCheckoutDialog', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    vi.resetAllMocks()
    vi.stubGlobal('open', vi.fn())
    paymentAPI.getCheckoutInfo.mockResolvedValue({
      data: {
        balance_disabled: false,
        methods: {
          alipay: { display_name: '支付宝', fee_rate: 0, available: true, min_amount: 1, max_amount: 10000 },
        },
      },
    })
  })

  afterEach(() => {
    vi.useRealTimers()
    vi.unstubAllGlobals()
  })

  it('displays shortfall breakdown, creates payment intent, polls read-only GET and emits completed', async () => {
    marketAPI.checkoutPayment.mockResolvedValue({
      mode: 'payment_required',
      intent_id: 55,
      shortfall_cents: 850,
      payment: { order_id: 900, amount: 8.5, pay_amount: 8.5, currency: 'CNY', qr_code: 'https://qr.example/pay' },
    })
    marketAPI.getPaymentIntent
      .mockResolvedValueOnce({ id: 55, listing_id: 10, payment_order_id: 900, shortfall_cents: 850, topup_credited_usd: 0, status: 'pending' })
      .mockResolvedValueOnce({
        id: 55,
        listing_id: 10,
        payment_order_id: 900,
        marketplace_order_id: 301,
        shortfall_cents: 850,
        topup_credited_usd: 8.5,
        status: 'completed',
        marketplace_order: { id: 301, listing_id: 10, buyer_id: 1, seller_id: 2, title: '按额度账号', resource_type: 'account', price_cents: 1250, status: 'active', starts_at: '2026-09-13T00:00:00Z', ends_at: null, refund_cents: 0, seller_earned_cents: 0 },
      })

    const wrapper = mountDialog()
    await flushPromises()
    expect(wrapper.get('[data-testid="shortfall-amount"]').text()).toBe('$8.50')

    await wrapper.get('[data-testid="start-shortfall-payment"]').trigger('click')
    await flushPromises()
    expect(marketAPI.checkoutPayment).toHaveBeenCalledWith(10, expect.objectContaining({
      idempotency_key: 'idem-1',
      payment_type: 'alipay',
    }))

    await vi.advanceTimersByTimeAsync(2500)
    await flushPromises()
    expect(marketAPI.getPaymentIntent).toHaveBeenCalledWith(55)
    expect(marketAPI.verifyPaymentIntent).not.toHaveBeenCalled()

    await vi.advanceTimersByTimeAsync(2500)
    await flushPromises()
    expect(wrapper.emitted('completed')?.[0]?.[0]).toMatchObject({ id: 301 })
    wrapper.unmount()
  })

  it('explicitly calls POST /verify on button click and renders safe balance-credited alert on checkout_failed', async () => {
    marketAPI.checkoutPayment.mockResolvedValue({
      mode: 'payment_required',
      intent_id: 66,
      shortfall_cents: 850,
      payment: { order_id: 901, amount: 8.5, pay_amount: 8.5, currency: 'CNY', pay_url: 'https://pay.example/order' },
    })
    marketAPI.verifyPaymentIntent.mockResolvedValue({
      id: 66,
      listing_id: 10,
      payment_order_id: 901,
      shortfall_cents: 850,
      topup_credited_usd: 8.5,
      status: 'checkout_failed',
      failure_code: 'MARKETPLACE_CAPACITY',
      failure_message: 'listing has no available capacity',
    })

    const wrapper = mountDialog()
    await flushPromises()
    await wrapper.get('[data-testid="start-shortfall-payment"]').trigger('click')
    await flushPromises()

    await wrapper.get('[data-testid="verify-payment-intent"]').trigger('click')
    await flushPromises()
    expect(marketAPI.verifyPaymentIntent).toHaveBeenCalledWith(66)
    expect(wrapper.get('[role="alert"]').text()).toContain('支付已成功入账，但租赁未能自动开通')
    expect(wrapper.get('[role="alert"]').text()).toContain('$8.50')
    expect(wrapper.emitted('balanceCredited')?.[0]?.[0]).toMatchObject({ id: 66, status: 'checkout_failed' })
    wrapper.unmount()
  })

  it('completes immediately when backend returns mode=balance_completed', async () => {
    marketAPI.checkoutPayment.mockResolvedValue({
      mode: 'balance_completed',
      order: { id: 400, listing_id: 10, buyer_id: 1, seller_id: 2, title: '按额度账号', resource_type: 'account', price_cents: 1250, status: 'active', starts_at: '2026-09-13T00:00:00Z', ends_at: null, refund_cents: 0, seller_earned_cents: 0 },
    })
    const wrapper = mountDialog()
    await flushPromises()
    await wrapper.get('[data-testid="start-shortfall-payment"]').trigger('click')
    await flushPromises()
    expect(wrapper.emitted('completed')?.[0]?.[0]).toMatchObject({ id: 400 })
    wrapper.unmount()
  })
})
