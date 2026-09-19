import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import MarketplaceView from '../MarketplaceView.vue'
import type { Listing, RentalOrder } from '../types'

const { api, auth, showSuccess } = vi.hoisted(() => ({
  api: { listings: vi.fn(), orders: vi.fn(), resources: vi.fn(), publish: vi.fn(), checkout: vi.fn(), setStatus: vi.fn(), terminate: vi.fn(), service: vi.fn(), settings: vi.fn(), updateSettings: vi.fn(), revenue: vi.fn() },
  auth: { isAdmin: false, user: { id: 1 } },
  showSuccess: vi.fn(),
}))
vi.mock('@/stores/auth', () => ({ useAuthStore: () => auth }))
vi.mock('@/stores/app', () => ({ useAppStore: () => ({ showSuccess, showError: vi.fn() }) }))
vi.mock('../api', async importOriginal => ({ ...await importOriginal<typeof import('../api')>(), marketplaceAPI: api }))

const listing: Listing = { id: 10, seller_id: 2, resource_type: 'account', title: '共享账号', description: '用于开发', duration_hours: 24, price_cents: 1250, capacity: 2, active_rentals: 0, status: 'active' }
const order: RentalOrder = { id: 30, listing_id: 10, buyer_id: 1, seller_id: 2, title: '共享账号', resource_type: 'account', price_cents: 1250, status: 'active', starts_at: '2026-09-13T00:00:00Z', ends_at: '2026-09-14T00:00:00Z', group_id: 90, refund_cents: 0, seller_earned_cents: 0 }

function render() {
  return mount(MarketplaceView, {
    global: { stubs: {
      AppLayout: { template: '<main><slot /></main>' },
      BaseDialog: { props: ['show', 'title'], template: '<section v-if="show" role="dialog"><h2>{{ title }}</h2><slot /><slot name="footer" /></section>' },
      RouterLink: { props: ['to'], template: '<a :href="to"><slot /></a>' },
    } },
  })
}
async function click(wrapper: ReturnType<typeof render>, text: string) {
  const button = wrapper.findAll('button').find(item => item.text() === text)
  expect(button, `button ${text}`).toBeTruthy()
  await button!.trigger('click')
  await flushPromises()
}

describe('Marketplace', () => {
  it('keeps usage revenue separate from rent and preserves microcharges', async () => {
    api.revenue.mockResolvedValue({ gross_amount: 0.00000001, available_income: 0, pending_income: 0.00000001, platform_amount: 0 })
    const wrapper = render()
    await flushPromises()
    await click(wrapper, '我的上架')
    const summary = wrapper.get('[aria-label="用量收入"]')
    expect(summary.text()).toContain('$0.00000001')
    expect(summary.text()).toContain('出租方待收款')
    expect(summary.text()).toContain('平台用量应计抽成')
    wrapper.unmount()
  })
  it('uses the layout title without a duplicate content heading', async () => {
    const wrapper = render()
    await flushPromises()
    expect(wrapper.find('h1').exists()).toBe(false)
    expect(wrapper.find('#market-commission').exists()).toBe(false)
    wrapper.unmount()
  })
  it('validates admin percentages and sends exact basis points', async () => {
    auth.isAdmin = true
    const wrapper = render()
    await flushPromises()
    await click(wrapper, '平台管理')
    await wrapper.get('[data-testid="rent-commission"]').setValue('100.01')
    await wrapper.get('#market-commission').trigger('submit')
    expect(api.updateSettings).not.toHaveBeenCalled()
    await wrapper.get('[data-testid="rent-commission"]').setValue('1.25')
    await wrapper.get('[data-testid="usage-commission"]').setValue('0')
    await wrapper.get('#market-commission').trigger('submit')
    await flushPromises()
    expect(api.updateSettings).toHaveBeenCalledWith({ rent_commission_bps: 125, usage_commission_bps: 0 })
    wrapper.unmount()
  })
  it('displays settled platform commission separately from seller net income', async () => {
    api.orders.mockResolvedValue([{ ...order, status: 'completed', rent_commission_bps: 1000, platform_commission_cents: 125, seller_earned_cents: 1125 }])
    const wrapper = render()
    await flushPromises()
    await click(wrapper, '我的租赁')
    expect(wrapper.text()).toContain('平台已结算租金抽成$1.25（10%）')
    expect(wrapper.text()).toContain('出租方已结算净收入$11.25')
    wrapper.unmount()
  })
  it('shows unknown commission as unavailable rather than zero and allows retry', async () => {
    api.settings.mockRejectedValueOnce(new Error('rate unavailable'))
    const wrapper = render()
    await flushPromises()
    expect(wrapper.text()).toContain('rate unavailable')
    expect(wrapper.text()).not.toContain('平台抽成：租金 0%')
    await click(wrapper, '重新加载抽成设置')
    expect(wrapper.text()).toContain('平台抽成：租金 0%')
    wrapper.unmount()
  })
  beforeEach(() => {
    vi.resetAllMocks()
    auth.isAdmin = false
    api.settings.mockResolvedValue({ rent_commission_bps: 0, usage_commission_bps: 0 })
    api.revenue.mockResolvedValue({ gross_amount: 1.5, available_income: 1, pending_income: 0.4, platform_amount: 0.1 })
    api.updateSettings.mockImplementation(async value => value)
    api.listings.mockResolvedValue([listing])
    api.orders.mockResolvedValue([order])
    api.resources.mockResolvedValue({ accounts: [{ id: 5, name: '自己的账号', platform: 'openai' }], proxies: [{ id: 6, name: '自己的代理' }] })
    api.checkout.mockResolvedValue(order)
    api.publish.mockResolvedValue(listing)
    api.setStatus.mockResolvedValue({ ...listing, status: 'inactive' })
    api.terminate.mockResolvedValue({ ...order, status: 'terminated', refund_cents: 625 })
  })
  afterEach(() => { vi.unstubAllGlobals(); window.history.replaceState({}, '', '/') })

  it('previews fixture states and rejects checkout without touching real market APIs', async () => {
    window.history.replaceState({}, '', '/marketplace?demo=1')
    const wrapper = render()
    await flushPromises()
    expect(wrapper.text()).toContain('演示预览')
    expect(wrapper.findAll('[data-listing]')).toHaveLength(5)
    expect(wrapper.text()).toContain('名额已满')
    await click(wrapper, '租用此资源')
    await wrapper.get('[data-testid="confirm-checkout"]').trigger('click')
    await flushPromises()
    expect(wrapper.get('[role="dialog"]').text()).toContain('演示数据仅供预览')
    await click(wrapper, '取消')
    await click(wrapper, '我的租赁')
    expect(wrapper.findAll('[data-order]')).toHaveLength(4)
    expect(wrapper.text()).toContain('已完成')
    expect(wrapper.text()).toContain('已终止')
    expect(wrapper.find('a[href="/keys"]').exists()).toBe(false)
    expect(wrapper.find('a[href="/accounts"]').exists()).toBe(false)
    await click(wrapper, '服务详情')
    expect(wrapper.get('[role="dialog"]').text()).toContain('680 ms')
    expect(wrapper.find('a[href="/keys"]').exists()).toBe(false)
    for (const method of Object.values(api)) expect(method).not.toHaveBeenCalled()
    wrapper.unmount()
  })

  it('preserves the checkout key through retries and starts a fresh attempt after success', async () => {
    const uuid = vi.fn().mockReturnValueOnce('attempt-1').mockReturnValueOnce('attempt-2')
    vi.stubGlobal('crypto', { randomUUID: uuid })
    api.checkout.mockRejectedValueOnce(new Error('network interrupted')).mockResolvedValue(order)
    const wrapper = render()
    await flushPromises()
    await click(wrapper, '租用此资源')
    expect(api.checkout).not.toHaveBeenCalled()
    expect(wrapper.get('[role="dialog"]').text()).toContain('$12.50')
    await wrapper.get('[data-testid="confirm-checkout"]').trigger('click')
    await flushPromises()
    expect(wrapper.get('[role="alert"]').text()).toContain('network interrupted')
    await wrapper.get('[data-testid="confirm-checkout"]').trigger('click')
    await flushPromises()
    expect(api.checkout.mock.calls).toEqual([[10, 'attempt-1'], [10, 'attempt-1']])
    await click(wrapper, '浏览市场')
    await click(wrapper, '租用此资源')
    await wrapper.get('[data-testid="confirm-checkout"]').trigger('click')
    await flushPromises()
    expect(api.checkout).toHaveBeenLastCalledWith(10, 'attempt-2')
    wrapper.unmount()
  })

  it('uses a different key when choosing a different listing after failure', async () => {
    vi.stubGlobal('crypto', { randomUUID: vi.fn().mockReturnValueOnce('first').mockReturnValueOnce('second') })
    api.listings.mockResolvedValue([listing, { ...listing, id: 11 }])
    api.checkout.mockRejectedValue(new Error('unavailable'))
    const wrapper = render()
    await flushPromises()
    await wrapper.get('[data-listing="10"] .btn-primary').trigger('click')
    await wrapper.get('[data-testid="confirm-checkout"]').trigger('click')
    await flushPromises()
    await click(wrapper, '取消')
    await wrapper.get('[data-listing="11"] .btn-primary').trigger('click')
    await wrapper.get('[data-testid="confirm-checkout"]').trigger('click')
    await flushPromises()
    expect(api.checkout.mock.calls).toEqual([[10, 'first'], [11, 'second']])
    wrapper.unmount()
  })

  it('publishes an owned resource with exact cents and does not send resource secrets', async () => {
    api.resources.mockResolvedValue({ accounts: [{ id: 5, name: '自己的账号', platform: 'openai', credentials: { api_key: 'never-render-me' } }], proxies: [] })
    const wrapper = render()
    await flushPromises()
    await click(wrapper, '发布租赁')
    const form = wrapper.get('#market-publish')
    await form.findAll('select')[1].setValue('5')
    await form.findAll('input')[0].setValue('我的服务')
    await form.findAll('input')[2].setValue('0.29')
    await form.get('[data-testid="usage-multiplier"]').setValue('0')
    await form.trigger('submit')
    expect(api.publish).not.toHaveBeenCalled()
    await form.get('[data-testid="usage-multiplier"]').setValue('2.5')
    await form.trigger('submit')
    await flushPromises()
    expect(api.publish).toHaveBeenCalledWith({ resource_type: 'account', resource_id: 5, title: '我的服务', description: '', duration_hours: 24, price_cents: 29, capacity: 1, usage_rate_multiplier: 2.5 })
    expect(wrapper.html()).not.toContain('never-render-me')
    expect(api.listings).toHaveBeenLastCalledWith('mine')
    wrapper.unmount()
  })

  it('loads administrator scope only when the administrator selects management', async () => {
    const userWrapper = render()
    await flushPromises()
    expect(userWrapper.text()).not.toContain('平台管理')
    expect(api.listings).toHaveBeenCalledWith('market')
    expect(api.listings).not.toHaveBeenCalledWith('all')
    userWrapper.unmount()
    auth.isAdmin = true
    const adminWrapper = render()
    await flushPromises()
    await click(adminWrapper, '平台管理')
    expect(api.listings).toHaveBeenLastCalledWith('all')
    await click(adminWrapper, '下架')
    expect(api.setStatus).toHaveBeenCalledWith(10, 'inactive')
    adminWrapper.unmount()
  })

  it('confirms termination and uses server refund rather than estimating a credit', async () => {
    const wrapper = render()
    await flushPromises()
    await click(wrapper, '我的租赁')
    await click(wrapper, '提前终止')
    expect(api.terminate).not.toHaveBeenCalled()
    expect(wrapper.get('[role="dialog"]').text()).toContain('按比例退款')
    await click(wrapper, '确认终止')
    expect(api.terminate).toHaveBeenCalledWith(30)
    expect(showSuccess).toHaveBeenCalledWith('租赁已终止，退还租金 $6.25')
    wrapper.unmount()
  })

  it('shows service errors without inventing health or exposing unknown backend properties', async () => {
    api.service.mockRejectedValueOnce(new Error('temporarily unavailable')).mockResolvedValue({ group_id: 90, group_name: '租赁分组', platform: 'openai', accounts: [{ id: 'alias-1', name: '服务账号', status: 'active', credentials: 'secret-account' }], test_reports: [], proxy_password: 'secret-proxy' })
    const wrapper = render()
    await flushPromises()
    await click(wrapper, '我的租赁')
    await click(wrapper, '服务详情')
    expect(wrapper.get('[role="dialog"]').text()).toContain('temporarily unavailable')
    await click(wrapper, '重试')
    expect(wrapper.get('[role="dialog"]').text()).toContain('首字 暂无数据')
    expect(wrapper.html()).not.toContain('secret-account')
    expect(wrapper.html()).not.toContain('secret-proxy')
    expect(wrapper.find('a[href="/keys"]').exists()).toBe(true)
    wrapper.unmount()
  })

  it('shows load failure instead of misleading empty inventory', async () => {
    api.listings.mockRejectedValue(new Error('market unavailable'))
    const wrapper = render()
    await flushPromises()
    expect(wrapper.get('[role="alert"]').text()).toContain('market unavailable')
    expect(wrapper.text()).not.toContain('暂无符合条件的租赁')
    wrapper.unmount()
  })
})
