import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount } from '@vue/test-utils'
import ProxySelector from '../ProxySelector.vue'
import type { Proxy } from '@/types'

const testProxyMock = vi.fn()

vi.mock('@/api/admin', () => ({
  adminAPI: {
    proxies: {
      testProxy: (...args: unknown[]) => testProxyMock(...args)
    }
  }
}))

vi.mock('vue-i18n', () => ({
  useI18n: () => ({
    t: (key: string) => key
  })
}))

const ownedProxy: Proxy = {
  id: 1,
  name: 'Owned US',
  protocol: 'http',
  host: '203.0.113.10',
  port: 8080,
  username: 'u',
  status: 'active',
  max_accounts: 5,
  max_rpm: 60,
  max_concurrency: 10,
  expires_at: null,
  fallback_mode: 'none',
  expiry_warn_days: 7,
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-01-01T00:00:00Z'
}

const rentedProxy: Proxy = {
  id: 2,
  name: 'Tokyo Rental',
  protocol: 'socks5',
  host: '',
  port: 0,
  username: null,
  status: 'active',
  is_rental: true,
  rental_order_id: 99,
  timezone: 'Asia/Tokyo',
  country_code: 'JP',
  max_accounts: 3,
  max_rpm: 60,
  max_concurrency: 6,
  expires_at: null,
  fallback_mode: 'none',
  expiry_warn_days: 7,
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-01-01T00:00:00Z'
}

describe('ProxySelector (Track B)', () => {
  beforeEach(() => {
    testProxyMock.mockReset()
    testProxyMock.mockResolvedValue({ success: true, message: 'ok', latency_ms: 25 })
  })

  it('hides No Proxy option when allowDirect is false and shows it when true', async () => {
    const wrapperStrict = mount(ProxySelector, {
      props: { modelValue: null, proxies: [ownedProxy], allowDirect: false },
      global: { stubs: { Icon: true } }
    })
    await wrapperStrict.find('button.select-trigger').trigger('click')
    expect(wrapperStrict.text()).not.toContain('admin.accounts.noProxy')

    const wrapperAdmin = mount(ProxySelector, {
      props: { modelValue: null, proxies: [ownedProxy], allowDirect: true },
      global: { stubs: { Icon: true } }
    })
    await wrapperAdmin.find('button.select-trigger').trigger('click')
    expect(wrapperAdmin.text()).toContain('admin.accounts.noProxy')
  })

  it('renders rented proxy badge without host:port and skips rented proxy in batch test', async () => {
    const wrapper = mount(ProxySelector, {
      props: { modelValue: 2, proxies: [ownedProxy, rentedProxy], allowDirect: false },
      global: { stubs: { Icon: true } }
    })
    expect(wrapper.find('button.select-trigger').text()).toContain('Tokyo Rental (Asia/Tokyo)')
    expect(wrapper.find('button.select-trigger').text()).not.toContain('://:0')

    await wrapper.find('button.select-trigger').trigger('click')
    expect(wrapper.text()).toContain('Rented')
    expect(wrapper.text()).not.toContain('socks5://:0')

    // Only ownedProxy (id=1) should have an individual test button
    expect(wrapper.findAll('button.test-btn')).toHaveLength(1)

    // Batch test should only call testProxy for ownedProxy (id=1), never rentedProxy (id=2)
    await wrapper.find('button.batch-test-btn').trigger('click')
    expect(testProxyMock).toHaveBeenCalledTimes(1)
    expect(testProxyMock).toHaveBeenCalledWith(1)
  })
})
