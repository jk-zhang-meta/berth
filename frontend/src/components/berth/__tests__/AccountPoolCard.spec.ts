import { describe, expect, it, vi, afterEach } from 'vitest'
import { mount, DOMWrapper, flushPromises } from '@vue/test-utils'
import { adminAPI } from '@/api'
import { defineComponent } from 'vue'
import AccountPoolCard from '../AccountPoolCard.vue'
import type { AccountListItem } from '@/types'

afterEach(() => {
  document.body.innerHTML = ''
  vi.mocked(adminAPI.accounts.update).mockReset().mockImplementation(async (id, updates) => ({ id, ...updates }) as AccountListItem)
})

vi.mock('vue-i18n', async () => {
  const actual = await vi.importActual<typeof import('vue-i18n')>('vue-i18n')
  return {
    ...actual,
    useI18n: () => ({
      t: (key: string) => key
    })
  }
})

vi.mock('@/composables/useClipboard', () => ({
  useClipboard: () => ({
    copied: { value: false },
    copyToClipboard: vi.fn()
  })
}))

vi.mock('@/api', () => ({
  adminAPI: {
    accounts: {
      update: vi.fn().mockImplementation((id: number, updates: any) => Promise.resolve({ id, ...updates }))
    }
  }
}))

const UsageStub = defineComponent({
  name: 'AccountUsageCell',
  props: ['account'],
  template: '<div data-test="usage-windows">5h 7d</div>'
})

const StatusStub = defineComponent({
  name: 'AccountStatusIndicator',
  props: ['account'],
  template: '<span data-test="status-pill">生效</span>'
})

function makeAccount(overrides: Partial<AccountListItem> = {}): AccountListItem {
  return {
    id: 11,
    name: 'codex-plus',
    platform: 'openai',
    type: 'oauth',
    proxy_id: null,
    concurrency: 1,
    priority: 2,
    status: 'active',
    error_message: null,
    last_used_at: '2026-09-11T08:00:00Z',
    expires_at: null,
    auto_pause_on_expired: true,
    created_at: '2026-03-15T00:00:00Z',
    updated_at: '2026-03-15T00:00:00Z',
    schedulable: true,
    rate_limited_at: null,
    rate_limit_reset_at: null,
    overload_until: null,
    temp_unschedulable_until: null,
    temp_unschedulable_reason: null,
    session_window_start: null,
    session_window_end: null,
    session_window_status: null,
    extra: { email: 'plus@example.com' },
    credentials: { plan_type: 'plus' },
    owner_label: 'user@berth.local',
    first_token_ms: 420,
    rate_multiplier: 1,
    ...overrides
  }
}

describe('AccountPoolCard', () => {
  it('shows response duration independently of first-token availability', async () => {
    const wrapper = mount(AccountPoolCard, {
      props: { account: makeAccount({ first_token_ms: null, duration_ms: 2320 }) },
      global: { stubs: { AccountUsageCell: UsageStub, AccountStatusIndicator: StatusStub } }
    })
    expect(wrapper.get('.response-duration').text()).toContain('响应总耗时')
    expect(wrapper.get('.response-duration strong').text()).toBe('2.32s')
    expect(wrapper.get('.first-token').text()).toBe('--')
    await wrapper.setProps({ account: makeAccount({ duration_ms: null }) })
    expect(wrapper.get('.response-duration strong').text()).toBe('--')
  })
  it.each([true, false])('persists cleared notes and proxy for pool controls=%s', async (showPoolControls) => {
    let stored = makeAccount({ notes: 'old note', proxy_id: 10 })
    // Go pointer update semantics: null means omitted; zero clears the proxy.
    vi.mocked(adminAPI.accounts.update).mockImplementationOnce(async (_id, updates) => {
      if (updates.proxy_id != null) stored = { ...stored, proxy_id: updates.proxy_id || null, proxy: null }
      return stored
    }).mockImplementationOnce(async (_id, updates) => {
      if (updates.notes != null) stored = { ...stored, notes: updates.notes }
      return stored
    })
    const wrapper = mount(AccountPoolCard, {
      props: { account: stored, showPoolControls },
      global: { stubs: { AccountUsageCell: UsageStub, AccountStatusIndicator: StatusStub } }
    })
    await wrapper.get('select.proxy-select').setValue('')
    await flushPromises()
    expect(stored.proxy_id).toBeNull()
    await wrapper.setProps({ account: stored })
    expect((wrapper.get('select.proxy-select').element as HTMLSelectElement).value).toBe('')
    await wrapper.get('.notes-btn').trigger('click')
    const textarea = new DOMWrapper(document.body.querySelector('.notes-textarea') as HTMLTextAreaElement)
    expect(textarea.element.readOnly).toBe(false)
    await textarea.setValue('  ')
    await new DOMWrapper(document.body.querySelector('.notes-modal-content .btn-save') as HTMLButtonElement).trigger('click')
    await flushPromises()
    expect(stored.notes).toBe('')
    await wrapper.setProps({ account: stored })
    await wrapper.get('.notes-btn').trigger('click')
    expect((document.body.querySelector('.notes-textarea') as HTMLTextAreaElement).value).toBe('')
    wrapper.unmount()
  })

  it.each([true, false])('distinguishes unavailable, zero and stale statistics for pool controls=%s', async (showPoolControls) => {
    const wrapper = mount(AccountPoolCard, {
      props: { account: makeAccount(), showPoolControls, todayStatsError: 'failed' },
      global: { stubs: { AccountUsageCell: UsageStub, AccountStatusIndicator: StatusStub } }
    })
    expect(wrapper.get('.today-stats-panel').text()).toContain('加载失败')
    expect(wrapper.findAll('.stat-col strong').slice(0, 3).map(el => el.text())).toEqual(['--', '--', '--'])
    await wrapper.setProps({ todayStatsError: null, todayStats: { requests: 0, tokens: 0, cost: 0 } })
    expect(wrapper.findAll('.stat-col strong').slice(0, 3).map(el => el.text())).toEqual(['0', '0', '0.00'])
    await wrapper.setProps({ todayStatsError: 'failed', todayStats: { requests: 12, tokens: 30, cost: 1 } })
    expect(wrapper.get('.today-stats-panel').text()).toContain('刷新失败，显示上次数据')
    expect(wrapper.get('.stat-col strong').text()).toBe('12')
    expect(wrapper.find('.live-dot').exists()).toBe(false)
    wrapper.unmount()
  })

  it.each(['apikey', 'bedrock'] as const)('renders real quota bars for %s accounts', (type) => {
    const wrapper = mount(AccountPoolCard, {
      props: { account: makeAccount({ type, quota_daily_limit: 100, quota_daily_used: 25, quota_weekly_limit: 200, quota_weekly_used: 100, quota_limit: 1000, quota_used: 750 }) },
      global: { stubs: { AccountStatusIndicator: StatusStub } }
    })
    expect(wrapper.get('.card-quota').text()).toContain('25%')
    expect(wrapper.get('.card-quota').text()).toContain('50%')
    expect(wrapper.get('.card-quota').text()).toContain('75%')
    wrapper.unmount()
  })

  it('renders eligible Ollama usage through the real usage component', () => {
    const wrapper = mount(AccountPoolCard, {
      props: { account: makeAccount({ type: 'apikey', ollama_cloud_usage: { eligible: true, configured: true } as NonNullable<AccountListItem['ollama_cloud_usage']> }) },
      global: { stubs: { AccountStatusIndicator: StatusStub } }
    })
    expect(wrapper.get('[data-testid="ollama-cloud-usage-cell"]').exists()).toBe(true)
    expect(wrapper.get('[data-testid="ollama-cloud-usage-query"]').exists()).toBe(true)
    wrapper.unmount()
  })
  it('renders Personal Web card chrome with today metrics and 首字', () => {
    const wrapper = mount(AccountPoolCard, {
      props: {
        account: makeAccount(),
        todayStats: { requests: 12, tokens: 15600, cost: 1.5 },
        showPoolControls: true
      },
      global: {
        stubs: {
          AccountUsageCell: UsageStub,
          AccountStatusIndicator: StatusStub
        }
      }
    })

    expect(wrapper.get('[data-testid="account-pool-card"]').classes()).toContain('is-active')
    expect(wrapper.get('.email-plain').text()).toBe('plus@example.com')
    expect(wrapper.get('.provider-pill').text()).toContain('O')
    expect(wrapper.get('.provider-pill').text()).toContain('OpenAI')
    expect(wrapper.get('.plan-pill').text()).toBe('Plus')
    expect(wrapper.get('.relay-pill').text()).toBe('user@berth.local')
    expect(wrapper.get('[data-test="usage-windows"]').exists()).toBe(true)
    expect(wrapper.text()).toContain('#REQ')
    expect(wrapper.text()).toContain('12')
    expect(wrapper.text()).toContain('#TOKEN')
    expect(wrapper.text()).toContain('15.6K')
    expect(wrapper.text()).toContain('$COST')
    expect(wrapper.text()).toContain('1.50')
    expect(wrapper.text()).toContain('usage.latencyFirstToken')
    expect(wrapper.get('.first-token').text()).toBe('420ms')
    expect(wrapper.get('.first-token').classes()).toContain('is-good')
    expect(wrapper.get('.id-pill').text()).toBe('#11')
    expect(wrapper.get('.type-pill').text()).toBe('OAuth')
    expect(wrapper.get('.concurrency-pill').text()).toContain('0/1')
  })

  it('renders complete information: proxy, groups, notes, and expiration', async () => {
    const account = makeAccount({
      notes: '测试备注信息',
      proxy: {
        id: 5,
        name: '香港专线-01',
        country_code: 'HK',
        status: 'active',
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-01T00:00:00Z',
        expires_at: '2026-12-31T00:00:00Z'
      } as any,
      expires_at: 1800000000,
      auto_pause_on_expired: true
    })

    const wrapper = mount(AccountPoolCard, {
      props: {
        account,
        groups: [
          { id: 1, name: '默认分组' },
          { id: 2, name: 'VIP分组' }
        ]
      },
      global: {
        stubs: {
          AccountUsageCell: UsageStub,
          AccountStatusIndicator: StatusStub
        }
      }
    })

    // Proxy dropdown display
    expect(wrapper.get('.card-proxy-row').text()).toContain('香港专线-01')
    expect(wrapper.get('.card-proxy-row').text()).toContain('HK')
    const proxySelect = wrapper.get('select.proxy-select')
    expect(proxySelect.exists()).toBe(true)

    // Groups display
    expect(wrapper.get('.card-groups-row').text()).toContain('默认分组')
    expect(wrapper.get('.card-groups-row').text()).toContain('VIP分组')

    // Notes button display & click to show modal
    const notesBtn = wrapper.get('.notes-btn')
    expect(notesBtn.classes()).toContain('has-notes')
    expect(notesBtn.text()).toContain('备注')
    await notesBtn.trigger('click')
    const textarea = document.body.querySelector('.notes-textarea') as HTMLTextAreaElement
    expect(textarea?.value).toBe('测试备注信息')

    // Expiration display
    expect(wrapper.get('.account-times').text()).toContain('到期')
    expect(wrapper.get('.account-times').text()).toContain('自动暂停')
  })

  it('renders priority widget with edit button for pool controls', async () => {
    const account = makeAccount({ priority: 3 })
    const wrapper = mount(AccountPoolCard, {
      props: {
        account,
        showPoolControls: true
      },
      global: {
        stubs: {
          AccountUsageCell: UsageStub,
          AccountStatusIndicator: StatusStub
        }
      }
    })

    expect(wrapper.get('.priority-value').text()).toBe('P3')
    const editBtn = wrapper.get('.priority-edit-btn')
    expect(editBtn.exists()).toBe(true)
    await editBtn.trigger('click')
    expect(document.body.querySelector('.priority-modal-content')?.textContent).toContain('修改调度权值')
  })

  it('hides priority editing but permits owned proxy editing without pool controls', () => {
    const account = makeAccount({ priority: 3 })
    const wrapper = mount(AccountPoolCard, {
      props: {
        account,
        showPoolControls: false
      },
      global: {
        stubs: {
          AccountUsageCell: UsageStub,
          AccountStatusIndicator: StatusStub
        }
      }
    })

    expect(wrapper.get('.priority-value').text()).toBe('P3')
    expect(wrapper.find('.priority-edit-btn').exists()).toBe(false)
    const select = wrapper.get('select.proxy-select')
    expect((select.element as HTMLSelectElement).disabled).toBe(false)
  })

  it('renders today stats panel with user_cost and live indicator', () => {
    const account = makeAccount()
    const wrapper = mount(AccountPoolCard, {
      props: {
        account,
        todayStats: { requests: 25, tokens: 48000, cost: 3.2, user_cost: 5.8 },
        todayStatsLoading: false
      },
      global: {
        stubs: {
          AccountUsageCell: UsageStub,
          AccountStatusIndicator: StatusStub
        }
      }
    })

    expect(wrapper.get('.today-stats-panel').exists()).toBe(true)
    expect(wrapper.get('.stats-panel-title').text()).toContain('今日统计')
    expect(wrapper.get('.user-cost-tag').text()).toContain('5.80')
    expect(wrapper.text()).toContain('25')
    expect(wrapper.text()).toContain('48.0K')
    expect(wrapper.text()).toContain('3.20')
  })

  it('switches proxy via dropdown and emits account-updated', async () => {
    const account = makeAccount({ id: 99, proxy_id: null })
    const proxies = [
      { id: 10, name: '日本节点-01', country_code: 'JP', protocol: 'http', host: '1.2.3.4', port: 8080, status: 'active' } as any
    ]
    const wrapper = mount(AccountPoolCard, {
      props: {
        account,
        proxies,
        showPoolControls: true
      },
      global: {
        stubs: {
          AccountUsageCell: UsageStub,
          AccountStatusIndicator: StatusStub
        }
      }
    })

    const select = wrapper.get('select.proxy-select')
    expect(select.text()).toContain('日本节点-01')
    await select.setValue('10')
    await select.trigger('change')

    expect(wrapper.emitted('account-updated')).toBeTruthy()
    expect(wrapper.emitted('account-updated')![0][0]).toMatchObject({
      id: 99,
      proxy_id: 10
    })
  })

  it('saves notes and emits account-updated', async () => {
    const account = makeAccount({ id: 88, notes: '旧备注' })
    const wrapper = mount(AccountPoolCard, {
      props: {
        account,
        showPoolControls: true
      },
      global: {
        stubs: {
          AccountUsageCell: UsageStub,
          AccountStatusIndicator: StatusStub
        }
      }
    })

    await wrapper.get('.notes-btn').trigger('click')
    const textarea = document.body.querySelector('.notes-textarea') as HTMLTextAreaElement
    expect(textarea.value).toBe('旧备注')

    // Find and click the save button in the modal
    const saveBtn = document.body.querySelector('.notes-modal-content .btn-save') as HTMLButtonElement
    expect(saveBtn).toBeTruthy()
    await new DOMWrapper(saveBtn).trigger('click')

    await new Promise(resolve => setTimeout(resolve, 50))
    expect(wrapper.emitted('account-updated')).toBeTruthy()
  })

  it('saves priority and emits account-updated', async () => {
    const account = makeAccount({ id: 77, priority: 5 })
    const wrapper = mount(AccountPoolCard, {
      props: {
        account,
        showPoolControls: true
      },
      global: {
        stubs: {
          AccountUsageCell: UsageStub,
          AccountStatusIndicator: StatusStub
        }
      }
    })

    await wrapper.get('.priority-edit-btn').trigger('click')
    const priorityInput = document.body.querySelector('.priority-input') as HTMLInputElement
    expect(priorityInput).toBeTruthy()

    const saveBtn = document.body.querySelector('.priority-modal-content .btn-save') as HTMLButtonElement
    expect(saveBtn).toBeTruthy()
    await new DOMWrapper(saveBtn).trigger('click')

    await new Promise(resolve => setTimeout(resolve, 50))
    expect(wrapper.emitted('account-updated')).toBeTruthy()
  })
})
