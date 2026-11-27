import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'

import AccountsView from '../AccountsView.vue'

const {
  listAccounts,
  listWithEtag,
  getBatchTodayStats,
  getAllProxies,
  getAllGroups
} = vi.hoisted(() => ({
  listAccounts: vi.fn(),
  listWithEtag: vi.fn(),
  getBatchTodayStats: vi.fn(),
  getAllProxies: vi.fn(),
  getAllGroups: vi.fn()
}))

const role = vi.hoisted(() => ({ isAdmin: false }))

vi.mock('@/api/admin', () => ({
  adminAPI: {
    accounts: {
      list: listAccounts,
      listWithEtag,
      getBatchTodayStats,
      getUpstreamBillingProbeSettings: vi.fn().mockResolvedValue({ enabled: true, interval_minutes: 30 }),
      delete: vi.fn(),
      batchClearError: vi.fn(),
      batchRefresh: vi.fn(),
      toggleSchedulable: vi.fn()
    },
    proxies: {
      getAll: getAllProxies,
      getAllWithCount: getAllProxies
    },
    groups: {
      getAll: getAllGroups
    }
  }
}))

vi.mock('@/stores/app', () => ({
  useAppStore: () => ({
    showError: vi.fn(),
    showSuccess: vi.fn(),
    showInfo: vi.fn()
  })
}))

vi.mock('@/stores/auth', () => ({
  useAuthStore: () => ({
    token: 'user-token',
    isAdmin: role.isAdmin,
    isSimpleMode: false
  })
}))

vi.mock('vue-i18n', async () => {
  const actual = await vi.importActual<typeof import('vue-i18n')>('vue-i18n')
  return {
    ...actual,
    useI18n: () => ({
      t: (key: string) => key
    })
  }
})

const DataTableStub = {
  props: ['columns', 'data'],
  template: '<div data-test="data-table"></div>'
}

function mountView() {
  return mount(AccountsView, {
    global: {
      stubs: {
        AppLayout: { template: '<div><slot /></div>' },
        TablePageLayout: {
          template: '<div><slot name="filters" /><slot name="table" /><slot name="pagination" /></div>'
        },
        DataTable: DataTableStub,
        AccountTableFilters: {
          props: ['groups', 'owners'],
          template:
            '<div data-test="account-filters" :data-group-count="(groups || []).length" :data-owner-count="(owners || []).length"></div>'
        },
        HelpTooltip: true,
        Pagination: true,
        ConfirmDialog: true,
        AccountActionMenu: true,
        ImportDataModal: true,
        ReAuthAccountModal: true,
        AccountTestModal: true,
        AccountStatsModal: true,
        ScheduledTestsPanel: true,
        SyncFromCrsModal: true,
        TempUnschedStatusModal: true,
        ErrorPassthroughRulesModal: true,
        TLSFingerprintProfilesModal: true,
        CreateAccountModal: true,
        EditAccountModal: true,
        BulkEditAccountModal: true,
        PlatformTypeBadge: true,
        AccountCapacityCell: true,
        AccountStatusIndicator: true,
        AccountTodayStatsCell: true,
        AccountGroupsCell: true,
        AccountUsageCell: true,
        AccountPoolCard: true,
        Icon: true
      }
    }
  })
}

describe('user AccountsView hides admin-only pool controls', () => {
  beforeEach(() => {
    role.isAdmin = false
    localStorage.clear()
    listAccounts.mockReset()
    listWithEtag.mockReset()
    getBatchTodayStats.mockReset()
    getAllProxies.mockReset()
    getAllGroups.mockReset()
    listAccounts.mockResolvedValue({ items: [], total: 0, page: 1, page_size: 20, pages: 0 })
    listWithEtag.mockResolvedValue({ notModified: true, etag: null, data: null })
    getBatchTodayStats.mockResolvedValue({ stats: {} })
    getAllProxies.mockResolvedValue([])
    getAllGroups.mockResolvedValue([{ id: 1, name: 'hidden-from-user' }])
  })

  it.each([false, true])('passes initial and refresh statistics failures to cards for admin=%s', async (isAdmin) => {
    role.isAdmin = isAdmin
    const account = { id: 11, name: 'own account', platform: 'openai', type: 'apikey', credentials: {}, extra: {}, status: 'active', schedulable: true, group_ids: [] }
    listAccounts.mockResolvedValue({ items: [account], total: 1, page: 1, page_size: 20, pages: 1 })
    getBatchTodayStats.mockRejectedValue(new Error('stats unavailable'))
    const wrapper = mountView()
    await flushPromises()
    await wrapper.findAll('button').find(button => button.text() === '卡片')!.trigger('click')
    await flushPromises()
    const card = () => wrapper.findComponent({ name: 'AccountPoolCard' })
    expect(card().props('todayStatsError')).toBe('Failed')
    expect(card().props('todayStats')).toBeNull()
    expect(card().props('showPoolControls')).toBe(isAdmin)

    const stats = { requests: 12, tokens: 30, cost: 1 }
    getBatchTodayStats.mockResolvedValue({ stats: { '11': stats } })
    wrapper.findComponent({ name: 'AccountTableActions' }).vm.$emit('refresh')
    await flushPromises()
    expect(card().props('todayStats')).toEqual(stats)
    expect(card().props('todayStatsError')).toBeNull()

    getBatchTodayStats.mockRejectedValue(new Error('refresh unavailable'))
    wrapper.findComponent({ name: 'AccountTableActions' }).vm.$emit('refresh')
    await flushPromises()
    expect(card().props('todayStatsError')).toBe('Failed')
    expect(card().props('todayStats')).toEqual(stats)
    wrapper.unmount()
  })

  it('keeps add/refresh and hides CRS/import/export/passthrough/TLS/group filter', async () => {
    const wrapper = mountView()
    await flushPromises()

    expect(wrapper.text()).toContain('admin.accounts.createAccount')
    expect(wrapper.text()).not.toContain('admin.accounts.syncFromCrs')
    expect(wrapper.text()).not.toContain('admin.accounts.dataImport')
    expect(wrapper.text()).not.toContain('admin.accounts.dataExport')
    expect(wrapper.text()).not.toContain('admin.errorPassthrough.title')
    expect(wrapper.text()).not.toContain('admin.tlsFingerprintProfiles.title')
    expect(wrapper.get('[data-test="account-filters"]').attributes('data-group-count')).toBe('0')
    expect(wrapper.get('[data-test="account-filters"]').attributes('data-owner-count')).toBe('0')
    expect(getAllGroups).not.toHaveBeenCalled()
  })

  it('passes force=true to getBatchTodayStats on manual refresh and preserves latency fields on inline account update', async () => {
    role.isAdmin = true
    const account = {
      id: 24,
      name: 'codex@example.com',
      platform: 'openai',
      type: 'oauth',
      credentials: {},
      extra: {},
      status: 'active',
      schedulable: true,
      group_ids: [],
      first_token_ms: 1010,
      duration_ms: 2340,
      owner_user_id: 1,
      owner_label: 'admin@example.com'
    }
    listAccounts.mockResolvedValue({ items: [account], total: 1, page: 1, page_size: 20, pages: 1 })
    getBatchTodayStats.mockResolvedValue({ stats: { '24': { requests: 5, tokens: 1200, cost: 0.05 } } })

    const wrapper = mountView()
    await flushPromises()
    await wrapper.findAll('button').find(button => button.text() === '卡片')!.trigger('click')
    await flushPromises()

    getBatchTodayStats.mockClear()
    wrapper.findComponent({ name: 'AccountTableActions' }).vm.$emit('refresh')
    await flushPromises()
    expect(getBatchTodayStats).toHaveBeenCalledWith([24], { force: true })

    // Inline card update (e.g. proxy or notes PUT) returns Account without steward latency fields;
    // mergeRuntimeFields must preserve first_token_ms, duration_ms, and owner_label.
    const card = wrapper.findComponent({ name: 'AccountPoolCard' })
    card.vm.$emit('account-updated', {
      id: 24,
      name: 'codex@example.com',
      platform: 'openai',
      type: 'oauth',
      credentials: {},
      extra: {},
      status: 'active',
      schedulable: true,
      group_ids: [],
      notes: 'updated'
    })
    await flushPromises()
    const updatedProp = wrapper.findComponent({ name: 'AccountPoolCard' }).props('account') as Record<string, unknown>
    expect(updatedProp.first_token_ms).toBe(1010)
    expect(updatedProp.duration_ms).toBe(2340)
    expect(updatedProp.owner_label).toBe('admin@example.com')
    wrapper.unmount()
  })
})
