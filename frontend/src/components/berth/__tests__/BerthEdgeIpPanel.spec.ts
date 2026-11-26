import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import BerthEdgeIpPanel from '../BerthEdgeIpPanel.vue'

const mockAPI = vi.hoisted(() => ({
  listNodes: vi.fn(),
  listAdminGrants: vi.fn(),
  listUsers: vi.fn(),
  createAdminGrant: vi.fn(),
  approveAdminGrant: vi.fn(),
  rejectAdminGrant: vi.fn(),
  revokeAdminGrant: vi.fn(),
  listAvailableLandingNodes: vi.fn(),
  listUserGrants: vi.fn(),
  applyLandingGrant: vi.fn(),
  cancelPendingApplication: vi.fn(),
}))

vi.mock('@/api/berthNetwork', () => ({
  berthNetworkAPI: mockAPI,
}))

vi.mock('@/stores/app', () => ({
  useAppStore: () => ({
    showSuccess: vi.fn(),
    showError: vi.fn(),
    showInfo: vi.fn(),
  }),
}))

describe('BerthEdgeIpPanel', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('renders only landing nodes (hiding pure forwarding nodes) and pending approval queue for admin', async () => {
    mockAPI.listNodes.mockResolvedValue([
      {
        id: 1,
        name: 'po0-gz',
        roles: ['ingress_relay', 'mgmt_entry'],
        exit_ip: '81.71.126.162',
        exit_country_code: 'CN',
        exit_timezone: 'Asia/Shanghai',
        status: 'active',
        max_bytes_month: 0,
        used_bytes_month: 0,
        reserved_bytes_month: 0,
      },
      {
        id: 10,
        name: 'houston-vm100',
        roles: ['landing'],
        exit_ip: '68.77.201.112',
        exit_country_code: 'US',
        exit_timezone: 'America/Chicago',
        status: 'active',
        max_bytes_month: 0,
        used_bytes_month: 0,
        reserved_bytes_month: 0,
      },
    ])
    mockAPI.listAdminGrants.mockResolvedValue([
      {
        id: 7,
        node_id: 10,
        node_name: 'houston-vm100',
        node_exit_ip: '68.77.201.112',
        exit_country_code: 'US',
        grantee_user_id: 42,
        grantee_email: 'alice@example.com',
        status: 'pending',
        request_reason: 'Need US IP for Codex',
        max_bytes: 0,
        used_bytes: 0,
        reserved_bytes: 0,
        remaining_bytes: 0,
        max_accounts: 2,
        max_rpm: 0,
        max_concurrency: 0,
        notes: '',
        created_at: '2026-11-26T00:00:00Z',
        updated_at: '2026-11-26T00:00:00Z',
      },
    ])
    mockAPI.listUsers.mockResolvedValue([{ id: 1, email: 'admin@example.com', role: 'admin' }])

    const wrapper = mount(BerthEdgeIpPanel, {
      props: { isAdmin: true },
      global: {
        stubs: {
          BaseDialog: { template: '<div v-if="show"><slot /><slot name="footer" /></div>', props: ['show'] },
          RouterLink: { template: '<a><slot /></a>' },
        },
      },
    })
    await flushPromises()

    // Pure forwarding node po0-gz must NOT appear in Proxy Management!
    expect(wrapper.text()).not.toContain('po0-gz')
    expect(wrapper.text()).toContain('houston-vm100')
    expect(wrapper.text()).toContain('alice@example.com')
    expect(wrapper.text()).toContain('批准')
  })

  it('renders redacted available landing nodes and user applications for non-admin', async () => {
    mockAPI.listAvailableLandingNodes.mockResolvedValue([
      {
        id: 10,
        name: 'houston-vm100',
        exit_country_code: 'US',
        exit_timezone: 'America/Chicago',
        exit_locale: 'en_US.UTF-8',
        status: 'active',
        has_active_grant: false,
        has_pending_request: false,
      },
    ])
    mockAPI.listUserGrants.mockResolvedValue([])

    const wrapper = mount(BerthEdgeIpPanel, {
      props: { isAdmin: false },
      global: {
        stubs: {
          BaseDialog: { template: '<div v-if="show"><slot /><slot name="footer" /></div>', props: ['show'] },
          RouterLink: { template: '<a><slot /></a>' },
        },
      },
    })
    await flushPromises()

    expect(wrapper.text()).toContain('houston-vm100')
    expect(wrapper.text()).toContain('申请使用')
    expect(wrapper.text()).not.toContain('68.77.201.112')
  })
})
