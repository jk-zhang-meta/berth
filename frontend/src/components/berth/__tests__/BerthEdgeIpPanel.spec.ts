import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import BerthEdgeIpPanel from '../BerthEdgeIpPanel.vue'

const mockApi = vi.hoisted(() => ({
  listZones: vi.fn(),
  listNodes: vi.fn(),
  listLinks: vi.fn(),
  listAdminGrants: vi.fn(),
  createAdminGrant: vi.fn(),
  approveAdminGrant: vi.fn(),
  rejectAdminGrant: vi.fn(),
  revokeAdminGrant: vi.fn(),
  listUsers: vi.fn(),
  listAvailableLandingNodes: vi.fn(),
  listUserGrants: vi.fn(),
  applyLandingGrant: vi.fn(),
  cancelPendingApplication: vi.fn(),
}))

vi.mock('@/api/berthNetwork', () => ({
  berthNetworkAPI: mockApi,
}))

describe('BerthEdgeIpPanel', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockApi.listZones.mockResolvedValue([{ id: 1, slug: 'cn_mainland', display_name: 'CN Mainland' }])
    mockApi.listNodes.mockResolvedValue([
      {
        id: 10,
        name: 'houston-vm100',
        roles: ['landing'],
        exit_ip: '68.77.201.111',
        exit_country_code: 'US',
        exit_timezone: 'America/Chicago',
        exit_locale: 'en_US.UTF-8',
        max_bytes_month: 0,
        used_bytes_month: 0,
        reserved_bytes_month: 0,
        status: 'active',
      },
    ])
    mockApi.listLinks.mockResolvedValue([])
    mockApi.listUsers.mockResolvedValue([{ id: 1, email: 'jk.zhang.meta@gmail.com', role: 'admin' }])
    mockApi.listAdminGrants.mockResolvedValue([
      {
        id: 99,
        node_id: 10,
        node_name: 'houston-vm100',
        exit_country_code: 'US',
        exit_timezone: 'America/Chicago',
        grantee_user_id: 2,
        grantee_email: 'alice@example.com',
        max_bytes: 0,
        used_bytes: 0,
        reserved_bytes: 0,
        remaining_bytes: -1,
        max_accounts: 2,
        max_rpm: 0,
        max_concurrency: 0,
        status: 'pending',
        notes: '',
        request_reason: 'Need US IP for Codex',
        created_at: '2026-11-26T00:00:00Z',
        updated_at: '2026-11-26T00:00:00Z',
      },
    ])
    mockApi.approveAdminGrant.mockResolvedValue({ id: 99, status: 'active' })
    mockApi.listAvailableLandingNodes.mockResolvedValue([
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
    mockApi.listUserGrants.mockResolvedValue([])
    mockApi.applyLandingGrant.mockResolvedValue({ id: 101, status: 'pending' })
  })

  it('shows pending applications for admin and approves cleanly', async () => {
    const wrapper = mount(BerthEdgeIpPanel, { props: { isAdmin: true } })
    await flushPromises()

    expect(wrapper.get('[data-test="pending-badge"]').text()).toContain('1 条待审批')
    expect(wrapper.text()).toContain('alice@example.com')
    expect(wrapper.text()).toContain('Need US IP for Codex')

    await wrapper.get('[data-test="approve-grant-99"]').trigger('click')
    await wrapper.get('[data-test="confirm-approve-btn"]').trigger('click')
    await flushPromises()

    expect(mockApi.approveAdminGrant).toHaveBeenCalledWith(99, expect.objectContaining({ max_accounts: 2 }))
    expect(wrapper.emitted('grant-changed')).toBeTruthy()
  })

  it('allows normal user to apply for an available landing node', async () => {
    const wrapper = mount(BerthEdgeIpPanel, { props: { isAdmin: false } })
    await flushPromises()

    expect(wrapper.text()).toContain('houston-vm100')
    expect(wrapper.text()).not.toContain('68.77.201.111')

    await wrapper.get('[data-test="apply-node-10"]').trigger('click')
    await wrapper.get('[data-test="apply-reason-input"]').setValue('Codex dev workspace')
    await wrapper.get('[data-test="submit-apply-btn"]').trigger('click')
    await flushPromises()

    expect(mockApi.applyLandingGrant).toHaveBeenCalledWith(
      expect.objectContaining({ node_id: 10, request_reason: 'Codex dev workspace' })
    )
  })
})
