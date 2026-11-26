/**
 * Berth v2 Edge Network Topology, Landing Nodes & Grant Approval API client.
 */
import { apiClient } from './client'

export interface BerthNetworkZone {
  id: number
  slug: string
  display_name: string
  description?: string
  default_ingress_strategy?: string
  created_at?: string
}

export interface BerthEdgeNode {
  id: number
  name: string
  zone_id?: number | null
  roles: string[]
  public_addr?: string
  connect_mode?: string
  exit_ip?: string
  exit_country_code?: string
  exit_timezone?: string
  exit_locale?: string
  asn_class?: string
  max_bytes_month: number
  used_bytes_month: number
  reserved_bytes_month: number
  status: string
  last_seen_at?: string | null
  created_at?: string
}

export interface BerthServerLink {
  id: number
  src_node_id: number
  dst_node_id: number
  link_class: string
  rtt_ms: number
  weight: number
  enabled: boolean
}

export interface BerthLandingGrant {
  id: number
  node_id: number
  node_name?: string
  node_status?: string
  node_exit_ip?: string
  exit_country_code?: string
  exit_timezone?: string
  exit_locale?: string
  grantee_user_id: number
  grantee_email?: string
  grantee_username?: string
  granted_by_admin_id?: number | null
  proxy_id?: number | null
  expires_at?: string | null
  max_bytes: number
  used_bytes: number
  reserved_bytes: number
  remaining_bytes: number
  max_accounts: number
  max_rpm: number
  max_concurrency: number
  status: 'pending' | 'active' | 'paused' | 'revoked' | 'rejected' | 'expired' | 'quota_exhausted' | string
  notes: string
  request_reason?: string
  review_note?: string
  reviewed_at?: string | null
  created_at: string
  updated_at: string
}

export interface BerthAvailableLandingNode {
  id: number
  name: string
  exit_country_code: string
  exit_timezone: string
  exit_locale: string
  status: string
  has_active_grant: boolean
  has_pending_request: boolean
}

export interface BerthSimpleUser {
  id: number
  email: string
  username?: string
  role?: string
  status?: string
}

export interface CreateLandingGrantPayload {
  node_id: number
  grantee_user_id: number
  max_bytes: number
  max_accounts: number
  max_rpm: number
  max_concurrency: number
  expires_at?: string | null
  notes?: string
}

export interface ApplyLandingGrantPayload {
  node_id: number
  request_reason: string
  max_accounts?: number
  max_bytes?: number
}

export interface ApproveLandingGrantPayload {
  max_bytes?: number
  max_accounts?: number
  max_rpm?: number
  max_concurrency?: number
  expires_at?: string | null
  review_note?: string
  notes?: string
}

export const berthNetworkAPI = {
  // ---- Admin APIs ----
  async listZones(): Promise<BerthNetworkZone[]> {
    const { data } = await apiClient.get<{ items: BerthNetworkZone[] }>('/admin/network/zones')
    return data?.items ?? []
  },
  async listNodes(): Promise<BerthEdgeNode[]> {
    const { data } = await apiClient.get<{ items: BerthEdgeNode[] }>('/admin/network/nodes')
    return data?.items ?? []
  },
  async listLinks(): Promise<BerthServerLink[]> {
    const { data } = await apiClient.get<{ items: BerthServerLink[] }>('/admin/network/links')
    return data?.items ?? []
  },
  async listAdminGrants(): Promise<BerthLandingGrant[]> {
    const { data } = await apiClient.get<{ items: BerthLandingGrant[] }>('/admin/network/grants')
    return data?.items ?? []
  },
  async createAdminGrant(payload: CreateLandingGrantPayload): Promise<BerthLandingGrant> {
    const { data } = await apiClient.post<BerthLandingGrant>('/admin/network/grants', payload)
    return data
  },
  async approveAdminGrant(grantId: number, payload: ApproveLandingGrantPayload): Promise<BerthLandingGrant> {
    const { data } = await apiClient.post<BerthLandingGrant>(`/admin/network/grants/${grantId}/approve`, payload)
    return data
  },
  async rejectAdminGrant(grantId: number, review_note: string): Promise<BerthLandingGrant> {
    const { data } = await apiClient.post<BerthLandingGrant>(`/admin/network/grants/${grantId}/reject`, { review_note })
    return data
  },
  async revokeAdminGrant(grantId: number, reason?: string): Promise<void> {
    const query = reason ? `?reason=${encodeURIComponent(reason)}` : ''
    await apiClient.delete(`/admin/network/grants/${grantId}${query}`)
  },
  async listUsers(): Promise<BerthSimpleUser[]> {
    const { data } = await apiClient.get<{ items: BerthSimpleUser[] }>('/admin/users', {
      params: { page: 1, page_size: 100 },
    })
    return data?.items ?? []
  },

  // ---- Normal-User Self-Service APIs ----
  async listAvailableLandingNodes(): Promise<BerthAvailableLandingNode[]> {
    const { data } = await apiClient.get<{ items: BerthAvailableLandingNode[] }>('/user/landing-nodes')
    return data?.items ?? []
  },
  async listUserGrants(): Promise<BerthLandingGrant[]> {
    const { data } = await apiClient.get<{ items: BerthLandingGrant[] }>('/user/landing-grants')
    return data?.items ?? []
  },
  async applyLandingGrant(payload: ApplyLandingGrantPayload): Promise<BerthLandingGrant> {
    const { data } = await apiClient.post<BerthLandingGrant>('/user/landing-grants/apply', payload)
    return data
  },
  async cancelPendingApplication(grantId: number): Promise<void> {
    await apiClient.delete(`/user/landing-grants/${grantId}`)
  },
}
