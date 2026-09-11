import { apiClient } from './client'

export interface BerthAccount {
  id: number
  name: string
  platform: string
  type: string
  status: string
  proxy_id?: number | null
  listed: boolean
  rental_id?: number
  has_secret: boolean
  borrowed: boolean
}

export interface BerthProxy {
  id: number
  name: string
  protocol: string
  host: string
  port: number
  status: string
}

export async function listBerthAccounts(): Promise<BerthAccount[]> {
  const { data } = await apiClient.get<{ items?: BerthAccount[] }>('/accounts')
  return data.items ?? []
}

export async function createBerthAccount(body: {
  name: string
  platform: string
  type: string
  credentials?: Record<string, unknown>
  proxy_id?: number
}): Promise<BerthAccount> {
  const { data } = await apiClient.post<BerthAccount>('/accounts', body)
  return data
}

export async function listBerthProxies(): Promise<BerthProxy[]> {
  const { data } = await apiClient.get<{ items?: BerthProxy[] }>('/proxies')
  return data.items ?? []
}

export async function createBerthProxy(body: {
  name: string
  protocol: string
  host: string
  port: number
  username?: string
  password?: string
}): Promise<BerthProxy> {
  const { data } = await apiClient.post<BerthProxy>('/proxies', body)
  return data
}
