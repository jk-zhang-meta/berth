import { apiClient } from './client'

export interface SessionQueueMember {
  account_id: number
  account_name?: string
  platform?: string
  priority: number
}

export interface WorkSession {
  id: number
  client_session_id: string
  platform: string
  agent?: string
  ags_id?: string
  device_id?: string
  title?: string
  description?: string
  cwd?: string
  host?: string
  assigned_account_id?: number
  last_account_id?: number
  account_name?: string
  account_platform?: string
  status: 'live' | 'ended' | string
  started_at: string
  ended_at?: string
  last_seen_at: string
  requests: number
  input_tokens: number
  output_tokens: number
  cache_read_tokens: number
  cache_creation_tokens: number
  total_tokens: number
  total_cost: number
  queue: SessionQueueMember[]
}

export interface SessionAccountOption {
  id: number
  name: string
  platform: string
  headroom: number
  schedulable: boolean
}

export async function listSessions(): Promise<WorkSession[]> {
  const { data } = await apiClient.get<{ items: WorkSession[] }>('/usage/sessions')
  return data.items || []
}

export async function listSessionAccounts(): Promise<SessionAccountOption[]> {
  const { data } = await apiClient.get<{ items: SessionAccountOption[] }>('/usage/sessions/accounts')
  return data.items || []
}

export async function replaceSessionQueue(sessionId: number, accountIds: number[]): Promise<void> {
  await apiClient.put(`/usage/sessions/${sessionId}/queue`, { account_ids: accountIds })
}

export const sessionsAPI = {
  list: listSessions,
  accounts: listSessionAccounts,
  replaceQueue: replaceSessionQueue,
}

export default sessionsAPI
