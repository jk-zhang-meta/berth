<template>
  <AppLayout>
    <div class="space-y-6">
      <div class="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 class="text-2xl font-semibold text-gray-900 dark:text-white">{{ t('sessions.title') }}</h1>
          <p class="mt-1 text-sm text-gray-500 dark:text-gray-400">{{ t('sessions.description') }}</p>
        </div>
        <button class="btn btn-secondary" :disabled="loading" @click="loadAll">
          {{ t('common.refresh') }}
        </button>
      </div>

      <div class="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <div class="card p-4">
          <div class="text-sm text-gray-500 dark:text-gray-400">{{ t('sessions.active') }}</div>
          <div class="mt-1 text-2xl font-semibold text-gray-900 dark:text-white">{{ activeCount }}</div>
        </div>
        <div class="card p-4">
          <div class="text-sm text-gray-500 dark:text-gray-400">{{ t('sessions.ended') }}</div>
          <div class="mt-1 text-2xl font-semibold text-gray-900 dark:text-white">{{ endedCount }}</div>
        </div>
        <div class="card p-4">
          <div class="text-sm text-gray-500 dark:text-gray-400">{{ t('sessions.totalCost') }}</div>
          <div class="mt-1 text-2xl font-semibold text-gray-900 dark:text-white">{{ formatCost(totalCost) }}</div>
        </div>
      </div>

      <div class="card overflow-hidden">
        <div class="flex flex-wrap items-center gap-2 border-b border-gray-200 p-4 dark:border-dark-700">
          <button
            v-for="option in filters"
            :key="option.value"
            class="rounded-lg px-3 py-1.5 text-sm font-medium transition-colors"
            :class="statusFilter === option.value
              ? 'bg-primary-50 text-primary-700 dark:bg-primary-900/20 dark:text-primary-300'
              : 'text-gray-600 hover:bg-gray-100 dark:text-gray-300 dark:hover:bg-dark-700'"
            @click="statusFilter = option.value"
          >
            {{ option.label }}
          </button>
        </div>

        <DataTable :columns="columns" :data="filteredSessions" :loading="loading" row-key="id">
          <template #cell-session="{ row }">
            <div class="min-w-[190px]">
              <div class="font-mono text-xs font-medium text-gray-900 dark:text-white">
                {{ row.ags_id || row.client_session_id }}
              </div>
              <div class="mt-1 flex items-center gap-2 text-xs text-gray-500 dark:text-gray-400">
                <span>{{ row.agent || row.platform }}</span>
                <span v-if="row.host">· {{ row.host }}</span>
              </div>
            </div>
          </template>

          <template #cell-status="{ row }">
            <span
              class="inline-flex rounded-full px-2 py-1 text-xs font-medium"
              :class="row.status === 'live'
                ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300'
                : 'bg-gray-100 text-gray-600 dark:bg-dark-700 dark:text-gray-300'"
            >
              {{ row.status === 'live' ? t('sessions.active') : t('sessions.ended') }}
            </span>
          </template>

          <template #cell-started_at="{ row }">
            <span class="whitespace-nowrap text-sm">{{ formatTime(row.started_at) }}</span>
          </template>

          <template #cell-ended_at="{ row }">
            <span class="whitespace-nowrap text-sm">{{ row.ended_at ? formatTime(row.ended_at) : '—' }}</span>
          </template>

          <template #cell-requests="{ row }">
            <span class="tabular-nums">{{ formatNumber(row.requests) }}</span>
          </template>

          <template #cell-total_tokens="{ row }">
            <span class="tabular-nums">{{ formatNumber(row.total_tokens) }}</span>
          </template>

          <template #cell-total_cost="{ row }">
            <span class="font-medium tabular-nums">{{ formatCost(row.total_cost) }}</span>
          </template>

          <template #cell-cwd="{ row }">
            <div class="max-w-[260px] truncate font-mono text-xs" :title="row.cwd || ''">{{ row.cwd || '—' }}</div>
          </template>

          <template #cell-description="{ row }">
            <div class="max-w-[320px] whitespace-normal text-sm leading-5" :title="row.description || ''">
              {{ row.description || t('sessions.noDescription') }}
            </div>
          </template>

          <template #cell-account="{ row }">
            <div class="min-w-[210px] space-y-2">
              <div v-if="row.queue?.length" class="flex max-w-[260px] flex-wrap gap-1">
                <span
                  v-for="member in row.queue"
                  :key="member.account_id"
                  class="rounded-md bg-gray-100 px-2 py-1 text-xs text-gray-700 dark:bg-dark-700 dark:text-gray-200"
                >
                  {{ member.account_name || `#${member.account_id}` }}
                </span>
              </div>
              <div v-else class="text-xs text-gray-500 dark:text-gray-400">{{ t('sessions.autoSchedule') }}</div>
              <div v-if="row.account_name" class="text-xs text-gray-500 dark:text-gray-400">
                {{ t('sessions.currentAccount') }}: {{ row.account_name }}
              </div>
              <button class="btn btn-secondary btn-sm" @click="openAccountDialog(row)">
                {{ t('sessions.assignAccounts') }}
              </button>
            </div>
          </template>
        </DataTable>
      </div>
    </div>

    <BaseDialog
      :show="showAccountDialog"
      :title="t('sessions.assignAccounts')"
      width="wide"
      @close="closeAccountDialog"
    >
      <div class="space-y-5">
        <p class="text-sm text-gray-500 dark:text-gray-400">{{ t('sessions.queueHint') }}</p>

        <div v-if="queueDraft.length" class="space-y-2">
          <div
            v-for="(accountId, index) in queueDraft"
            :key="accountId"
            class="flex items-center gap-3 rounded-xl border border-gray-200 p-3 dark:border-dark-700"
          >
            <span class="w-6 text-center text-xs font-semibold text-gray-400">{{ index + 1 }}</span>
            <div class="min-w-0 flex-1">
              <div class="truncate text-sm font-medium text-gray-900 dark:text-white">{{ accountName(accountId) }}</div>
              <div class="text-xs text-gray-500 dark:text-gray-400">{{ accountPlatform(accountId) }}</div>
            </div>
            <button class="btn btn-secondary btn-sm" :disabled="index === 0" @click="moveQueue(index, -1)">↑</button>
            <button class="btn btn-secondary btn-sm" :disabled="index === queueDraft.length - 1" @click="moveQueue(index, 1)">↓</button>
            <button class="btn btn-danger btn-sm" @click="removeQueue(index)">{{ t('common.remove') }}</button>
          </div>
        </div>
        <div v-else class="rounded-xl border border-dashed border-gray-300 p-5 text-center text-sm text-gray-500 dark:border-dark-600 dark:text-gray-400">
          {{ t('sessions.autoScheduleHint') }}
        </div>

        <div class="flex flex-wrap items-end gap-3">
          <div class="min-w-[260px] flex-1">
            <label class="input-label">{{ t('sessions.addAccount') }}</label>
            <select v-model.number="accountToAdd" class="input w-full">
              <option :value="0">{{ t('sessions.chooseAccount') }}</option>
              <option v-for="account in addableAccounts" :key="account.id" :value="account.id">
                {{ account.name }} · {{ account.platform }}{{ account.schedulable ? '' : ` · ${t('sessions.unavailable')}` }}
              </option>
            </select>
          </div>
          <button class="btn btn-secondary" :disabled="!accountToAdd" @click="addQueueAccount">{{ t('common.add') }}</button>
        </div>
      </div>

      <template #footer>
        <button class="btn btn-secondary" @click="closeAccountDialog">{{ t('common.cancel') }}</button>
        <button class="btn btn-primary" :disabled="savingQueue" @click="saveQueue">
          {{ savingQueue ? t('common.saving') : t('common.save') }}
        </button>
      </template>
    </BaseDialog>
  </AppLayout>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import AppLayout from '@/components/layout/AppLayout.vue'
import DataTable from '@/components/common/DataTable.vue'
import BaseDialog from '@/components/common/BaseDialog.vue'
import type { Column } from '@/components/common/types'
import sessionsAPI, { type SessionAccountOption, type WorkSession } from '@/api/sessions'

const { t } = useI18n()
const loading = ref(false)
const savingQueue = ref(false)
const sessions = ref<WorkSession[]>([])
const accounts = ref<SessionAccountOption[]>([])
const statusFilter = ref<'all' | 'live' | 'ended'>('all')
const showAccountDialog = ref(false)
const selectedSession = ref<WorkSession | null>(null)
const queueDraft = ref<number[]>([])
const accountToAdd = ref(0)

const filters = computed(() => [
  { value: 'all' as const, label: t('common.all') },
  { value: 'live' as const, label: t('sessions.active') },
  { value: 'ended' as const, label: t('sessions.ended') },
])

const columns = computed<Column[]>(() => [
  { key: 'session', label: t('sessions.sessionId') },
  { key: 'status', label: t('common.status') },
  { key: 'started_at', label: t('sessions.startedAt') },
  { key: 'ended_at', label: t('sessions.endedAt') },
  { key: 'requests', label: '#Req' },
  { key: 'total_tokens', label: '#Token' },
  { key: 'total_cost', label: t('sessions.cost') },
  { key: 'cwd', label: t('sessions.cwd') },
  { key: 'description', label: t('sessions.topic') },
  { key: 'account', label: t('sessions.accounts') },
])

const filteredSessions = computed(() => {
  if (statusFilter.value === 'all') return sessions.value
  return sessions.value.filter((item) => item.status === statusFilter.value)
})
const activeCount = computed(() => sessions.value.filter((item) => item.status === 'live').length)
const endedCount = computed(() => sessions.value.filter((item) => item.status !== 'live').length)
const totalCost = computed(() => sessions.value.reduce((sum, item) => sum + Number(item.total_cost || 0), 0))

const compatibleAccounts = computed(() => {
  const platform = selectedSession.value?.platform
  if (!platform || platform === 'unknown') return accounts.value
  return accounts.value.filter((account) => account.platform === platform)
})
const addableAccounts = computed(() => compatibleAccounts.value.filter((account) => !queueDraft.value.includes(account.id)))

function formatTime(value: string): string {
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(date)
}
function formatNumber(value: number): string {
  return new Intl.NumberFormat().format(Number(value || 0))
}
function formatCost(value: number): string {
  const amount = Number(value || 0)
  return `$${amount < 0.01 && amount > 0 ? amount.toFixed(6) : amount.toFixed(4)}`
}
function accountById(id: number): SessionAccountOption | undefined {
  return accounts.value.find((account) => account.id === id)
}
function accountName(id: number): string {
  return accountById(id)?.name || selectedSession.value?.queue?.find((item) => item.account_id === id)?.account_name || `#${id}`
}
function accountPlatform(id: number): string {
  return accountById(id)?.platform || selectedSession.value?.queue?.find((item) => item.account_id === id)?.platform || ''
}

async function loadAll() {
  loading.value = true
  try {
    const [sessionItems, accountItems] = await Promise.all([sessionsAPI.list(), sessionsAPI.accounts()])
    sessions.value = sessionItems
    accounts.value = accountItems
  } finally {
    loading.value = false
  }
}

function openAccountDialog(session: WorkSession) {
  selectedSession.value = session
  queueDraft.value = (session.queue || []).map((item) => item.account_id)
  accountToAdd.value = 0
  showAccountDialog.value = true
}
function closeAccountDialog() {
  showAccountDialog.value = false
  selectedSession.value = null
  queueDraft.value = []
  accountToAdd.value = 0
}
function addQueueAccount() {
  if (accountToAdd.value > 0 && !queueDraft.value.includes(accountToAdd.value)) {
    queueDraft.value.push(accountToAdd.value)
  }
  accountToAdd.value = 0
}
function removeQueue(index: number) {
  queueDraft.value.splice(index, 1)
}
function moveQueue(index: number, delta: number) {
  const target = index + delta
  if (target < 0 || target >= queueDraft.value.length) return
  const next = [...queueDraft.value]
  ;[next[index], next[target]] = [next[target], next[index]]
  queueDraft.value = next
}
async function saveQueue() {
  if (!selectedSession.value) return
  savingQueue.value = true
  try {
    await sessionsAPI.replaceQueue(selectedSession.value.id, queueDraft.value)
    await loadAll()
    closeAccountDialog()
  } finally {
    savingQueue.value = false
  }
}

onMounted(loadAll)
</script>
