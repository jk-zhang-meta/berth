<template>
  <AppLayout>
    <TablePageLayout>
      <template #filters>
        <div class="flex flex-wrap-reverse items-start justify-between gap-3">
          <div class="flex flex-wrap items-center gap-3">
            <SearchInput
              :model-value="params.search"
              placeholder="搜索会话、AGS、目录"
              class="w-full sm:w-64"
              @update:model-value="params.search = String($event)"
              @search="debouncedReload"
            />
            <Select
              :model-value="params.platform"
              class="w-40"
              :options="platformOptions"
              @update:model-value="updatePlatform"
              @change="debouncedReload"
            />
            <Select
              :model-value="params.status"
              class="w-40"
              :options="statusOptions"
              @update:model-value="updateStatus"
              @change="debouncedReload"
            />
          </div>
          <button class="btn btn-secondary" type="button" :disabled="loading" @click="reload">
            {{ t('common.refresh') }}
          </button>
        </div>
      </template>

      <template #table>
        <div class="flex min-h-0 flex-1 flex-col overflow-hidden">
        <div class="account-card-toolbar">
          <span class="text-xs text-gray-400">{{ pagination.total }} · p{{ pagination.page }}/{{ pagination.pages || 1 }}</span>
        </div>
        <div v-if="loading && sessions.length === 0" class="flex flex-1 items-center justify-center text-sm text-gray-400">
          {{ t('common.loading') }}
        </div>
        <div v-else-if="!loading && sessions.length === 0" class="flex flex-1 items-center justify-center text-sm text-gray-400">
          这个筛选下还没有会话。请求带上 session_id 后会出现在对应平台里。
        </div>
        <div v-else class="accounts-grid-wrap">
          <div class="accounts-grid">
            <article
              v-for="row in sessions"
              :key="row.id"
              class="account-card"
              :class="'is-' + cardStatus(row)"
            >
              <div class="card-top">
                <div class="min-w-0 flex-1">
                  <div class="truncate font-medium text-gray-900 dark:text-white" :title="row.client_session_id">
                    {{ row.title || shortId(row.client_session_id) }}
                  </div>
                  <div class="truncate text-xs text-gray-500 dark:text-gray-400" :title="row.cwd">
                    {{ row.cwd || '工作目录未上报' }}
                  </div>
                </div>
                <span class="font-mono text-[10px] text-gray-400">#{{ row.id }}</span>
              </div>

              <div class="flex flex-wrap items-center gap-2">
                <span class="inline-flex items-center gap-1 rounded-md bg-gray-100 px-2 py-1 text-xs font-medium text-gray-700 dark:bg-dark-700 dark:text-gray-200">
                  <PlatformIcon :platform="row.platform as GroupPlatform" size="xs" />
                  {{ providerTitle(row.platform) }}
                </span>
                <span class="rounded px-1.5 py-0.5 text-[10px] font-medium" :class="row.status === 'live' ? 'bg-emerald-50 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300' : 'bg-gray-100 text-gray-500 dark:bg-dark-700'">
                  {{ row.status === 'live' ? '进行中' : '已结束' }}
                </span>
                <span v-if="row.ags_id" class="rounded px-1.5 py-0.5 text-[10px] font-medium bg-gray-100 text-gray-600 dark:bg-dark-700 dark:text-gray-300">
                  AGS {{ row.ags_id }}
                </span>
                <span class="text-[10px] font-semibold text-gray-400">P{{ row.importance }}</span>
              </div>

              <div class="card-panel">
                <p class="text-xs text-gray-500">
                  {{ row.account_name || (row.last_account_id ? '#' + row.last_account_id : '未占用账号') }}
                </p>
                <p class="mt-1 text-xs text-gray-400">
                  <template v-if="row.queue?.length">队列 {{ row.queue.map((m) => m.account_name || m.account_id).join(' → ') }}</template>
                  <template v-else>空队列则在该 provider 的公共池里选号</template>
                </p>
              </div>

              <div class="card-metrics">
                <div>
                  <small>请求</small>
                  <span class="text-xs text-gray-700 dark:text-gray-200">{{ row.requests }}</span>
                </div>
                <div>
                  <small>Token</small>
                  <span class="text-xs text-gray-700 dark:text-gray-200">{{ formatTokens(row.total_tokens) }}</span>
                </div>
                <div>
                  <small>输入 / 输出</small>
                  <span class="text-xs text-gray-700 dark:text-gray-200">{{ formatTokens(row.input_tokens) }} / {{ formatTokens(row.output_tokens) }}</span>
                </div>
                <div>
                  <small>最近</small>
                  <span class="text-xs text-gray-500">{{ ago(row.last_seen_at) }}</span>
                </div>
              </div>

              <label class="block text-sm">
                <span class="input-label">重要性 {{ row.importance }} · {{ importanceLabel(row.importance) }}</span>
                <input type="range" min="1" max="100" class="w-full" :value="row.importance" @change="onImportance(row, $event)" />
              </label>

              <label class="block">
                <span class="input-label">AGS ID</span>
                <input class="input" :value="row.ags_id || ''" placeholder="ags save 用的 ID" @change="onAgs(row, $event)" />
              </label>

              <div v-if="openQueueId === row.id" class="card-panel max-h-36 space-y-1 overflow-y-auto">
                <p v-if="!accountsFor(row.platform).length" class="text-xs text-gray-400">没有同平台账号可排队。</p>
                <label
                  v-for="account in accountsFor(row.platform)"
                  :key="account.id"
                  class="flex items-center gap-2 text-sm text-gray-700 dark:text-gray-300"
                >
                  <input
                    type="checkbox"
                    class="rounded border-gray-300 text-primary-600"
                    :checked="inQueue(row, account.id)"
                    @change="toggleQueue(row, account.id, $event)"
                  />
                  {{ account.name }}
                </label>
              </div>

              <ul v-if="openRequestId === row.id" class="card-panel divide-y divide-gray-100 text-xs text-gray-500 dark:divide-dark-700">
                <li v-if="requestLoading" class="py-2">加载中…</li>
                <li v-else-if="!requests.length" class="py-2">这条会话还没有记到请求。</li>
                <li v-for="item in requests" :key="item.id" class="grid grid-cols-3 gap-2 py-2">
                  <span>{{ item.model }}</span>
                  <span>{{ item.input_tokens }} / {{ item.output_tokens }}</span>
                  <span>{{ formatTime(item.created_at) }}</span>
                </li>
              </ul>

              <div class="card-footer">
                <button type="button" class="card-op" @click="toggleQueuePanel(row)">队列</button>
                <button type="button" class="card-op" @click="toggleRequests(row)">
                  {{ openRequestId === row.id ? '收起请求' : '请求' }}
                </button>
                <button v-if="row.status === 'live'" type="button" class="card-op card-op-danger" @click="endSession(row)">
                  结束
                </button>
              </div>
            </article>
          </div>
        </div>
        </div>
      </template>

      <template #pagination>
        <Pagination
          v-if="pagination.total > 0"
          :page="pagination.page"
          :total="pagination.total"
          :page-size="pagination.page_size"
          @update:page="handlePageChange"
          @update:pageSize="handlePageSizeChange"
        />
      </template>
    </TablePageLayout>
  </AppLayout>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import { useI18n } from 'vue-i18n'
import AppLayout from '@/components/layout/AppLayout.vue'
import TablePageLayout from '@/components/layout/TablePageLayout.vue'
import Pagination from '@/components/common/Pagination.vue'
import SearchInput from '@/components/common/SearchInput.vue'
import Select from '@/components/common/Select.vue'
import PlatformIcon from '@/components/common/PlatformIcon.vue'
import { useTableLoader } from '@/composables/useTableLoader'
import { CONCRETE_PLATFORM_OPTIONS } from '@/constants/platforms'
import { platformLabel } from '@/utils/platformColors'
import { listSessions, listSessionRequests, patchSession, replaceSessionQueue, type WorkSession, type WorkSessionRequest } from '@/api/usage'
import { listBerthAccounts, type BerthAccount } from '@/api/berth'
import type { BasePaginationResponse, GroupPlatform } from '@/types'

const { t } = useI18n()
const route = useRoute()
const admin = computed(() => route.path.startsWith('/admin'))
const accounts = ref<BerthAccount[]>([])
const openQueueId = ref<number | null>(null)
const openRequestId = ref<number | null>(null)
const requests = ref<WorkSessionRequest[]>([])
const requestLoading = ref(false)

type SessionFilters = { search: string; platform: string; status: string }

const {
  items: sessions,
  loading,
  params,
  pagination,
  load,
  reload,
  debouncedReload,
  handlePageChange,
  handlePageSizeChange
} = useTableLoader<WorkSession, SessionFilters>({
  fetchFn: async (page, pageSize, filters): Promise<BasePaginationResponse<WorkSession>> => {
    const all = await listSessions(admin.value)
    const q = (filters.search || '').trim().toLowerCase()
    const filtered = all.filter((row) => {
      if (filters.platform && (row.platform || 'unknown') !== filters.platform) return false
      if (filters.status && row.status !== filters.status) return false
      if (!q) return true
      return [row.title, row.client_session_id, row.ags_id, row.cwd, row.account_name]
        .some((value) => (value || '').toLowerCase().includes(q))
    })
    const total = filtered.length
    const pages = total > 0 ? Math.ceil(total / pageSize) : 0
    const start = (page - 1) * pageSize
    return {
      items: filtered.slice(start, start + pageSize),
      total,
      page,
      page_size: pageSize,
      pages
    }
  },
  initialParams: { search: '', platform: '', status: '' }
})

const platformOptions = computed(() => [
  { value: '', label: t('admin.accounts.allPlatforms') },
  ...CONCRETE_PLATFORM_OPTIONS.map((item) => ({
    value: item.value,
    label: providerTitle(item.value)
  }))
])

const statusOptions = computed(() => [
  { value: '', label: t('admin.accounts.allStatus') },
  { value: 'live', label: '进行中' },
  { value: 'ended', label: '已结束' }
])

function updatePlatform(value: string | number | boolean | null) {
  params.platform = String(value ?? '')
}

function updateStatus(value: string | number | boolean | null) {
  params.status = String(value ?? '')
}

function providerTitle(platform: string) {
  if (platform === 'anthropic') return 'Claude'
  if (platform === 'openai') return 'OpenAI / Codex'
  if (platform === 'unknown' || !platform) return '未识别'
  return platformLabel(platform)
}

function cardStatus(row: WorkSession) {
  return row.status === 'live' ? 'active' : 'inactive'
}

function accountsFor(platform: string) {
  return accounts.value.filter((account) => account.platform === platform)
}

async function loadAccounts() {
  accounts.value = await listBerthAccounts()
}

function shortId(value: string) {
  if (!value) return '—'
  return value.length > 18 ? `${value.slice(0, 8)}…${value.slice(-6)}` : value
}

function formatTokens(value: number) {
  if (value >= 1_000_000) return `${(value / 1_000_000).toFixed(1)}M`
  if (value >= 1000) return `${(value / 1000).toFixed(1)}k`
  return String(value || 0)
}

function importanceLabel(value: number) {
  if (value <= 20) return '独占优先'
  if (value <= 40) return '尽量独占'
  if (value >= 80) return '可共享'
  return '普通'
}

function ago(value: string) {
  const ts = Date.parse(value)
  if (!Number.isFinite(ts)) return ''
  const delta = Date.now() - ts
  if (delta < 60_000) return '刚刚'
  if (delta < 3_600_000) return `${Math.floor(delta / 60_000)} 分钟前`
  if (delta < 86_400_000) return `${Math.floor(delta / 3_600_000)} 小时前`
  return `${Math.floor(delta / 86_400_000)} 天前`
}

function formatTime(value: string) {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return date.toLocaleString()
}

async function onImportance(row: WorkSession, event: Event) {
  const importance = Number((event.target as HTMLInputElement).value)
  row.importance = importance
  await patchSession(row.id, { importance }, admin.value)
}

async function onAgs(row: WorkSession, event: Event) {
  const ags_id = (event.target as HTMLInputElement).value.trim()
  row.ags_id = ags_id
  await patchSession(row.id, { ags_id }, admin.value)
}

function inQueue(row: WorkSession, accountId: number) {
  return (row.queue || []).some((member) => member.account_id === accountId)
}

async function toggleQueue(row: WorkSession, accountId: number, event: Event) {
  const checked = (event.target as HTMLInputElement).checked
  const current = (row.queue || []).map((member) => member.account_id)
  const next = checked ? [...current, accountId] : current.filter((id) => id !== accountId)
  await replaceSessionQueue(row.id, next, admin.value)
  await load()
}

async function endSession(row: WorkSession) {
  row.status = 'ended'
  await patchSession(row.id, { status: 'ended' }, admin.value)
  await load()
}

function toggleQueuePanel(row: WorkSession) {
  openQueueId.value = openQueueId.value === row.id ? null : row.id
}

async function toggleRequests(row: WorkSession) {
  if (openRequestId.value === row.id) {
    openRequestId.value = null
    requests.value = []
    return
  }
  openRequestId.value = row.id
  requestLoading.value = true
  try {
    requests.value = await listSessionRequests(row.id, admin.value)
  } finally {
    requestLoading.value = false
  }
}

onMounted(async () => {
  await Promise.all([load(), loadAccounts()])
})
</script>

<style scoped>
.account-card-toolbar {
  @apply flex flex-none items-center justify-between gap-3 border-b border-gray-100 px-4 py-2 dark:border-dark-700;
}

.accounts-grid-wrap {
  @apply min-h-0 flex-1 overflow-y-auto p-4;
}

.accounts-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
  gap: 16px;
}

.account-card {
  @apply flex min-h-[240px] flex-col gap-3 rounded-2xl border border-gray-200 bg-white p-4 shadow-sm dark:border-dark-700 dark:bg-dark-800;
}

.account-card.is-active { border-left: 3px solid rgb(16 185 129); }
.account-card.is-inactive { border-left: 3px solid rgb(156 163 175); }

.card-top {
  display: flex;
  align-items: flex-start;
  gap: 8px;
}

.card-panel {
  padding: 8px;
  border-radius: 10px;
  background: rgb(249 250 251);
}

.dark .card-panel {
  background: rgb(17 24 39);
}

.card-metrics {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 8px 12px;
}

.card-metrics small {
  display: block;
  margin-bottom: 2px;
  font-size: 10px;
  font-weight: 700;
  letter-spacing: 0.04em;
  color: rgb(156 163 175);
}

.card-footer {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  margin-top: auto;
}

.card-op {
  height: 26px;
  padding: 0 8px;
  border: 1px solid rgb(209 213 219);
  border-radius: 7px;
  background: #fff;
  font-size: 11px;
  font-weight: 650;
  color: rgb(75 85 99);
}

.dark .card-op {
  border-color: rgb(75 85 99);
  background: rgb(31 41 55);
  color: rgb(209 213 219);
}

.card-op-danger:hover {
  border-color: rgb(252 165 165);
  color: rgb(220 38 38);
}
</style>
