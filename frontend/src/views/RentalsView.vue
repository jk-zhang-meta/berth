<template>
  <AppLayout>
    <div class="space-y-6">
      <div class="flex flex-wrap items-center justify-between gap-3">
        <p class="text-sm text-gray-500 dark:text-gray-400">
          市场里是别人挂出的号。点租用立即开始；物主随时可以收回。
        </p>
        <button class="btn btn-secondary" type="button" :disabled="loading" @click="load">
          {{ t('common.refresh') }}
        </button>
      </div>

      <form class="card flex flex-wrap items-end gap-3 p-4" @submit.prevent="createOffer">
        <label class="min-w-[12rem] flex-1">
          <span class="input-label">账号</span>
          <select v-model.number="draft.account_id" class="input" required>
            <option :value="0" disabled>选择要挂出的账号</option>
            <option v-for="account in ownAccounts" :key="account.id" :value="account.id">
              {{ account.name }} · {{ account.platform }}
            </option>
          </select>
        </label>
        <label class="w-36">
          <span class="input-label">Token 额度</span>
          <input v-model.number="draft.token_quota" class="input" type="number" min="0" placeholder="可空" />
        </label>
        <label class="w-28">
          <span class="input-label">时长（小时）</span>
          <input v-model.number="draft.duration_hours" class="input" type="number" min="1" />
        </label>
        <label class="flex items-center gap-2 pb-2 text-sm text-gray-700 dark:text-gray-300">
          <input v-model="draft.exclusive" type="checkbox" class="rounded border-gray-300 text-primary-600" />
          独占
        </label>
        <label class="min-w-[10rem] flex-1">
          <span class="input-label">备注</span>
          <input v-model="draft.note" class="input" placeholder="可选" />
        </label>
        <button class="btn btn-primary" type="submit">挂出</button>
      </form>

      <p v-if="error" class="text-sm text-red-500">{{ error }}</p>

      <div class="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
        <article v-for="row in rentals" :key="row.id" class="card flex flex-col gap-3 p-5">
          <div class="flex items-start justify-between gap-2">
            <h3 class="font-medium text-gray-900 dark:text-white">{{ row.account_name || ('#' + row.account_id) }}</h3>
            <span class="rounded-md bg-gray-100 px-1.5 py-0.5 text-xs text-gray-600 dark:bg-dark-700 dark:text-gray-300">
              {{ statusLabel(row.status) }}
            </span>
          </div>
          <p class="text-xs text-gray-500">
            {{ row.account_platform }} · {{ row.exclusive ? '独占' : '可共享' }}
          </p>
          <p class="text-sm text-gray-600 dark:text-gray-300">
            额度 {{ formatTokens(row.tokens_used) }} / {{ row.token_quota ? formatTokens(row.token_quota) : '不限' }}
            <span v-if="row.duration_hours"> · {{ row.duration_hours }}h</span>
          </p>
          <p v-if="row.ends_at" class="text-xs text-gray-400">至 {{ formatTime(row.ends_at) }}</p>
          <p v-if="row.note" class="text-sm text-gray-500">{{ row.note }}</p>
          <div class="mt-auto flex flex-wrap gap-2">
            <button v-if="row.status === 'listed' && row.owner_user_id !== myId" class="btn btn-primary btn-sm" type="button" @click="act(row, 'request')">租用</button>
            <button v-if="row.status === 'requested'" class="btn btn-primary btn-sm" type="button" @click="act(row, 'approve')">批准</button>
            <button v-if="row.status === 'requested'" class="btn btn-secondary btn-sm" type="button" @click="act(row, 'reject')">拒绝</button>
            <button
              v-if="row.status === 'active' || row.status === 'listed' || row.status === 'requested'"
              class="btn btn-secondary btn-sm"
              type="button"
              @click="act(row, 'revoke')"
            >
              收回
            </button>
          </div>
        </article>
      </div>
    </div>
  </AppLayout>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import AppLayout from '@/components/layout/AppLayout.vue'
import { createRental, listRentals, rentalAction, type AccountRental } from '@/api/usage'
import { listBerthAccounts, type BerthAccount } from '@/api/berth'
import { useAuthStore } from '@/stores/auth'

const { t } = useI18n()
const authStore = useAuthStore()
const myId = computed(() => authStore.user?.id ?? 0)
const loading = ref(false)
const error = ref('')
const rentals = ref<AccountRental[]>([])
const ownAccounts = ref<BerthAccount[]>([])
const draft = reactive({
  account_id: 0,
  token_quota: undefined as number | undefined,
  duration_hours: 24,
  exclusive: true,
  note: '',
})

async function load() {
  loading.value = true
  error.value = ''
  try {
    const [mine, market, owned] = await Promise.all([
      listRentals('mine'),
      listRentals('market'),
      listBerthAccounts(),
    ])
    const seen = new Set<number>()
    rentals.value = [...market, ...mine].filter((row) => {
      if (seen.has(row.id)) return false
      seen.add(row.id)
      return true
    })
    ownAccounts.value = owned.filter((row) => !row.borrowed)
  } catch (err) {
    error.value = err instanceof Error ? err.message : '加载失败'
  } finally {
    loading.value = false
  }
}

async function createOffer() {
  if (!draft.account_id) return
  await createRental({
    account_id: draft.account_id,
    token_quota: draft.token_quota || undefined,
    duration_hours: draft.duration_hours || undefined,
    exclusive: draft.exclusive,
    note: draft.note || undefined,
  })
  await load()
}

async function act(row: AccountRental, action: 'request' | 'approve' | 'reject' | 'revoke') {
  try {
    await rentalAction(row.id, action)
    await load()
  } catch (err) {
    error.value = err instanceof Error ? err.message : '操作失败'
  }
}

function statusLabel(status: string) {
  return ({ listed: '挂出', requested: '待批', active: '租用中', rejected: '已拒', expired: '到期', revoked: '已收回' } as Record<string, string>)[status] || status
}

function formatTokens(value: number) {
  if (!value) return '0'
  if (value >= 1_000_000) return `${(value / 1_000_000).toFixed(1)}M`
  if (value >= 1000) return `${(value / 1000).toFixed(1)}k`
  return String(value)
}

function formatTime(value: string) {
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString()
}

onMounted(load)
</script>
