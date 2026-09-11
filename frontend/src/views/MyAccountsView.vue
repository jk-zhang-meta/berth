<template>
  <AppLayout>
    <div class="space-y-6">
      <p class="text-sm text-gray-500 dark:text-gray-400">
        停靠自己的 Claude / Codex / Gemini 号。挂到市场后别人可以租；收回后只有你能用。
      </p>

      <form class="card grid grid-cols-1 gap-3 p-4 md:grid-cols-2 xl:grid-cols-4" @submit.prevent="createAccount">
        <label>
          <span class="input-label">名称</span>
          <input v-model="draft.name" class="input" required placeholder="家里的 Pro 号" />
        </label>
        <label>
          <span class="input-label">平台</span>
          <select v-model="draft.platform" class="input">
            <option value="openai">OpenAI / Codex</option>
            <option value="anthropic">Claude</option>
            <option value="gemini">Gemini</option>
          </select>
        </label>
        <label>
          <span class="input-label">类型</span>
          <select v-model="draft.type" class="input">
            <option value="oauth">OAuth</option>
            <option value="apikey">API Key</option>
            <option value="setup-token">Setup Token</option>
          </select>
        </label>
        <label>
          <span class="input-label">代理</span>
          <select v-model.number="draft.proxy_id" class="input">
            <option :value="0">不使用代理</option>
            <option v-for="proxy in proxies" :key="proxy.id" :value="proxy.id">
              {{ proxy.name }} · {{ proxy.host }}:{{ proxy.port }}
            </option>
          </select>
        </label>
        <label class="md:col-span-2 xl:col-span-3">
          <span class="input-label">{{ credentialLabel }}</span>
          <input v-model="draft.secret" class="input" :placeholder="credentialPlaceholder" required />
        </label>
        <div class="flex items-end">
          <button class="btn btn-primary w-full" type="submit" :disabled="saving">停靠</button>
        </div>
      </form>

      <p v-if="error" class="text-sm text-red-500">{{ error }}</p>

      <div class="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
        <article v-for="row in accounts" :key="row.id" class="card flex flex-col gap-3 p-5">
          <div class="flex items-start justify-between gap-2">
            <h3 class="font-medium text-gray-900 dark:text-white">{{ row.name }}</h3>
            <span class="rounded-md bg-gray-100 px-1.5 py-0.5 text-xs text-gray-600 dark:bg-dark-700 dark:text-gray-300">
              {{ row.borrowed ? '租来的' : row.listed ? '已挂出' : '自用' }}
            </span>
          </div>
          <p class="text-xs text-gray-500">{{ platformLabel(row.platform) }} · {{ row.type }} · {{ row.status }}</p>
          <div v-if="!row.borrowed" class="mt-auto flex flex-wrap gap-2">
            <button v-if="!row.listed" class="btn btn-primary btn-sm" type="button" @click="listOnMarket(row)">挂到市场</button>
            <button v-else class="btn btn-secondary btn-sm" type="button" @click="reclaim(row)">收回</button>
          </div>
        </article>
      </div>
    </div>
  </AppLayout>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import AppLayout from '@/components/layout/AppLayout.vue'
import { createBerthAccount, listBerthAccounts, listBerthProxies, type BerthAccount, type BerthProxy } from '@/api/berth'
import { createRental, rentalAction } from '@/api/usage'

const accounts = ref<BerthAccount[]>([])
const proxies = ref<BerthProxy[]>([])
const error = ref('')
const saving = ref(false)
const draft = reactive({
  name: '',
  platform: 'openai',
  type: 'oauth',
  secret: '',
  proxy_id: 0,
})

const credentialLabel = computed(() => {
  if (draft.type === 'apikey') return 'API Key'
  if (draft.type === 'setup-token') return 'Setup Token'
  return 'Refresh Token / Access Token'
})

const credentialPlaceholder = computed(() => {
  if (draft.type === 'apikey') return 'sk-...'
  return '粘贴 token'
})

function platformLabel(platform: string) {
  if (platform === 'anthropic') return 'Claude'
  if (platform === 'openai') return 'OpenAI / Codex'
  return platform
}

function credentials() {
  if (draft.type === 'apikey') return { api_key: draft.secret }
  if (draft.type === 'setup-token') return { setup_token: draft.secret }
  return { refresh_token: draft.secret, access_token: draft.secret }
}

async function load() {
  error.value = ''
  try {
    const [accountRows, proxyRows] = await Promise.all([listBerthAccounts(), listBerthProxies()])
    accounts.value = accountRows
    proxies.value = proxyRows
  } catch (err) {
    error.value = err instanceof Error ? err.message : '加载失败'
  }
}

async function createAccount() {
  saving.value = true
  error.value = ''
  try {
    await createBerthAccount({
      name: draft.name,
      platform: draft.platform,
      type: draft.type,
      credentials: credentials(),
      proxy_id: draft.proxy_id || undefined,
    })
    draft.name = ''
    draft.secret = ''
    await load()
  } catch (err) {
    error.value = err instanceof Error ? err.message : '停靠失败'
  } finally {
    saving.value = false
  }
}

async function listOnMarket(row: BerthAccount) {
  await createRental({ account_id: row.id, exclusive: true, duration_hours: 24 })
  await load()
}

async function reclaim(row: BerthAccount) {
  if (!row.rental_id) return
  await rentalAction(row.rental_id, 'revoke')
  await load()
}

onMounted(load)
</script>
