<template>
  <article class="account-card" :class="'is-' + statusKind" data-testid="account-pool-card">
    <div class="card-top">
      <span class="id-pill" :title="'ID: ' + account.id">#{{ account.id }}</span>
      <div class="email-cell">
        <div class="email-line">
          <span class="email-plain" :title="email">{{ email }}</span>
          <button type="button" class="email-copy" title="复制邮箱" @click="copyEmail">
            <svg class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.8">
              <path stroke-linecap="round" stroke-linejoin="round" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
            </svg>
          </button>
        </div>
        <small v-if="account.name && account.name !== email">{{ account.name }}</small>
      </div>
      <span class="provider-pill" :title="platformName">
        <i>{{ mark }}</i>
        {{ platformName }}
      </span>
      <span class="type-pill" :title="account.type">{{ typeLabel }}</span>
      <span class="plan-pill" :class="planTone">{{ plan }}</span>
      <span v-if="privacyMode" class="privacy-pill" :title="'隐私模式: ' + privacyMode">
        🔒 {{ privacyMode }}
      </span>
    </div>

    <div class="card-status-row">
      <div class="status-display">
        <AccountStatusIndicator :account="account" @show-temp-unsched="emit('show-temp-unsched', account)" />
      </div>
      <div class="priority-widget" title="调度权值（数值越低越先调度）">
        <span class="priority-value">P{{ account.priority }}</span>
        <button
          v-if="showPoolControls"
          type="button"
          class="priority-edit-btn"
          title="修改调度权值"
          @click="openPriorityModal"
        >
          <svg class="h-3 w-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.2">
            <path stroke-linecap="round" stroke-linejoin="round" d="M15.232 5.232l3.536 3.536m-2.036-5.036a2.5 2.5 0 113.536 3.536L6.5 21.036H3v-3.572L16.732 3.732z" />
          </svg>
        </button>
      </div>
      <button
        type="button"
        class="sched-pill"
        :class="{ on: account.schedulable }"
        :disabled="togglingSchedulable"
        :title="account.schedulable ? '调度已开启，点击暂停调度' : '调度已暂停，点击开启调度'"
        @click="emit('toggle-schedulable', account)"
      >
        {{ account.schedulable ? 'ON' : 'OFF' }}
      </button>
      <span class="concurrency-pill" :title="'并发限制: ' + (account.concurrency ? account.concurrency : '不限')">
        <svg class="h-3 w-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
          <path stroke-linecap="round" stroke-linejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z" />
        </svg>
        <span>{{ account.current_concurrency ?? 0 }}/{{ account.concurrency || '∞' }}</span>
      </span>
    </div>

    <!-- 关联代理：默认显示在卡片上，下拉框支持自由切换 -->
    <div class="card-proxy-row">
      <div class="proxy-select-wrap">
        <svg class="h-3.5 w-3.5 text-blue-500 flex-none" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
          <path stroke-linecap="round" stroke-linejoin="round" d="M12 21a9.004 9.004 0 008.716-6.747M12 21a9.004 9.004 0 01-8.716-6.747M12 21c2.485 0 4.5-4.03 4.5-9S14.485 3 12 3m0 18c-2.485 0-4.5-4.03-4.5-9S9.515 3 12 3m0 0a8.997 8.997 0 017.843 4.582M12 3a8.997 8.997 0 00-7.843 4.582m15.686 0A11.953 11.953 0 0112 10.5c-2.998 0-5.74-1.1-7.843-2.918m15.686 0A8.959 8.959 0 0121 12c0 .778-.099 1.533-.284 2.253m0 0A17.919 17.919 0 0112 16.5c-3.162 0-6.133-.815-8.716-2.247m0 0A9.015 9.015 0 013 12c0-1.605.42-3.113 1.157-4.418" />
        </svg>
        <span class="proxy-label">代理:</span>
        <select
          class="proxy-select"
          :value="currentProxyId ?? ''"
          :disabled="updatingProxy"
          title="切换账号代理"
          @change="handleProxySelectChange"
        >
          <option value="">直连 (无代理)</option>
          <option
            v-for="p in proxyOptions"
            :key="p.id"
            :value="p.id"
          >
            {{ p.name }}{{ p.country_code ? ` (${p.country_code})` : '' }} [{{ p.account_count || 0 }} 账号 | 并发: {{ p.concurrency || 0 }}]
          </option>
        </select>
        <span v-if="updatingProxy" class="proxy-saving-spinner" title="正在切换代理...">
          <svg class="animate-spin h-3.5 w-3.5 text-teal-600" fill="none" viewBox="0 0 24 24">
            <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
            <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
          </svg>
        </span>
      </div>
      <span v-if="account.proxy?.expires_at" class="proxy-expires">
        到期: {{ formatDateTime(account.proxy.expires_at) }}
      </span>
      <span v-if="account.proxy_fallback_origin_id" class="proxy-fallback-pill" :title="account.proxy_fallback_origin_name ? ('回退代理: ' + account.proxy_fallback_origin_name) : '当前处于回退代理状态'">
        回退代理中
      </span>
    </div>

    <!-- 所属分组 -->
    <div v-if="displayGroups && displayGroups.length > 0" class="card-groups-row">
      <span class="groups-label">分组:</span>
      <div class="groups-list">
        <span v-for="g in displayGroups" :key="g.id" class="group-tag">
          {{ g.name }}
        </span>
      </div>
    </div>

    <!-- 配额用量窗口 -->
    <div class="card-quota">
      <AccountUsageCell
        :account="account"
        :today-stats="todayStats"
        :today-stats-loading="todayStatsLoading"
        :manual-refresh-token="manualRefreshToken"
        :batched-usage="batchedUsage"
        :batched-usage-error="batchedUsageError"
        :batched-usage-loading="batchedUsageLoading"
        :request-batched-usage="requestBatchedUsage"
        @account-updated="emit('account-updated', $event)"
        @usage-loaded="emit('usage-loaded', $event)"
      />
    </div>

    <!-- 今日统计面板：卡片化整合呈现 -->
    <div class="today-stats-panel" data-test="today-stats-panel">
      <div class="stats-panel-head">
        <div class="stats-panel-title">
          <span v-if="!todayStatsError && (todayStats || todayStatsLoading)" class="live-dot" :class="{ 'is-loading': todayStatsLoading }"></span>
          <span class="title-text">今日统计</span>
          <span v-if="todayStatsLoading" class="loading-tag">刷新中…</span>
        </div>
        <span
          v-if="todayStats?.user_cost !== undefined && todayStats.user_cost > 0"
          class="user-cost-tag"
          title="今日用户侧实际扣费"
        >
          用户: {{ formatCostNumber(todayStats.user_cost) }}
        </span>
      </div>
      <span v-if="todayStatsError" role="status" class="text-xs text-amber-700 dark:text-amber-400">
        {{ todayStats ? '刷新失败，显示上次数据' : '加载失败，今日统计暂不可用' }}
      </span>
      <div class="stats-grid card-metrics">
        <div class="stat-col">
          <small>#REQ</small>
          <strong>{{ todayStatsLoading && !todayStats ? '…' : formatCompactCount(todayStats?.requests) }}</strong>
        </div>
        <div class="stat-col">
          <small>#TOKEN</small>
          <strong>{{ todayStatsLoading && !todayStats ? '…' : formatCompactCount(todayStats?.tokens) }}</strong>
        </div>
        <div class="stat-col">
          <small>$COST</small>
          <strong class="stat-cost">{{ todayStatsLoading && !todayStats ? '…' : formatCostNumber(todayStats?.cost) }}</strong>
        </div>
        <div class="stat-col">
          <small>{{ t('usage.latencyFirstToken') }}</small>
          <strong
            class="first-token"
            :class="'is-' + tokenTone"
            :title="t('admin.ops.tooltips.ttft')"
          >{{ firstToken }}</strong>
        </div>
        <div class="stat-col response-duration" title="今日平均响应总耗时：从请求开始到响应结束，包含流式输出时间">
          <small>响应总耗时</small>
          <strong>{{ formatFirstTokenMs(account.duration_ms) }}</strong>
        </div>
      </div>
    </div>

    <!-- 卡片底部：倍率、时间戳、操作按钮 -->
    <div class="card-footer">
      <div class="account-times">
        <span>
          <small>倍率</small>
          <strong class="multiplier-val inline-flex items-center gap-1 font-semibold text-gray-700 dark:text-gray-200">
            <span>{{ formatMultiplier(account.rate_multiplier ?? 1) }}×</span>
            <span
              v-if="account.extra?.upstream_billing_rate_sync_enabled === true"
              class="inline-flex text-emerald-600 dark:text-emerald-400"
              title="上游倍率已自动同步"
            >
              <svg class="h-3 w-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                <path stroke-linecap="round" stroke-linejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
              </svg>
            </span>
          </strong>
        </span>
        <span><small>使用</small>{{ formatDateTime(account.last_used_at) || '--' }}</span>
        <span><small>创建</small>{{ formatDateTime(account.created_at) || '--' }}</span>
        <span v-if="account.expires_at">
          <small>到期</small>
          <span>{{ formatExpiresAt(account.expires_at) }}</span>
          <span v-if="isExpired(account.expires_at)" class="expire-badge is-expired">已过期</span>
          <span v-if="account.auto_pause_on_expired" class="expire-badge is-autopause" title="到期自动暂停">自动暂停</span>
        </span>
      </div>
      <div class="table-row-actions">
        <button type="button" @click="emit('edit', account)">{{ t('common.edit') }}</button>
        <button type="button" class="is-danger" @click="emit('delete', account)">{{ t('common.delete') }}</button>
        <button
          type="button"
          class="notes-btn"
          :class="{ 'has-notes': Boolean(account.notes) }"
          :title="account.notes ? ('备注: ' + account.notes) : '点击添加或查看备注'"
          @click="openNotesModal"
        >
          <span>备注</span>
          <span v-if="account.notes" class="notes-dot" title="已填写备注"></span>
        </button>
        <button type="button" @click="onMore">{{ t('common.more') }}</button>
        <span
          v-if="showPoolControls && account.owner_label"
          class="relay-pill card-owner"
          :title="'所属用户: ' + account.owner_label"
        >{{ account.owner_label }}</span>
      </div>
    </div>

    <!-- 备注查看/编辑弹窗 -->
    <Teleport to="body">
      <div
        v-if="showNotesModal"
        class="notes-modal-backdrop"
        @click.self="closeNotesModal"
      >
        <div class="notes-modal-content">
          <div class="notes-modal-head">
            <div class="flex items-center gap-2">
              <svg class="h-5 w-5 text-teal-600 dark:text-teal-400 flex-none" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                <path stroke-linecap="round" stroke-linejoin="round" d="M7 8h10M7 12h4m1 8l-4-4H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-3l-4 4z" />
              </svg>
              <h3 class="text-base font-bold text-gray-900 dark:text-white">
                账号备注 - #{{ account.id }}
              </h3>
            </div>
            <button
              type="button"
              class="notes-close-btn"
              title="关闭"
              @click="closeNotesModal"
            >
              <svg class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>

          <div class="notes-modal-body">
            <textarea
              v-model="notesDraft"
              rows="6"
              class="notes-textarea"
              placeholder="暂无备注信息，可在此输入备注内容..."
            ></textarea>
          </div>

          <div class="notes-modal-foot">
            <button
              type="button"
              class="btn-cancel"
              @click="closeNotesModal"
            >
              关闭
            </button>
            <button
              type="button"
              class="btn-save"
              :disabled="savingNotes"
              @click="handleSaveNotes"
            >
              <svg v-if="savingNotes" class="animate-spin h-4 w-4 text-white" fill="none" viewBox="0 0 24 24">
                <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
              </svg>
              保存备注
            </button>
          </div>
        </div>
      </div>
    </Teleport>

    <!-- 调度权值修改弹窗 -->
    <Teleport to="body">
      <div
        v-if="showPriorityModal"
        class="priority-modal-backdrop"
        @click.self="closePriorityModal"
      >
        <div class="priority-modal-content">
          <div class="priority-modal-head">
            <h3 class="text-base font-bold text-gray-900 dark:text-white">
              修改调度权值 - #{{ account.id }}
            </h3>
            <button
              type="button"
              class="priority-close-btn"
              title="关闭"
              @click="closePriorityModal"
            >
              <svg class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>

          <div class="priority-modal-body">
            <label class="block text-xs font-semibold text-gray-700 dark:text-gray-300 mb-1.5">
              权值数值 (数值越小优先级越高)
            </label>
            <input
              v-model.number="priorityDraft"
              type="number"
              min="0"
              step="1"
              class="priority-input"
              @keyup.enter="handleSavePriority"
            />
            <p class="mt-2 text-xs text-gray-500 dark:text-gray-400">
              调度器在选择账号时，会优先使用权值更小的账号（例如 P0 优先于 P1）。
            </p>
          </div>

          <div class="priority-modal-foot">
            <button
              type="button"
              class="btn-cancel"
              @click="closePriorityModal"
            >
              取消
            </button>
            <button
              type="button"
              class="btn-save"
              :disabled="savingPriority"
              @click="handleSavePriority"
            >
              <svg v-if="savingPriority" class="animate-spin h-4 w-4 text-white" fill="none" viewBox="0 0 24 24">
                <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
              </svg>
              保存
            </button>
          </div>
        </div>
      </div>
    </Teleport>
  </article>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue'
import { useI18n } from 'vue-i18n'
import AccountStatusIndicator from '@/components/account/AccountStatusIndicator.vue'
import AccountUsageCell from '@/components/account/AccountUsageCell.vue'
import { adminAPI } from '@/api'
import { useAppStore } from '@/stores/app'
import { useClipboard } from '@/composables/useClipboard'
import { platformLabel } from '@/utils/platformColors'
import { formatDateTime } from '@/utils/format'
import { formatMultiplier } from '@/utils/formatters'
import type { Account, AccountUsageInfo, Proxy as AccountProxy, WindowStats } from '@/types'
import {
  accountEmail,
  accountPlan,
  cardStatusKind,
  firstTokenTone,
  formatCompactCount,
  formatCostNumber,
  formatFirstTokenMs,
  planClass,
  providerMark
} from './accountCardDisplay'

const props = withDefaults(
  defineProps<{
    account: Account
    groups?: { id: number; name: string }[] | null
    proxies?: AccountProxy[] | null
    todayStats?: WindowStats | null
    todayStatsLoading?: boolean
    todayStatsError?: string | null
    manualRefreshToken?: number
    batchedUsage?: AccountUsageInfo | null
    batchedUsageError?: string | null
    batchedUsageLoading?: boolean
    requestBatchedUsage?: ((account: Account, options?: { force?: boolean }) => void) | null
    togglingSchedulable?: boolean
    showPoolControls?: boolean
  }>(),
  {
    groups: null,
    proxies: null,
    todayStats: null,
    todayStatsLoading: false,
    todayStatsError: null,
    manualRefreshToken: 0,
    batchedUsage: null,
    batchedUsageError: null,
    batchedUsageLoading: false,
    requestBatchedUsage: null,
    togglingSchedulable: false,
    showPoolControls: false
  }
)

const emit = defineEmits<{
  edit: [account: Account]
  delete: [account: Account]
  more: [account: Account, event: MouseEvent]
  'toggle-schedulable': [account: Account]
  'account-updated': [account: Account]
  'usage-loaded': [usage: AccountUsageInfo]
  'show-temp-unsched': [account: Account]
}>()

const { t } = useI18n()
const { copyToClipboard } = useClipboard()

const showFeedback = (type: 'success' | 'error', message: string) => {
  try {
    const store = useAppStore()
    if (type === 'success') {
      store.showSuccess(message)
    } else {
      store.showError(message)
    }
  } catch {
    if (type === 'error') {
      console.error(message)
    }
  }
}

const email = computed(() => accountEmail(props.account))
const plan = computed(() => accountPlan(props.account))
const planTone = computed(() => planClass(plan.value))
const mark = computed(() => providerMark(props.account.platform))
const platformName = computed(() => platformLabel(props.account.platform))
const statusKind = computed(() => cardStatusKind(props.account))
const firstToken = computed(() => formatFirstTokenMs(props.account.first_token_ms))
const tokenTone = computed(() => firstTokenTone(props.account.first_token_ms))

const typeLabel = computed(() => {
  const t = props.account.type
  switch (t) {
    case 'oauth': return 'OAuth'
    case 'setup-token': return 'Setup'
    case 'apikey': return 'API Key'
    case 'upstream': return 'Upstream'
    case 'bedrock': return 'Bedrock'
    case 'service_account': return 'Service Account'
    default: return t ? String(t).toUpperCase() : 'OAuth'
  }
})

const privacyMode = computed(() => {
  const extra = props.account.extra as Record<string, unknown> | undefined
  return (extra?.privacy_mode || (props.account as any).parent_privacy_mode || '') as string
})

const displayGroups = computed(() => {
  if (props.groups && props.groups.length > 0) return props.groups
  if (props.account.groups && props.account.groups.length > 0) return props.account.groups
  return []
})

// 备注弹窗状态与操作
const showNotesModal = ref(false)
const notesDraft = ref('')
const savingNotes = ref(false)

const openNotesModal = () => {
  notesDraft.value = props.account.notes || ''
  showNotesModal.value = true
}

const closeNotesModal = () => {
  showNotesModal.value = false
}

const handleSaveNotes = async () => {
  savingNotes.value = true
  try {
    const updated = await adminAPI.accounts.update(props.account.id, {
      notes: notesDraft.value.trim()
    })
    emit('account-updated', updated)
    showFeedback('success', '备注保存成功')
    closeNotesModal()
  } catch (error: any) {
    console.error('Failed to save notes:', error)
    showFeedback('error', error?.response?.data?.message || '保存备注失败')
  } finally {
    savingNotes.value = false
  }
}

// 调度权值弹窗状态与操作
const showPriorityModal = ref(false)
const priorityDraft = ref(0)
const savingPriority = ref(false)

const openPriorityModal = () => {
  priorityDraft.value = props.account.priority ?? 0
  showPriorityModal.value = true
}

const closePriorityModal = () => {
  showPriorityModal.value = false
}

const handleSavePriority = async () => {
  savingPriority.value = true
  try {
    const updated = await adminAPI.accounts.update(props.account.id, {
      priority: Number(priorityDraft.value)
    })
    emit('account-updated', updated)
    showFeedback('success', '调度权值修改成功')
    closePriorityModal()
  } catch (error: any) {
    console.error('Failed to update priority:', error)
    showFeedback('error', error?.response?.data?.message || '修改调度权值失败')
  } finally {
    savingPriority.value = false
  }
}

// 代理下拉选项与切换
interface MinimalProxyOption {
  id: number
  name: string
  country_code?: string
  concurrency?: number
  account_count?: number
}

const currentProxyId = computed<number | null>(() => {
  return props.account.proxy_id ?? props.account.proxy?.id ?? null
})

const proxyOptions = computed<MinimalProxyOption[]>(() => {
  const list: MinimalProxyOption[] = (props.proxies || []).map(p => ({
    id: p.id,
    name: p.name,
    country_code: p.country_code,
    concurrency: p.concurrency ?? 0,
    account_count: p.account_count ?? 0
  }))
  const activeId = currentProxyId.value
  if (activeId && !list.some(p => p.id === activeId)) {
    list.unshift({
      id: activeId,
      name: props.account.proxy?.name || `代理 #${activeId}`,
      country_code: props.account.proxy?.country_code,
      concurrency: props.account.proxy?.concurrency ?? 0,
      account_count: props.account.proxy?.account_count ?? 1
    })
  }
  return list
})

const updatingProxy = ref(false)

const handleProxySelectChange = async (event: Event) => {
  const target = event.target as HTMLSelectElement
  const val = target.value
  const newProxyId = val === '' ? null : Number(val)
  if (newProxyId === currentProxyId.value) return

  updatingProxy.value = true
  try {
    const updated = await adminAPI.accounts.update(props.account.id, {
      proxy_id: newProxyId ?? 0
    })
    emit('account-updated', updated)
    showFeedback('success', newProxyId ? '代理已切换' : '已切换为直连 (无代理)')
  } catch (error: any) {
    console.error('Failed to update proxy:', error)
    showFeedback('error', error?.response?.data?.message || '切换代理失败')
    target.value = currentProxyId.value !== null ? String(currentProxyId.value) : ''
  } finally {
    updatingProxy.value = false
  }
}

const formatExpiresAt = (val?: number | null): string => {
  if (!val) return '--'
  return formatDateTime(new Date(val * 1000)) || '--'
}

const isExpired = (val?: number | null): boolean => {
  if (!val) return false
  return val * 1000 <= Date.now()
}

const copyEmail = () => {
  void copyToClipboard(email.value, t('common.copiedToClipboard'))
}

const onMore = (event: MouseEvent) => {
  emit('more', props.account, event)
}
</script>

<style scoped>
.account-card {
  display: flex;
  flex-direction: column;
  gap: 16px;
  min-height: 300px;
  padding: 18px;
  border: 1px solid rgba(22, 131, 122, 0.12);
  border-radius: 16px;
  background: #ffffff;
  box-shadow:
    0 1px 2px rgba(39, 55, 65, 0.03),
    0 10px 24px rgba(39, 55, 65, 0.05);
  transition: transform 0.2s ease, box-shadow 0.2s ease, border-color 0.2s ease;
}
.account-card:hover {
  transform: translateY(-2px);
  border-color: rgba(22, 131, 122, 0.24);
  box-shadow:
    0 4px 12px rgba(39, 55, 65, 0.07),
    0 16px 32px rgba(39, 55, 65, 0.07);
}
.account-card.is-active { border-left: 4px solid #1ba38f; }
.account-card.is-rate-limited { border-left: 4px solid #d99a3f; }
.account-card.is-error { border-left: 4px solid #d92d20; }
.account-card.is-inactive { border-left: 4px solid #c5d0d4; }

.card-top {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
}
.id-pill {
  display: inline-flex;
  align-items: center;
  padding: 2px 7px;
  border: 1px solid #e2e8f0;
  border-radius: 6px;
  background: #f8fafc;
  color: #64748b;
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  font-size: 11px;
  font-weight: 700;
  line-height: 1.2;
}
:global(.dark) .id-pill {
  border-color: #334155;
  background: #0f172a;
  color: #94a3b8;
}

.email-cell { flex: 1 1 160px; min-width: 0; display: grid; gap: 4px; }
.email-cell small { color: #8b979d; font-size: 12px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.email-line { display: flex; align-items: baseline; gap: 8px; min-width: 0; }
.email-plain {
  overflow: hidden;
  color: #273740;
  font-size: 15px;
  font-weight: 700;
  letter-spacing: -0.02em;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.email-copy {
  display: inline-flex;
  flex: none;
  align-items: center;
  padding: 0;
  border: 0;
  background: none;
  color: #b3c0c5;
  cursor: pointer;
}
.email-copy:hover { color: #16837a; }

.provider-pill {
  display: inline-flex;
  max-width: 100%;
  align-items: center;
  gap: 6px;
  overflow: hidden;
  padding: 4px 10px 4px 5px;
  border: 1px solid #cfe3e0;
  border-radius: 999px;
  background: #f2f8f7;
  color: #0f766e;
  font-size: 12px;
  font-weight: 700;
  line-height: 1.2;
  white-space: nowrap;
}
.provider-pill i {
  display: grid;
  place-items: center;
  width: 20px;
  height: 20px;
  flex: none;
  border-radius: 999px;
  background: linear-gradient(145deg, #137a72, #0d5e59);
  color: #fff;
  font-size: 11px;
  font-style: normal;
  font-weight: 800;
}

.type-pill {
  display: inline-flex;
  align-items: center;
  padding: 3px 8px;
  border: 1px solid #e0e7ff;
  border-radius: 999px;
  background: #eef2ff;
  color: #4338ca;
  font-size: 11px;
  font-weight: 600;
  line-height: 1.2;
  white-space: nowrap;
}
:global(.dark) .type-pill {
  border-color: #3730a3;
  background: #1e1b4b;
  color: #a5b4fc;
}

.privacy-pill {
  display: inline-flex;
  align-items: center;
  padding: 2px 7px;
  border: 1px solid #fed7aa;
  border-radius: 6px;
  background: #fff7ed;
  color: #c2410c;
  font-size: 11px;
  font-weight: 600;
  line-height: 1.2;
  white-space: nowrap;
}
:global(.dark) .privacy-pill {
  border-color: #7c2d12;
  background: #2d140a;
  color: #fb923c;
}

.plan-pill {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  overflow: hidden;
  padding: 4px 10px;
  border: 1px solid #dce6e8;
  border-radius: 999px;
  font-size: 12px;
  font-weight: 700;
  line-height: 1.2;
  white-space: nowrap;
}
.plan-pill.plan-plus { border-color: #cfe5dc; background: #f0f8f4; color: #287a59; }
.plan-pill.plan-pro { border-color: #d8d0ef; background: #f5f1fc; color: #6949a2; }
.plan-pill.plan-other { background: #f5f8f8; color: #68777e; }

.card-status-row {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 10px;
}
.status-display { min-width: 0; flex: 1; }
.status-display :deep(.badge) {
  font-size: 12px;
  padding: 3px 10px;
}
.relay-pill {
  display: inline-flex;
  max-width: 180px;
  overflow: hidden;
  align-items: center;
  padding: 4px 10px;
  border: 1px solid #cfe3e0;
  border-radius: 999px;
  background: #f2f8f7;
  color: #0f766e;
  font-size: 12px;
  line-height: 1.2;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.priority-widget {
  display: inline-flex;
  align-items: center;
  gap: 3px;
}
.priority-value {
  display: inline-flex;
  min-width: 36px;
  justify-content: center;
  padding: 3px 8px;
  border: 1px solid #dce6e8;
  border-radius: 999px;
  background: #f5f8f8;
  color: #42545c;
  font-size: 12px;
  font-weight: 700;
  font-variant-numeric: tabular-nums;
}
.priority-edit-btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 22px;
  height: 22px;
  padding: 0;
  border: 1px solid #dce6e8;
  border-radius: 999px;
  background: #ffffff;
  color: #64748b;
  cursor: pointer;
  transition: all 0.15s ease;
}
.priority-edit-btn:hover {
  border-color: #0d9488;
  color: #0d9488;
  background: #f0fdfa;
}
:global(.dark) .priority-value {
  border-color: #334155;
  background: #0f172a;
  color: #cbd5e1;
}
:global(.dark) .priority-edit-btn {
  border-color: #334155;
  background: #1e293b;
  color: #94a3b8;
}
:global(.dark) .priority-edit-btn:hover {
  border-color: #2dd4bf;
  color: #2dd4bf;
  background: #134e4a;
}

.notes-btn {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  padding: 3px 9px;
  border: 1px solid #dce6e8;
  border-radius: 999px;
  background: #f8fafc;
  color: #64748b;
  font-size: 12px;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.15s ease;
}
.notes-btn:hover {
  border-color: #94a3b8;
  color: #334155;
  background: #f1f5f9;
}
.notes-btn.has-notes {
  border-color: #bbf7d0;
  background: #f0fdf4;
  color: #166534;
}
.notes-dot {
  width: 6px;
  height: 6px;
  border-radius: 999px;
  background: #16a34a;
  flex: none;
}
:global(.dark) .notes-btn {
  border-color: #334155;
  background: #1e293b;
  color: #94a3b8;
}
:global(.dark) .notes-btn:hover {
  border-color: #475569;
  color: #f1f5f9;
  background: #334155;
}
:global(.dark) .notes-btn.has-notes {
  border-color: #166534;
  background: #052e16;
  color: #86efac;
}
:global(.dark) .notes-dot {
  background: #4ade80;
}

.concurrency-pill {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 3px 9px;
  border: 1px solid #e0e7eb;
  border-radius: 999px;
  background: #f0fdf4;
  color: #15803d;
  font-size: 12px;
  font-weight: 650;
  font-variant-numeric: tabular-nums;
  white-space: nowrap;
}
:global(.dark) .concurrency-pill {
  border-color: #14532d;
  background: #052e16;
  color: #4ade80;
}

.card-proxy-row {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  padding: 6px 10px;
  border-radius: 8px;
  background: #f1f5f9;
  font-size: 12px;
}
:global(.dark) .card-proxy-row {
  background: #0f172a;
}
.proxy-select-wrap {
  display: flex;
  align-items: center;
  gap: 6px;
  flex: 1 1 200px;
  min-width: 0;
}
.proxy-label {
  color: #64748b;
  font-size: 11px;
  font-weight: 700;
  flex: none;
}
.proxy-select {
  flex: 1 1 auto;
  min-width: 120px;
  max-width: 240px;
  padding: 3px 8px;
  border: 1px solid #cbd5e1;
  border-radius: 6px;
  background: #ffffff;
  color: #1e293b;
  font-size: 12px;
  cursor: pointer;
  outline: none;
}
.proxy-select:focus {
  border-color: #0d9488;
  box-shadow: 0 0 0 1px #0d9488;
}
.proxy-select:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}
:global(.dark) .proxy-select {
  border-color: #475569;
  background: #1e293b;
  color: #e2e8f0;
}
.proxy-saving-spinner {
  display: inline-flex;
  align-items: center;
}
.proxy-expires {
  color: #64748b;
  font-size: 11px;
}
.proxy-fallback-pill {
  display: inline-flex;
  padding: 1px 6px;
  border-radius: 4px;
  background: #fef3c7;
  color: #92400e;
  font-size: 11px;
  font-weight: 600;
}

.today-stats-panel {
  display: flex;
  flex-direction: column;
  gap: 10px;
  padding: 12px 14px;
  border-radius: 12px;
  border: 1px solid rgba(13, 148, 136, 0.15);
  background: linear-gradient(180deg, #f9fbfb 0%, #f3f7f7 100%);
}
:global(.dark) .today-stats-panel {
  border-color: rgba(45, 212, 191, 0.15);
  background: linear-gradient(180deg, #0f172a 0%, #1e293b 100%);
}
.stats-panel-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
}
.stats-panel-title {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 12px;
  font-weight: 700;
  color: #0f766e;
}
:global(.dark) .stats-panel-title {
  color: #2dd4bf;
}
.live-dot {
  width: 7px;
  height: 7px;
  border-radius: 999px;
  background: #10b981;
  box-shadow: 0 0 6px #10b981;
}
.live-dot.is-loading {
  background: #f59e0b;
  box-shadow: 0 0 6px #f59e0b;
}
.loading-tag {
  font-size: 10px;
  font-weight: 500;
  color: #8b979d;
}
.user-cost-tag {
  display: inline-flex;
  align-items: center;
  padding: 1px 7px;
  border-radius: 999px;
  background: #ecfdf5;
  border: 1px solid #a7f3d0;
  color: #047857;
  font-size: 11px;
  font-weight: 600;
}
:global(.dark) .user-cost-tag {
  background: #064e3b;
  border-color: #059669;
  color: #6ee7b7;
}
.card-quota {
  min-width: 0;
  padding: 12px;
  border: 1px solid #e8eef2;
  border-radius: 10px;
  background: #f8fafc;
}
.card-quota:not(:has(> *)) { display: none; }
.card-quota :deep(.usage-progress-row) {
  display: grid;
  grid-template-columns: 1fr auto auto;
  column-gap: 8px;
  row-gap: 6px;
  padding: 4px 0 8px;
}
.card-quota :deep(.usage-progress-label) {
  grid-column: 1;
  grid-row: 1;
  justify-self: start;
}
.card-quota :deep(.usage-progress-percent) {
  grid-column: 2;
  grid-row: 1;
  font-variant-numeric: tabular-nums;
}
.card-quota :deep(.usage-progress-reset) {
  grid-column: 3;
  grid-row: 1;
  min-width: 62px;
  text-align: right;
  font-variant-numeric: tabular-nums;
}
.card-quota :deep(.usage-progress-track) {
  grid-column: 1 / -1;
  grid-row: 2;
  width: 100%;
  height: 6px;
}
.card-quota :deep(.usage-window-stats > div) {
  flex-wrap: wrap;
}
.stats-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr)) minmax(0, 1fr) minmax(66px, 1.2fr);
  gap: 8px;
}
.stat-col {
  display: flex;
  flex-direction: column;
  gap: 3px;
  min-width: 0;
}
.stat-col small {
  color: #64748b;
  font-size: 11px;
  font-weight: 700;
  letter-spacing: 0.02em;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
:global(.dark) .stat-col small {
  color: #94a3b8;
}
.stat-col strong {
  color: #0f172a;
  font-size: 15px;
  font-weight: 700;
  font-variant-numeric: tabular-nums;
  white-space: nowrap;
}
:global(.dark) .stat-col strong {
  color: #f1f5f9;
}
.stat-cost {
  color: #0d9488 !important;
}
:global(.dark) .stat-cost {
  color: #2dd4bf !important;
}
.first-token.is-good { color: #16756d; }
.first-token.is-ok { color: #b67620; }
.first-token.is-slow { color: #c2410c; }
.first-token.is-bad { color: #d92d20; }

.sched-pill {
  width: fit-content;
  padding: 3px 10px;
  border: 1px solid #dce6e8;
  border-radius: 999px;
  background: #f5f8f8;
  color: #68777e;
  font-size: 12px;
  font-weight: 650;
  white-space: nowrap;
  cursor: pointer;
}
.sched-pill.on { border-color: #cfe5dc; background: #edf8f6; color: #14766f; }
.sched-pill:disabled { opacity: 0.6; cursor: wait; }

.card-footer {
  display: flex;
  flex-direction: column;
  gap: 12px;
  margin-top: auto;
  padding-top: 6px;
}
.account-times {
  display: grid;
  gap: 4px;
  color: #596970;
  font-size: 12px;
  line-height: 1.35;
  font-variant-numeric: tabular-nums;
}
.account-times > span { display: flex; align-items: center; gap: 6px; min-width: 0; flex-wrap: wrap; }
.account-times small { flex: none; color: #98a2a7; font-size: 11px; }

.expire-badge {
  display: inline-flex;
  padding: 1px 5px;
  border-radius: 4px;
  font-size: 10px;
  font-weight: 600;
  margin-left: 2px;
}
.expire-badge.is-expired {
  background: #fee2e2;
  color: #b91c1c;
}
.expire-badge.is-autopause {
  background: #dcfce7;
  color: #15803d;
}
:global(.dark) .expire-badge.is-expired {
  background: #7f1d1d;
  color: #fca5a5;
}
:global(.dark) .expire-badge.is-autopause {
  background: #14532d;
  color: #86efac;
}

.table-row-actions { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; }
.card-owner {
  margin-left: auto;
  max-width: 100%;
  min-width: 0;
  font-size: 11px;
}
.table-row-actions > button {
  height: 32px;
  padding: 0 12px;
  border: 1px solid #dfe6e8;
  border-radius: 8px;
  background: #fff;
  color: #42545c;
  font-size: 12px;
  cursor: pointer;
}
.table-row-actions > button:hover { border-color: #91bdb7; color: #16837a; }
.table-row-actions > button.is-danger:hover { border-color: #f1b4b0; color: #d92d20; }

:global(.dark) .account-card {
  border-color: rgba(148, 163, 184, 0.16);
  background: #1e293b;
  box-shadow: none;
}
:global(.dark) .email-plain,
:global(.dark) .card-metrics strong { color: #e2e8f0; }
:global(.dark) .card-quota { background: #0f172a; border-color: rgba(148, 163, 184, 0.08); }
:global(.dark) .table-row-actions > button { background: #1e293b; border-color: #334155; color: #cbd5e1; }

.notes-modal-backdrop,
.priority-modal-backdrop {
  position: fixed;
  inset: 0;
  z-index: 9999;
  display: flex;
  align-items: center;
  justify-content: center;
  background: rgba(15, 23, 42, 0.6);
  backdrop-filter: blur(2px);
  padding: 16px;
}
.notes-modal-content {
  width: 100%;
  max-width: 520px;
  background: #ffffff;
  border-radius: 16px;
  box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04);
  padding: 20px;
}
.priority-modal-content {
  width: 100%;
  max-width: 380px;
  background: #ffffff;
  border-radius: 16px;
  box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04);
  padding: 20px;
}
:global(.dark) .notes-modal-content,
:global(.dark) .priority-modal-content {
  background: #1e293b;
  border: 1px solid #334155;
}
.notes-modal-head,
.priority-modal-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 14px;
}
.notes-close-btn,
.priority-close-btn {
  padding: 4px;
  border: 0;
  background: none;
  color: #94a3b8;
  border-radius: 6px;
  cursor: pointer;
}
.notes-close-btn:hover,
.priority-close-btn:hover {
  color: #475569;
  background: #f1f5f9;
}
:global(.dark) .notes-close-btn:hover,
:global(.dark) .priority-close-btn:hover {
  color: #cbd5e1;
  background: #334155;
}
.notes-textarea {
  width: 100%;
  padding: 10px 12px;
  border: 1px solid #cbd5e1;
  border-radius: 8px;
  font-size: 13px;
  line-height: 1.5;
  color: #1e293b;
  background: #f8fafc;
  resize: vertical;
  outline: none;
  box-sizing: border-box;
}
.notes-textarea:focus {
  border-color: #0d9488;
  background: #ffffff;
  box-shadow: 0 0 0 1px #0d9488;
}
:global(.dark) .notes-textarea {
  border-color: #475569;
  background: #0f172a;
  color: #e2e8f0;
}
.priority-input {
  width: 100%;
  padding: 8px 12px;
  border: 1px solid #cbd5e1;
  border-radius: 8px;
  font-size: 14px;
  color: #1e293b;
  background: #ffffff;
  outline: none;
  box-sizing: border-box;
}
.priority-input:focus {
  border-color: #0d9488;
  box-shadow: 0 0 0 1px #0d9488;
}
:global(.dark) .priority-input {
  border-color: #475569;
  background: #0f172a;
  color: #e2e8f0;
}
.notes-modal-foot,
.priority-modal-foot {
  display: flex;
  justify-content: flex-end;
  gap: 10px;
  margin-top: 18px;
}
.btn-cancel {
  padding: 6px 14px;
  border: 1px solid #d1d5db;
  border-radius: 8px;
  background: #ffffff;
  color: #374151;
  font-size: 13px;
  font-weight: 500;
  cursor: pointer;
}
.btn-cancel:hover {
  background: #f9fafb;
}
:global(.dark) .btn-cancel {
  border-color: #4b5563;
  background: #1f2937;
  color: #d1d5db;
}
.btn-save {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 6px 16px;
  border: 0;
  border-radius: 8px;
  background: #0d9488;
  color: #ffffff;
  font-size: 13px;
  font-weight: 600;
  cursor: pointer;
}
.btn-save:hover {
  background: #0f766e;
}
.btn-save:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}
</style>
