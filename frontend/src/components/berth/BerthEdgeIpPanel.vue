<template>
  <section class="mb-5 rounded-xl border border-gray-200 bg-white shadow-sm dark:border-dark-700 dark:bg-dark-800">
    <!-- ==================== ADMIN VIEW (Landing Proxies + Approval Queue ONLY — NO Forwarding Nodes) ==================== -->
    <template v-if="isAdmin">
      <div class="flex flex-wrap items-center justify-between gap-3 border-b border-gray-200 px-5 py-3.5 dark:border-dark-700">
        <div>
          <h2 class="text-base font-semibold text-gray-900 dark:text-white">
            落地节点代理与使用审批
          </h2>
          <p class="mt-0.5 text-xs text-gray-500 dark:text-gray-400">
            只展示已启用落地功能的服务器节点（共 {{ landingNodes.length }} 个，{{ onlineLandingCount }} 在线）；选定落地节点即可在下方代理池生成可绑定账号的免凭据代理。
          </p>
        </div>
        <div class="flex items-center gap-2">
          <router-link to="/admin/nodes" class="btn btn-secondary btn-sm">
            节点管理
          </router-link>
          <button
            type="button"
            class="btn btn-secondary btn-sm"
            :disabled="loading"
            @click="loadAll"
          >
            {{ loading ? '刷新中...' : '刷新' }}
          </button>
          <button
            type="button"
            class="btn btn-primary btn-sm"
            :disabled="landingNodes.length === 0"
            @click="openDirectGrantModal()"
          >
            + 从落地节点创建代理
          </button>
        </div>
      </div>

      <!-- Compact Tabs (Landing Nodes + Grant Approval Queue) -->
      <div class="flex items-center gap-4 border-b border-gray-200 px-5 pt-2.5 dark:border-dark-700">
        <button
          type="button"
          class="border-b-2 pb-2 text-sm font-medium transition-colors"
          :class="adminTab === 'landings'
            ? 'border-primary-600 text-primary-600 dark:text-primary-400'
            : 'border-transparent text-gray-500 hover:text-gray-800 dark:text-gray-400'"
          @click="adminTab = 'landings'"
        >
          可选落地节点 ({{ landingNodes.length }})
        </button>
        <button
          type="button"
          class="inline-flex items-center gap-1.5 border-b-2 pb-2 text-sm font-medium transition-colors"
          :class="adminTab === 'grants'
            ? 'border-primary-600 text-primary-600 dark:text-primary-400'
            : 'border-transparent text-gray-500 hover:text-gray-800 dark:text-gray-400'"
          @click="adminTab = 'grants'"
        >
          <span>申请审批与授权 ({{ adminGrants.length }})</span>
          <span
            v-if="pendingGrantsCount > 0"
            class="rounded-full bg-amber-500 px-1.5 py-0.5 text-[11px] font-semibold leading-none text-white"
          >
            {{ pendingGrantsCount }}
          </span>
        </button>
      </div>

      <!-- Tab 1: Landing Nodes Only (NO transit/ingress-only forwarding nodes!) -->
      <div v-if="adminTab === 'landings'" class="overflow-x-auto">
        <table class="min-w-full divide-y divide-gray-200 text-sm dark:divide-dark-700">
          <thead class="bg-gray-50 text-xs uppercase text-gray-500 dark:bg-dark-900/60 dark:text-gray-400">
            <tr>
              <th class="px-4 py-2 text-left">落地节点</th>
              <th class="px-4 py-2 text-left">出口 IP</th>
              <th class="px-4 py-2 text-left">地区 / 时区</th>
              <th class="px-4 py-2 text-left">月流量</th>
              <th class="px-4 py-2 text-left">状态</th>
              <th class="px-4 py-2 text-right">操作</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-gray-100 dark:divide-dark-700/70">
            <tr
              v-for="node in landingNodes"
              :key="node.id"
              class="hover:bg-gray-50/70 dark:hover:bg-dark-700/40"
            >
              <td class="px-4 py-2">
                <div class="font-medium text-gray-900 dark:text-white">{{ node.name }}</div>
                <div class="text-xs text-gray-400">Node #{{ node.id }}</div>
              </td>
              <td class="px-4 py-2 font-mono text-xs text-gray-800 dark:text-gray-200">
                {{ node.exit_ip || '-' }}
              </td>
              <td class="px-4 py-2 text-xs text-gray-600 dark:text-gray-300">
                {{ node.exit_country_code || '-' }} · {{ node.exit_timezone || '-' }}
              </td>
              <td class="px-4 py-2 text-xs text-gray-600 dark:text-gray-300">
                {{ formatBytes(node.used_bytes_month) }} / {{ node.max_bytes_month > 0 ? formatBytes(node.max_bytes_month) : '不限' }}
              </td>
              <td class="px-4 py-2">
                <span class="rounded-full px-2 py-0.5 text-xs font-medium" :class="statusBadgeClass(node.status)">
                  {{ node.status === 'active' ? '在线' : node.status }}
                </span>
              </td>
              <td class="px-4 py-2 text-right">
                <button
                  type="button"
                  class="btn btn-primary btn-xs"
                  :disabled="node.status === 'suspended'"
                  @click="openDirectGrantModal(node)"
                >
                  生成落地代理
                </button>
              </td>
            </tr>
            <tr v-if="!loading && landingNodes.length === 0">
              <td colspan="6" class="px-4 py-6 text-center text-sm text-gray-400">
                暂无已启用落地功能的节点，请先在「节点管理」中为服务器开启落地功能。
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <!-- Tab 2: Landing Grants & Approval Queue -->
      <div v-else class="overflow-x-auto">
        <table class="min-w-full divide-y divide-gray-200 text-sm dark:divide-dark-700">
          <thead class="bg-gray-50 text-xs uppercase text-gray-500 dark:bg-dark-900/60 dark:text-gray-400">
            <tr>
              <th class="px-4 py-2 text-left">申请 / 授权对象</th>
              <th class="px-4 py-2 text-left">目标落地节点</th>
              <th class="px-4 py-2 text-left">状态</th>
              <th class="px-4 py-2 text-left">配额 / 上限</th>
              <th class="px-4 py-2 text-left">申请理由 / 审核备注</th>
              <th class="px-4 py-2 text-right">操作</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-gray-100 dark:divide-dark-700/70">
            <tr
              v-for="g in adminGrants"
              :key="g.id"
              class="hover:bg-gray-50/70 dark:hover:bg-dark-700/40"
              :class="g.status === 'pending' ? 'bg-amber-50/40 dark:bg-amber-900/10' : ''"
            >
              <td class="px-4 py-2">
                <div class="font-medium text-gray-900 dark:text-white">
                  {{ g.grantee_email || `用户 #${g.grantee_user_id}` }}
                </div>
                <div class="text-xs text-gray-500 dark:text-gray-400">
                  Grant #{{ g.id }}<span v-if="g.proxy_id"> · Proxy #{{ g.proxy_id }}</span>
                </div>
              </td>
              <td class="px-4 py-2">
                <div class="font-medium text-gray-900 dark:text-white">{{ g.node_name || `Node #${g.node_id}` }}</div>
                <div class="font-mono text-xs text-gray-500 dark:text-gray-400">
                  {{ g.node_exit_ip || '-' }} · {{ g.exit_country_code || '-' }}
                </div>
              </td>
              <td class="px-4 py-2">
                <span class="rounded-full px-2 py-0.5 text-xs font-medium" :class="grantStatusClass(g.status)">
                  {{ grantStatusLabel(g.status) }}
                </span>
              </td>
              <td class="px-4 py-2 text-xs text-gray-700 dark:text-gray-300">
                <div>流量: {{ formatBytes(g.used_bytes) }} / {{ g.max_bytes > 0 ? formatBytes(g.max_bytes) : '不限' }}</div>
                <div class="text-gray-500">账号≤{{ g.max_accounts }} · 并发≤{{ g.max_concurrency || '不限' }}</div>
              </td>
              <td class="max-w-xs px-4 py-2 text-xs text-gray-600 dark:text-gray-300">
                <div v-if="g.request_reason" class="truncate" :title="g.request_reason">理由: {{ g.request_reason }}</div>
                <div v-if="g.review_note" class="truncate text-gray-400" :title="g.review_note">备注: {{ g.review_note }}</div>
                <span v-if="!g.request_reason && !g.review_note" class="text-gray-400">-</span>
              </td>
              <td class="px-4 py-2 text-right">
                <div class="inline-flex items-center gap-1.5">
                  <template v-if="g.status === 'pending'">
                    <button type="button" class="btn btn-primary btn-xs" @click="openApproveModal(g)">批准</button>
                    <button type="button" class="btn btn-secondary btn-xs text-red-600" @click="openRejectModal(g)">拒绝</button>
                  </template>
                  <button
                    v-else-if="g.status === 'active'"
                    type="button"
                    class="btn btn-secondary btn-xs text-red-600"
                    :disabled="submitting"
                    @click="handleRevoke(g)"
                  >
                    撤销
                  </button>
                </div>
              </td>
            </tr>
            <tr v-if="!loading && adminGrants.length === 0">
              <td colspan="6" class="px-4 py-6 text-center text-sm text-gray-400">
                暂无落地申请或授权记录。点击右上角「从落地节点创建代理」即可为自己或指定用户生成落地代理。
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </template>

    <!-- ==================== NORMAL USER VIEW (Redacted Landing Catalog + My Applications) ==================== -->
    <template v-else>
      <div class="flex flex-wrap items-center justify-between gap-3 border-b border-gray-200 px-5 py-3.5 dark:border-dark-700">
        <div>
          <h2 class="text-base font-semibold text-gray-900 dark:text-white">
            管理员落地节点申请
          </h2>
          <p class="mt-0.5 text-xs text-gray-500 dark:text-gray-400">
            选择管理员开放的落地节点提交申请；批准后自动进入您的可用代理列表，可直接绑定 AI 账号（出口 IP 由平台托管并严格隐藏）。
          </p>
        </div>
        <button type="button" class="btn btn-secondary btn-sm" :disabled="loading" @click="loadAll">
          {{ loading ? '刷新中...' : '刷新' }}
        </button>
      </div>

      <div class="grid grid-cols-1 gap-4 p-5 lg:grid-cols-2">
        <!-- Available Landing Nodes -->
        <div>
          <h3 class="mb-2.5 text-sm font-semibold text-gray-800 dark:text-gray-100">
            可申请的落地节点 ({{ availableNodes.length }})
          </h3>
          <div class="space-y-2">
            <div
              v-for="node in availableNodes"
              :key="node.id"
              class="flex items-center justify-between rounded-lg border border-gray-200 px-3.5 py-2.5 dark:border-dark-700"
            >
              <div>
                <div class="flex items-center gap-2">
                  <span class="font-medium text-gray-900 dark:text-white">{{ node.name }}</span>
                  <span class="rounded-full px-2 py-0.5 text-[11px] font-medium" :class="statusBadgeClass(node.status)">
                    {{ node.status === 'active' ? '在线' : node.status }}
                  </span>
                </div>
                <div class="mt-0.5 text-xs text-gray-500 dark:text-gray-400">
                  地区: {{ node.exit_country_code || '-' }} · 时区: {{ node.exit_timezone || '-' }} · Locale: {{ node.exit_locale || '-' }}
                </div>
              </div>
              <div>
                <span
                  v-if="node.has_active_grant"
                  class="rounded-full bg-emerald-100 px-2.5 py-1 text-xs font-medium text-emerald-700 dark:bg-emerald-900/40 dark:text-emerald-300"
                >
                  已获批
                </span>
                <span
                  v-else-if="node.has_pending_request"
                  class="rounded-full bg-amber-100 px-2.5 py-1 text-xs font-medium text-amber-700 dark:bg-amber-900/40 dark:text-amber-300"
                >
                  待审批
                </span>
                <button
                  v-else
                  type="button"
                  class="btn btn-primary btn-xs"
                  @click="openApplyModal(node)"
                >
                  申请使用
                </button>
              </div>
            </div>
            <div v-if="!loading && availableNodes.length === 0" class="py-6 text-center text-sm text-gray-400">
              当前暂无管理员开放的落地节点
            </div>
          </div>
        </div>

        <!-- My Applications & Grants -->
        <div>
          <h3 class="mb-2.5 text-sm font-semibold text-gray-800 dark:text-gray-100">
            我的申请与落地授权 ({{ userGrants.length }})
          </h3>
          <div class="space-y-2">
            <div
              v-for="g in userGrants"
              :key="g.id"
              class="rounded-lg border border-gray-200 px-3.5 py-2.5 dark:border-dark-700"
            >
              <div class="flex items-center justify-between gap-2">
                <div class="flex items-center gap-2">
                  <span class="font-medium text-gray-900 dark:text-white">{{ g.node_name || `Node #${g.node_id}` }}</span>
                  <span class="rounded-full px-2 py-0.5 text-[11px] font-medium" :class="grantStatusClass(g.status)">
                    {{ grantStatusLabel(g.status) }}
                  </span>
                </div>
                <button
                  v-if="g.status === 'pending'"
                  type="button"
                  class="btn btn-secondary btn-xs text-red-600"
                  :disabled="submitting"
                  @click="handleCancelApplication(g)"
                >
                  撤回申请
                </button>
              </div>
              <div class="mt-1 text-xs text-gray-500 dark:text-gray-400">
                <span>{{ g.exit_country_code || '-' }} · {{ g.exit_timezone || '-' }}</span>
                <span v-if="g.status === 'active'">
                  · 流量 {{ formatBytes(g.used_bytes) }} / {{ g.max_bytes > 0 ? formatBytes(g.max_bytes) : '不限' }}
                  · 账号≤{{ g.max_accounts }}
                </span>
              </div>
              <div v-if="g.request_reason" class="mt-1 text-xs text-gray-600 dark:text-gray-300">
                申请理由: {{ g.request_reason }}
              </div>
              <div v-if="g.review_note" class="mt-1 text-xs text-amber-700 dark:text-amber-300">
                管理员回复: {{ g.review_note }}
              </div>
            </div>
            <div v-if="!loading && userGrants.length === 0" class="py-6 text-center text-sm text-gray-400">
              尚未申请任何落地节点
            </div>
          </div>
        </div>
      </div>
    </template>

    <!-- ==================== MODALS ==================== -->

    <!-- User Apply Modal -->
    <BaseDialog :show="showApplyModal" title="申请使用落地节点" width="normal" @close="showApplyModal = false">
      <div class="space-y-4">
        <div class="rounded-lg bg-gray-50 p-3 text-sm dark:bg-dark-700/60">
          <div class="font-medium text-gray-900 dark:text-white">{{ applyingNode?.name }}</div>
          <div class="mt-0.5 text-xs text-gray-500 dark:text-gray-400">
            {{ applyingNode?.exit_country_code }} · {{ applyingNode?.exit_timezone }} · {{ applyingNode?.exit_locale }}
          </div>
        </div>
        <div>
          <label class="input-label">申请理由 / 用途说明</label>
          <textarea
            v-model="applyForm.request_reason"
            rows="3"
            class="input"
            placeholder="例如：用于日常 Codex / Claude Code 开发，预计绑定 2 个账号"
          />
        </div>
        <div>
          <label class="input-label">预计绑定账号数</label>
          <input v-model.number="applyForm.max_accounts" type="number" min="1" max="50" class="input" />
        </div>
      </div>
      <template #footer>
        <div class="flex justify-end gap-2">
          <button type="button" class="btn btn-secondary" @click="showApplyModal = false">取消</button>
          <button type="button" class="btn btn-primary" :disabled="submitting" @click="submitApply">
            {{ submitting ? '提交中...' : '提交申请' }}
          </button>
        </div>
      </template>
    </BaseDialog>

    <!-- Admin Approve Modal -->
    <BaseDialog :show="showApproveModal" title="批准落地申请并生成代理" width="normal" @close="showApproveModal = false">
      <div class="space-y-4">
        <div class="rounded-lg bg-gray-50 p-3 text-xs dark:bg-dark-700/60">
          <div class="font-medium text-gray-900 dark:text-white">
            {{ reviewingGrant?.grantee_email || `用户 #${reviewingGrant?.grantee_user_id}` }} → {{ reviewingGrant?.node_name }}
          </div>
          <div v-if="reviewingGrant?.request_reason" class="mt-1 text-gray-600 dark:text-gray-300">
            申请理由：{{ reviewingGrant.request_reason }}
          </div>
        </div>
        <div class="grid grid-cols-2 gap-3">
          <div>
            <label class="input-label">月流量上限 (GB, 0=不限)</label>
            <input v-model.number="approveForm.max_gb" type="number" min="0" class="input" />
          </div>
          <div>
            <label class="input-label">最多绑定账号数</label>
            <input v-model.number="approveForm.max_accounts" type="number" min="1" class="input" />
          </div>
          <div>
            <label class="input-label">RPM 限制 (0=不限)</label>
            <input v-model.number="approveForm.max_rpm" type="number" min="0" class="input" />
          </div>
          <div>
            <label class="input-label">并发限制 (0=不限)</label>
            <input v-model.number="approveForm.max_concurrency" type="number" min="0" class="input" />
          </div>
        </div>
        <div>
          <label class="input-label">到期时间（留空永不过期）</label>
          <input v-model="approveForm.expires_date" type="date" class="input" />
        </div>
        <div>
          <label class="input-label">审核备注（用户可见）</label>
          <input v-model="approveForm.review_note" type="text" class="input" placeholder="如：已批准，请合理使用" />
        </div>
      </div>
      <template #footer>
        <div class="flex justify-end gap-2">
          <button type="button" class="btn btn-secondary" @click="showApproveModal = false">取消</button>
          <button type="button" class="btn btn-primary" :disabled="submitting" @click="submitApprove">
            {{ submitting ? '处理中...' : '确认批准' }}
          </button>
        </div>
      </template>
    </BaseDialog>

    <!-- Admin Reject Modal -->
    <BaseDialog :show="showRejectModal" title="拒绝落地申请" width="normal" @close="showRejectModal = false">
      <div class="space-y-3">
        <div class="text-sm text-gray-600 dark:text-gray-300">
          拒绝 <strong>{{ reviewingGrant?.grantee_email || `用户 #${reviewingGrant?.grantee_user_id}` }}</strong>
          对 <strong>{{ reviewingGrant?.node_name }}</strong> 的使用申请：
        </div>
        <div>
          <label class="input-label">拒绝原因（用户可见）</label>
          <textarea v-model="rejectNote" rows="3" class="input" placeholder="如：该落地节点当前负载较高，建议申请其他节点" />
        </div>
      </div>
      <template #footer>
        <div class="flex justify-end gap-2">
          <button type="button" class="btn btn-secondary" @click="showRejectModal = false">取消</button>
          <button type="button" class="btn btn-danger" :disabled="submitting" @click="submitReject">
            {{ submitting ? '处理中...' : '确认拒绝' }}
          </button>
        </div>
      </template>
    </BaseDialog>

    <!-- Admin Create Proxy From Landing Node Modal -->
    <BaseDialog :show="showDirectGrantModal" title="从落地节点创建代理" width="normal" @close="showDirectGrantModal = false">
      <div class="space-y-4">
        <div>
          <label class="input-label">选择落地节点 *</label>
          <select v-model.number="directForm.node_id" class="input">
            <option v-for="n in landingNodes" :key="n.id" :value="n.id">
              {{ n.name }} ({{ n.exit_country_code }} · {{ n.exit_ip || '-' }}{{ n.status !== 'active' ? ' · 离线' : '' }})
            </option>
          </select>
        </div>
        <div>
          <label class="input-label">归属 / 授权用户 *</label>
          <select v-model.number="directForm.grantee_user_id" class="input" :disabled="usersLoadFailed || users.length === 0">
            <option v-if="users.length === 0" :value="0">
              {{ usersLoadFailed ? '用户列表加载失败，请点击刷新重试' : '暂无可选用户' }}
            </option>
            <option v-for="u in users" :key="u.id" :value="u.id">
              {{ u.email }}{{ u.role === 'admin' ? '（管理员本人）' : '' }} (#{{ u.id }})
            </option>
          </select>
          <p v-if="usersLoadFailed" class="mt-1 text-xs text-red-600 dark:text-red-400">
            加载用户列表失败；为避免误授权给错误账号，请刷新后再创建。
          </p>
        </div>
        <div class="grid grid-cols-2 gap-3">
          <div>
            <label class="input-label">月流量上限 (GB, 0=不限)</label>
            <input v-model.number="directForm.max_gb" type="number" min="0" class="input" />
          </div>
          <div>
            <label class="input-label">最多绑定账号数</label>
            <input v-model.number="directForm.max_accounts" type="number" min="1" class="input" />
          </div>
          <div>
            <label class="input-label">RPM 限制 (0=不限)</label>
            <input v-model.number="directForm.max_rpm" type="number" min="0" class="input" />
          </div>
          <div>
            <label class="input-label">并发限制 (0=不限)</label>
            <input v-model.number="directForm.max_concurrency" type="number" min="0" class="input" />
          </div>
        </div>
        <div>
          <label class="input-label">到期时间（留空永不过期）</label>
          <input v-model="directForm.expires_date" type="date" class="input" />
        </div>
        <div>
          <label class="input-label">备注</label>
          <input v-model="directForm.notes" type="text" class="input" placeholder="可选备注" />
        </div>
      </div>
      <template #footer>
        <div class="flex justify-end gap-2">
          <button type="button" class="btn btn-secondary" @click="showDirectGrantModal = false">取消</button>
          <button
            type="button"
            class="btn btn-primary"
            :disabled="submitting || usersLoadFailed || !directForm.node_id || !directForm.grantee_user_id"
            @click="submitDirectGrant"
          >
            {{ submitting ? '创建中...' : '生成落地代理' }}
          </button>
        </div>
      </template>
    </BaseDialog>
  </section>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import BaseDialog from '@/components/common/BaseDialog.vue'
import { useAppStore } from '@/stores/app'
import {
  berthNetworkAPI,
  type BerthAvailableLandingNode,
  type BerthEdgeNode,
  type BerthLandingGrant,
  type BerthSimpleUser,
} from '@/api/berthNetwork'

const props = defineProps<{
  isAdmin: boolean
}>()

const emit = defineEmits<{
  (e: 'grant-changed'): void
}>()

const appStore = useAppStore()
const loading = ref(false)
const submitting = ref(false)
const adminTab = ref<'landings' | 'grants'>('landings')

const allNodes = ref<BerthEdgeNode[]>([])
const adminGrants = ref<BerthLandingGrant[]>([])
const users = ref<BerthSimpleUser[]>([])
const usersLoadFailed = ref(false)

const availableNodes = ref<BerthAvailableLandingNode[]>([])
const userGrants = ref<BerthLandingGrant[]>([])

// Strictly filter to landing-role nodes ONLY (pure forwarding/transit nodes belong in 节点管理).
const landingNodes = computed(() => allNodes.value.filter((n) => (n.roles || []).includes('landing')))
const onlineLandingCount = computed(() => landingNodes.value.filter((n) => n.status === 'active').length)
const pendingGrantsCount = computed(() => adminGrants.value.filter((g) => g.status === 'pending').length)

const statusBadgeClass = (status: string) => {
  switch (status) {
    case 'active':
      return 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/40 dark:text-emerald-300'
    case 'offline':
      return 'bg-gray-100 text-gray-600 dark:bg-dark-700 dark:text-gray-400'
    default:
      return 'bg-amber-100 text-amber-700 dark:bg-amber-900/40 dark:text-amber-300'
  }
}

const grantStatusLabel = (status: string) => {
  switch (status) {
    case 'pending': return '待审批'
    case 'active': return '已激活'
    case 'rejected': return '已拒绝'
    case 'revoked': return '已撤销'
    case 'expired': return '已过期'
    case 'quota_exhausted': return '流量耗尽'
    default: return status
  }
}

const grantStatusClass = (status: string) => {
  switch (status) {
    case 'pending': return 'bg-amber-100 text-amber-700 dark:bg-amber-900/40 dark:text-amber-300'
    case 'active': return 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/40 dark:text-emerald-300'
    case 'rejected':
    case 'revoked': return 'bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-300'
    default: return 'bg-gray-100 text-gray-600 dark:bg-dark-700 dark:text-gray-400'
  }
}

const formatBytes = (bytes: number): string => {
  if (!bytes || bytes <= 0) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let v = bytes
  let i = 0
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024
    i++
  }
  return `${v >= 10 || i === 0 ? v.toFixed(0) : v.toFixed(1)} ${units[i]}`
}

const loadAll = async () => {
  loading.value = true
  try {
    if (props.isAdmin) {
      usersLoadFailed.value = false
      const [n, g, u] = await Promise.all([
        berthNetworkAPI.listNodes(),
        berthNetworkAPI.listAdminGrants(),
        berthNetworkAPI.listUsers().catch(() => {
          usersLoadFailed.value = true
          return [] as BerthSimpleUser[]
        }),
      ])
      allNodes.value = n
      adminGrants.value = g
      users.value = u
      if (g.some((x) => x.status === 'pending')) {
        adminTab.value = 'grants'
      }
    } else {
      const [avail, mine] = await Promise.all([
        berthNetworkAPI.listAvailableLandingNodes(),
        berthNetworkAPI.listUserGrants(),
      ])
      availableNodes.value = avail
      userGrants.value = mine
    }
  } catch (err: any) {
    appStore.showError(err?.message || '加载落地节点信息失败')
  } finally {
    loading.value = false
  }
}

// User apply modal
const showApplyModal = ref(false)
const applyingNode = ref<BerthAvailableLandingNode | null>(null)
const applyForm = reactive({ request_reason: '', max_accounts: 2 })

const openApplyModal = (node: BerthAvailableLandingNode) => {
  applyingNode.value = node
  applyForm.request_reason = ''
  applyForm.max_accounts = 2
  showApplyModal.value = true
}

const submitApply = async () => {
  if (!applyingNode.value) return
  submitting.value = true
  try {
    await berthNetworkAPI.applyLandingGrant({
      node_id: applyingNode.value.id,
      request_reason: applyForm.request_reason.trim(),
      max_accounts: applyForm.max_accounts,
    })
    appStore.showSuccess('已提交落地节点申请，等待管理员审批')
    showApplyModal.value = false
    await loadAll()
  } catch (err: any) {
    appStore.showError(err?.message || '提交申请失败')
  } finally {
    submitting.value = false
  }
}

const handleCancelApplication = async (g: BerthLandingGrant) => {
  submitting.value = true
  try {
    await berthNetworkAPI.cancelPendingApplication(g.id)
    appStore.showSuccess('已撤回申请')
    await loadAll()
  } catch (err: any) {
    appStore.showError(err?.message || '撤回失败')
  } finally {
    submitting.value = false
  }
}

// Admin approve / reject / revoke / direct grant
const showApproveModal = ref(false)
const showRejectModal = ref(false)
const showDirectGrantModal = ref(false)
const reviewingGrant = ref<BerthLandingGrant | null>(null)
const rejectNote = ref('')

const approveForm = reactive({
  max_gb: 0,
  max_accounts: 2,
  max_rpm: 0,
  max_concurrency: 0,
  expires_date: '',
  review_note: '',
})

const directForm = reactive({
  node_id: 0,
  grantee_user_id: 0,
  max_gb: 0,
  max_accounts: 5,
  max_rpm: 0,
  max_concurrency: 0,
  expires_date: '',
  notes: '',
})

const openApproveModal = (g: BerthLandingGrant) => {
  reviewingGrant.value = g
  approveForm.max_gb = g.max_bytes > 0 ? Math.round(g.max_bytes / (1024 * 1024 * 1024)) : 0
  approveForm.max_accounts = g.max_accounts || 2
  approveForm.max_rpm = g.max_rpm || 0
  approveForm.max_concurrency = g.max_concurrency || 0
  approveForm.expires_date = ''
  approveForm.review_note = ''
  showApproveModal.value = true
}

const openRejectModal = (g: BerthLandingGrant) => {
  reviewingGrant.value = g
  rejectNote.value = ''
  showRejectModal.value = true
}

const openDirectGrantModal = (preselectedNode?: BerthEdgeNode) => {
  directForm.node_id = preselectedNode?.id ?? landingNodes.value[0]?.id ?? 0
  const adminUser = users.value.find((u) => u.role === 'admin')
  directForm.grantee_user_id = adminUser?.id ?? users.value[0]?.id ?? 0
  directForm.max_gb = 0
  directForm.max_accounts = 5
  directForm.max_rpm = 0
  directForm.max_concurrency = 0
  directForm.expires_date = ''
  directForm.notes = ''
  showDirectGrantModal.value = true
}

const toISOExpiry = (dateStr: string): string | null => {
  if (!dateStr) return null
  return new Date(`${dateStr}T23:59:59Z`).toISOString()
}

const submitApprove = async () => {
  if (!reviewingGrant.value) return
  submitting.value = true
  try {
    await berthNetworkAPI.approveAdminGrant(reviewingGrant.value.id, {
      max_bytes: approveForm.max_gb > 0 ? Math.round(approveForm.max_gb * 1024 * 1024 * 1024) : 0,
      max_accounts: approveForm.max_accounts,
      max_rpm: approveForm.max_rpm,
      max_concurrency: approveForm.max_concurrency,
      expires_at: toISOExpiry(approveForm.expires_date),
      review_note: approveForm.review_note.trim(),
    })
    appStore.showSuccess('已批准并在下方代理池自动生成落地代理')
    showApproveModal.value = false
    await loadAll()
    emit('grant-changed')
  } catch (err: any) {
    appStore.showError(err?.message || '审批失败')
  } finally {
    submitting.value = false
  }
}

const submitReject = async () => {
  if (!reviewingGrant.value) return
  submitting.value = true
  try {
    await berthNetworkAPI.rejectAdminGrant(reviewingGrant.value.id, rejectNote.value.trim())
    appStore.showSuccess('已拒绝申请')
    showRejectModal.value = false
    await loadAll()
  } catch (err: any) {
    appStore.showError(err?.message || '操作失败')
  } finally {
    submitting.value = false
  }
}

const submitDirectGrant = async () => {
  if (!directForm.node_id || !directForm.grantee_user_id) {
    appStore.showError('请选择落地节点和目标用户')
    return
  }
  submitting.value = true
  try {
    await berthNetworkAPI.createAdminGrant({
      node_id: directForm.node_id,
      grantee_user_id: directForm.grantee_user_id,
      max_bytes: directForm.max_gb > 0 ? Math.round(directForm.max_gb * 1024 * 1024 * 1024) : 0,
      max_accounts: directForm.max_accounts,
      max_rpm: directForm.max_rpm,
      max_concurrency: directForm.max_concurrency,
      expires_at: toISOExpiry(directForm.expires_date),
      notes: directForm.notes.trim(),
    })
    appStore.showSuccess('已生成落地代理并写入下方代理列表')
    showDirectGrantModal.value = false
    await loadAll()
    emit('grant-changed')
  } catch (err: any) {
    appStore.showError(err?.message || '创建失败')
  } finally {
    submitting.value = false
  }
}

const handleRevoke = async (g: BerthLandingGrant) => {
  submitting.value = true
  try {
    await berthNetworkAPI.revokeAdminGrant(g.id, 'admin_revoked')
    appStore.showSuccess('已撤销该落地授权')
    await loadAll()
    emit('grant-changed')
  } catch (err: any) {
    appStore.showError(err?.message || '撤销失败')
  } finally {
    submitting.value = false
  }
}

onMounted(loadAll)
</script>
