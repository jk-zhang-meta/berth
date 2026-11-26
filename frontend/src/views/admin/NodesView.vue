<template>
  <AppLayout>
    <div class="space-y-5">
      <!-- Header -->
      <div class="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 class="text-xl font-semibold text-gray-900 dark:text-white">节点管理</h1>
          <p class="mt-0.5 text-sm text-gray-500 dark:text-gray-400">
            管理全部已部署 <code>berth-edge</code> 的服务器：所有在线节点自动承担所属逻辑分区的接入与网内转发；开启「落地」开关后 ≤15 秒热生效，并出现在「代理管理」中供绑定账号。
          </p>
        </div>
        <div class="flex items-center gap-2">
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
            @click="openCreateNodeModal"
          >
            + 新增服务器节点
          </button>
        </div>
      </div>

      <!-- KPI Strip -->
      <div class="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <div class="rounded-xl border border-gray-200 bg-white p-4 dark:border-dark-700 dark:bg-dark-800">
          <div class="text-xs text-gray-500 dark:text-gray-400">服务器总数 / 在线</div>
          <div class="mt-1 text-2xl font-semibold text-gray-900 dark:text-white">
            {{ nodes.length }}
            <span class="text-sm font-normal text-emerald-600 dark:text-emerald-400">/ {{ activeNodesCount }} 在线</span>
          </div>
        </div>
        <div class="rounded-xl border border-gray-200 bg-white p-4 dark:border-dark-700 dark:bg-dark-800">
          <div class="text-xs text-gray-500 dark:text-gray-400">已启用落地功能</div>
          <div class="mt-1 text-2xl font-semibold text-emerald-600 dark:text-emerald-400">
            {{ landingNodesCount }}
            <span class="text-sm font-normal text-gray-500 dark:text-gray-400">台</span>
          </div>
        </div>
        <div class="rounded-xl border border-gray-200 bg-white p-4 dark:border-dark-700 dark:bg-dark-800">
          <div class="text-xs text-gray-500 dark:text-gray-400">逻辑分区 / 链路</div>
          <div class="mt-1 text-2xl font-semibold text-gray-900 dark:text-white">
            {{ zones.length }}
            <span class="text-sm font-normal text-gray-500 dark:text-gray-400">/ {{ links.length }} 条</span>
          </div>
        </div>
        <div class="rounded-xl border border-gray-200 bg-white p-4 dark:border-dark-700 dark:bg-dark-800">
          <div class="text-xs text-gray-500 dark:text-gray-400">Edge 自动更新目标版本</div>
          <div class="mt-1 truncate font-mono text-sm font-semibold text-gray-900 dark:text-white">
            {{ primaryRelease ? primaryRelease.version : '未发布目标包' }}
          </div>
          <div class="mt-0.5 text-xs text-gray-500 dark:text-gray-400">
            <template v-if="primaryRelease">
              已同步 {{ syncedAgentsCount }} / {{ activeNodesCount }} 在线节点
            </template>
            <template v-else>
              将二进制放至中央 edge-releases 即自动推送
            </template>
          </div>
        </div>
      </div>

      <!-- Tabs -->
      <div class="rounded-xl border border-gray-200 bg-white shadow-sm dark:border-dark-700 dark:bg-dark-800">
        <div class="flex flex-wrap items-center justify-between gap-2 border-b border-gray-200 px-4 pt-3 dark:border-dark-700">
          <div class="flex gap-4">
            <button
              type="button"
              class="border-b-2 pb-2.5 text-sm font-medium transition-colors"
              :class="activeTab === 'nodes'
                ? 'border-primary-600 text-primary-600 dark:text-primary-400'
                : 'border-transparent text-gray-500 hover:text-gray-800 dark:text-gray-400'"
              @click="activeTab = 'nodes'"
            >
              服务器节点 ({{ nodes.length }})
            </button>
            <button
              type="button"
              class="border-b-2 pb-2.5 text-sm font-medium transition-colors"
              :class="activeTab === 'topology'
                ? 'border-primary-600 text-primary-600 dark:text-primary-400'
                : 'border-transparent text-gray-500 hover:text-gray-800 dark:text-gray-400'"
              @click="activeTab = 'topology'"
            >
              逻辑分区与转发链路 ({{ zones.length }} / {{ links.length }})
            </button>
          </div>
          <div v-if="activeTab === 'nodes'" class="flex items-center gap-2 pb-2">
            <select v-model="nodeFilter" class="input py-1 text-xs">
              <option value="all">全部节点</option>
              <option value="relay">仅转发节点</option>
              <option value="landing">仅落地节点</option>
            </select>
          </div>
        </div>

        <!-- Nodes Table -->
        <div v-if="activeTab === 'nodes'" class="overflow-x-auto">
          <table class="min-w-full divide-y divide-gray-200 text-sm dark:divide-dark-700">
            <thead class="bg-gray-50 text-xs uppercase text-gray-500 dark:bg-dark-900/60 dark:text-gray-400">
              <tr>
                <th class="px-4 py-2.5 text-left">节点 / 逻辑分区</th>
                <th class="px-4 py-2.5 text-left">角色（转发 / 落地）</th>
                <th class="px-4 py-2.5 text-left">落地开关（热切换）</th>
                <th class="px-4 py-2.5 text-left">出口 IP / 地区时区</th>
                <th class="px-4 py-2.5 text-left">月流量</th>
                <th class="px-4 py-2.5 text-left">Edge 版本 / 状态</th>
                <th class="px-4 py-2.5 text-right">操作</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-gray-100 dark:divide-dark-700/70">
              <tr
                v-for="node in filteredNodes"
                :key="node.id"
                class="hover:bg-gray-50/70 dark:hover:bg-dark-700/40"
              >
                <td class="px-4 py-2.5">
                  <div class="font-medium text-gray-900 dark:text-white">{{ node.name }}</div>
                  <div class="text-xs text-gray-500 dark:text-gray-400">
                    #{{ node.id }} · {{ zoneName(node.zone_id) }}
                  </div>
                </td>
                <td class="px-4 py-2.5">
                  <div class="flex flex-wrap items-center gap-1.5">
                    <span
                      v-if="isRelayNode(node)"
                      class="rounded bg-blue-100 px-2 py-0.5 text-xs font-medium text-blue-700 dark:bg-blue-900/40 dark:text-blue-300"
                    >
                      转发
                    </span>
                    <span
                      v-if="hasRole(node, 'landing')"
                      class="rounded bg-emerald-100 px-2 py-0.5 text-xs font-medium text-emerald-700 dark:bg-emerald-900/40 dark:text-emerald-300"
                    >
                      落地
                    </span>
                  </div>
                  <div class="mt-0.5 text-[11px] text-gray-400">
                    {{ nodeAccessSummary(node) }}
                  </div>
                </td>
                <td class="px-4 py-2.5">
                  <button
                    type="button"
                    class="inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-medium transition-colors"
                    :class="hasRole(node, 'landing')
                      ? 'bg-emerald-100 text-emerald-700 hover:bg-emerald-200 dark:bg-emerald-900/40 dark:text-emerald-300'
                      : 'bg-gray-100 text-gray-600 hover:bg-gray-200 dark:bg-dark-700 dark:text-gray-300'"
                    :disabled="togglingNodeIds.has(node.id)"
                    @click="toggleLandingRole(node)"
                  >
                    <span
                      class="h-1.5 w-1.5 rounded-full"
                      :class="hasRole(node, 'landing') ? 'bg-emerald-500' : 'bg-gray-400'"
                    />
                    {{ togglingNodeIds.has(node.id) ? '切换中...' : (hasRole(node, 'landing') ? '已开启落地' : '开启落地') }}
                  </button>
                </td>
                <td class="px-4 py-2.5">
                  <div class="font-mono text-xs text-gray-900 dark:text-gray-100">{{ node.exit_ip || '-' }}</div>
                  <div class="text-xs text-gray-500 dark:text-gray-400">
                    {{ node.exit_country_code || '-' }} · {{ node.exit_timezone || '-' }}
                  </div>
                </td>
                <td class="px-4 py-2.5 text-xs text-gray-700 dark:text-gray-300">
                  {{ formatBytes(node.used_bytes_month) }} / {{ node.max_bytes_month > 0 ? formatBytes(node.max_bytes_month) : '不限' }}
                </td>
                <td class="px-4 py-2.5">
                  <div class="flex items-center gap-1.5">
                    <span class="rounded-full px-2 py-0.5 text-xs font-medium" :class="statusBadgeClass(node.status)">
                      {{ node.status === 'active' ? '在线' : node.status }}
                    </span>
                    <span v-if="node.meta?.agent_version" class="font-mono text-[11px] text-gray-600 dark:text-gray-300">
                      {{ node.meta.agent_version }}
                    </span>
                    <span
                      v-if="primaryRelease && node.status === 'active' && node.meta?.agent_sha256"
                      class="rounded px-1 py-0.5 text-[10px]"
                      :class="node.meta.agent_sha256 === primaryRelease.sha256
                        ? 'bg-emerald-50 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300'
                        : 'bg-amber-50 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300'"
                    >
                      {{ node.meta.agent_sha256 === primaryRelease.sha256 ? '已最新' : '待同步' }}
                    </span>
                  </div>
                  <div v-if="node.last_heartbeat_at" class="mt-0.5 text-[11px] text-gray-400">
                    心跳: {{ formatTime(node.last_heartbeat_at) }}
                  </div>
                </td>
                <td class="px-4 py-2.5 text-right">
                  <button
                    type="button"
                    class="btn btn-secondary btn-xs"
                    @click="openEditNodeModal(node)"
                  >
                    编辑
                  </button>
                </td>
              </tr>
              <tr v-if="!loading && filteredNodes.length === 0">
                <td colspan="7" class="px-4 py-8 text-center text-sm text-gray-400">暂无匹配节点</td>
              </tr>
            </tbody>
          </table>
        </div>

        <!-- Zones & Links Tab -->
        <div v-else class="grid grid-cols-1 gap-4 p-4 lg:grid-cols-2">
          <div class="rounded-lg border border-gray-200 p-4 dark:border-dark-700">
            <div class="mb-3 flex items-center justify-between">
              <div class="text-sm font-semibold text-gray-900 dark:text-white">逻辑分区（Zones）</div>
              <button type="button" class="btn btn-secondary btn-xs" @click="showZoneModal = true">+ 新增分区</button>
            </div>
            <div class="space-y-2">
              <div
                v-for="z in zones"
                :key="z.id"
                class="flex items-center justify-between rounded-lg bg-gray-50 px-3 py-2 text-xs dark:bg-dark-900/50"
              >
                <div>
                  <span class="font-medium text-gray-900 dark:text-white">{{ z.display_name }}</span>
                  <span class="ml-2 font-mono text-gray-400">{{ z.slug }}</span>
                </div>
                <span class="rounded bg-gray-200/70 px-1.5 py-0.5 text-[11px] text-gray-600 dark:bg-dark-700 dark:text-gray-300">
                  {{ zonePolicyLabel(z.default_mgmt_policy) }}
                </span>
              </div>
            </div>
          </div>

          <div class="rounded-lg border border-gray-200 p-4 dark:border-dark-700">
            <div class="mb-3 flex items-center justify-between">
              <div class="text-sm font-semibold text-gray-900 dark:text-white">转发链路（Links）</div>
              <button type="button" class="btn btn-secondary btn-xs" @click="openCreateLinkModal">+ 新增链路</button>
            </div>
            <div class="max-h-80 space-y-1.5 overflow-y-auto">
              <div
                v-for="l in links"
                :key="l.id"
                class="flex items-center justify-between rounded-lg bg-gray-50 px-3 py-2 text-xs dark:bg-dark-900/50"
              >
                <span class="text-gray-800 dark:text-gray-200">
                  {{ nodeName(l.src_node_id) }} {{ l.direction === 'bidirectional' ? '↔' : '→' }} {{ nodeName(l.dst_node_id) }}
                </span>
                <div class="flex items-center gap-2">
                  <span class="font-mono text-gray-500">{{ l.link_class }} · {{ l.rtt_ms }}ms · w={{ l.weight }}</span>
                  <button
                    type="button"
                    class="text-red-500 hover:text-red-700"
                    @click="handleDeleteLink(l)"
                  >
                    删除
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Create / Edit Node Modal (Simplified MeshHarbor Model) -->
    <BaseDialog
      :show="showNodeModal"
      :title="editingNodeId ? '编辑服务器节点' : '新增服务器节点'"
      width="wide"
      @close="showNodeModal = false"
    >
      <div class="space-y-4">
        <div class="grid grid-cols-1 gap-3 sm:grid-cols-3">
          <div>
            <label class="input-label">节点名称 *</label>
            <input v-model="nodeForm.name" type="text" class="input" placeholder="如 houston-vm104" />
          </div>
          <div>
            <label class="input-label">所属逻辑分区 (Zone) *</label>
            <select v-model.number="nodeForm.zone_id" class="input">
              <option v-for="z in zones" :key="z.id" :value="z.id">
                {{ z.display_name }} ({{ z.slug }})
              </option>
            </select>
          </div>
          <div>
            <label class="input-label">连接模式</label>
            <select v-model="nodeForm.connect_mode" class="input">
              <option value="direct">直连 (direct)</option>
              <option value="reverse_tunnel">反向隧道 (家宽 / NAT)</option>
            </select>
          </div>
        </div>

        <div class="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <div>
            <label class="input-label">对外入口地址（留空 = 仅网内中转 / 反向隧道）</label>
            <input
              v-model="nodeForm.public_addr"
              type="text"
              class="input font-mono text-xs"
              :disabled="nodeForm.connect_mode === 'reverse_tunnel'"
              placeholder="如 http://1.2.3.4:19443（填写后本区客户端可直接连入）"
            />
          </div>
          <div>
            <label class="input-label">网内隧道地址 (Tunnel Addr)</label>
            <input
              v-model="nodeForm.tunnel_addr"
              type="text"
              class="input font-mono text-xs"
              :disabled="nodeForm.connect_mode === 'reverse_tunnel'"
              placeholder="如 10.x.x.x:19443 或公网 ip:19443"
            />
          </div>
        </div>

        <!-- Two Clear Roles: Relay + Landing -->
        <div class="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <label class="flex cursor-pointer items-center justify-between gap-3 rounded-lg border border-gray-200 bg-gray-50/70 p-3 dark:border-dark-600 dark:bg-dark-900/40">
            <div>
              <div class="text-sm font-medium text-gray-900 dark:text-white">转发节点</div>
              <div class="text-xs text-gray-500 dark:text-gray-400">
                承担本逻辑分区接入与网内流量转发
              </div>
            </div>
            <input
              v-model="nodeForm.is_relay"
              type="checkbox"
              :disabled="nodeForm.connect_mode === 'reverse_tunnel'"
              class="h-4 w-4 rounded border-gray-300 text-primary-600"
            />
          </label>
          <label class="flex cursor-pointer items-center justify-between gap-3 rounded-lg border border-gray-200 bg-gray-50/70 p-3 dark:border-dark-600 dark:bg-dark-900/40">
            <div>
              <div class="text-sm font-medium text-gray-900 dark:text-white">落地节点（出口 IP）</div>
              <div class="text-xs text-gray-500 dark:text-gray-400">
                ≤15 秒热生效，并出现在「代理管理」中
              </div>
            </div>
            <input
              v-model="nodeForm.is_landing"
              type="checkbox"
              class="h-4 w-4 rounded border-gray-300 text-primary-600"
            />
          </label>
        </div>

        <div class="grid grid-cols-1 gap-3 sm:grid-cols-4">
          <div>
            <label class="input-label">出口 IP</label>
            <input v-model="nodeForm.exit_ip" type="text" class="input font-mono" placeholder="68.77.201.x" />
          </div>
          <div>
            <label class="input-label">国家代码</label>
            <input v-model="nodeForm.exit_country_code" type="text" class="input" placeholder="US / JP / SG" />
          </div>
          <div>
            <label class="input-label">出口时区</label>
            <input v-model="nodeForm.exit_timezone" type="text" class="input" placeholder="America/Chicago" />
          </div>
          <div>
            <label class="input-label">出口 Locale</label>
            <input v-model="nodeForm.exit_locale" type="text" class="input" placeholder="en_US.UTF-8" />
          </div>
        </div>

        <div class="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <div>
            <label class="input-label">月流量上限 (GB, 0=不限)</label>
            <input v-model.number="nodeForm.max_gb_month" type="number" min="0" class="input" />
          </div>
          <div>
            <label class="input-label">状态</label>
            <select v-model="nodeForm.status" class="input">
              <option value="active">在线 (active)</option>
              <option value="draining">排空中 (draining)</option>
              <option value="offline">离线 (offline)</option>
              <option value="suspended">已停用 (suspended)</option>
            </select>
          </div>
        </div>

        <div>
          <label class="input-label">节点 Ed25519 公钥 (base64url)</label>
          <input v-model="nodeForm.pubkey_ed25519" type="text" class="input font-mono text-xs" placeholder="可选，用于节点心跳与自动更新签名认证" />
        </div>
      </div>
      <template #footer>
        <div class="flex justify-end gap-2">
          <button type="button" class="btn btn-secondary" @click="showNodeModal = false">取消</button>
          <button type="button" class="btn btn-primary" :disabled="submitting" @click="submitNode">
            {{ submitting ? '保存中...' : '保存节点' }}
          </button>
        </div>
      </template>
    </BaseDialog>

    <!-- Create Zone Modal -->
    <BaseDialog :show="showZoneModal" title="新增逻辑分区" width="normal" @close="showZoneModal = false">
      <div class="space-y-3">
        <div>
          <label class="input-label">标识 (slug) *</label>
          <input v-model="zoneForm.slug" type="text" class="input" placeholder="如 eu_west" />
        </div>
        <div>
          <label class="input-label">显示名称 *</label>
          <input v-model="zoneForm.display_name" type="text" class="input" placeholder="如 欧洲区" />
        </div>
      </div>
      <template #footer>
        <div class="flex justify-end gap-2">
          <button type="button" class="btn btn-secondary" @click="showZoneModal = false">取消</button>
          <button type="button" class="btn btn-primary" :disabled="submitting" @click="submitZone">创建分区</button>
        </div>
      </template>
    </BaseDialog>

    <!-- Create Link Modal -->
    <BaseDialog :show="showLinkModal" title="新增转发链路" width="normal" @close="showLinkModal = false">
      <div class="space-y-3">
        <div class="grid grid-cols-2 gap-3">
          <div>
            <label class="input-label">源节点 *</label>
            <select v-model.number="linkForm.src_node_id" class="input">
              <option v-for="n in nodes" :key="n.id" :value="n.id">{{ n.name }}</option>
            </select>
          </div>
          <div>
            <label class="input-label">目标节点 *</label>
            <select v-model.number="linkForm.dst_node_id" class="input">
              <option v-for="n in nodes" :key="n.id" :value="n.id">{{ n.name }}</option>
            </select>
          </div>
        </div>
        <div class="grid grid-cols-2 gap-3">
          <div>
            <label class="input-label">方向</label>
            <select v-model="linkForm.direction" class="input">
              <option value="bidirectional">双向 (bidirectional)</option>
              <option value="one_way">单向 (one_way)</option>
            </select>
          </div>
          <div>
            <label class="input-label">链路类型</label>
            <select v-model="linkForm.link_class" class="input">
              <option value="direct">直连 (direct)</option>
              <option value="iplc">专线 (iplc)</option>
              <option value="reverse_tunnel">反向隧道 (reverse_tunnel)</option>
            </select>
          </div>
        </div>
        <div class="grid grid-cols-2 gap-3">
          <div>
            <label class="input-label">RTT (ms)</label>
            <input v-model.number="linkForm.rtt_ms" type="number" min="1" class="input" />
          </div>
          <div>
            <label class="input-label">权重 (越小越优先)</label>
            <input v-model.number="linkForm.weight" type="number" min="1" class="input" />
          </div>
        </div>
      </div>
      <template #footer>
        <div class="flex justify-end gap-2">
          <button type="button" class="btn btn-secondary" @click="showLinkModal = false">取消</button>
          <button type="button" class="btn btn-primary" :disabled="submitting" @click="submitLink">创建链路</button>
        </div>
      </template>
    </BaseDialog>
  </AppLayout>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import AppLayout from '@/components/layout/AppLayout.vue'
import BaseDialog from '@/components/common/BaseDialog.vue'
import { useAppStore } from '@/stores/app'
import {
  berthNetworkAPI,
  type BerthEdgeNode,
  type BerthEdgeRelease,
  type BerthNetworkZone,
  type BerthServerLink,
} from '@/api/berthNetwork'

const appStore = useAppStore()

const loading = ref(false)
const submitting = ref(false)
const activeTab = ref<'nodes' | 'topology'>('nodes')
const nodeFilter = ref<'all' | 'relay' | 'landing'>('all')
const togglingNodeIds = reactive(new Set<number>())

const zones = ref<BerthNetworkZone[]>([])
const nodes = ref<BerthEdgeNode[]>([])
const links = ref<BerthServerLink[]>([])
const releases = ref<BerthEdgeRelease[]>([])

const hasRole = (node: BerthEdgeNode, role: string) => (node.roles || []).includes(role)
const isRelayNode = (node: BerthEdgeNode) =>
  node.connect_mode !== 'reverse_tunnel' &&
  (hasRole(node, 'transit') || hasRole(node, 'ingress_relay') || (node.public_addr || '').trim() !== '')

const activeNodesCount = computed(() => nodes.value.filter((n) => n.status === 'active').length)
const landingNodesCount = computed(() => nodes.value.filter((n) => hasRole(n, 'landing')).length)
const primaryRelease = computed(() =>
  releases.value.find((r) => r.os === 'linux' && r.arch === 'amd64') ?? releases.value[0] ?? null
)
const syncedAgentsCount = computed(() => {
  if (!primaryRelease.value) return 0
  return nodes.value.filter(
    (n) => n.status === 'active' && n.meta?.agent_sha256 === primaryRelease.value?.sha256
  ).length
})

const filteredNodes = computed(() => {
  if (nodeFilter.value === 'landing') {
    return nodes.value.filter((n) => hasRole(n, 'landing'))
  }
  if (nodeFilter.value === 'relay') {
    return nodes.value.filter((n) => isRelayNode(n))
  }
  return nodes.value
})

const findZone = (zoneId?: number | null) => zones.value.find((z) => z.id === zoneId)
const zoneName = (zoneId?: number | null) => {
  if (!zoneId) return '默认区'
  return findZone(zoneId)?.display_name || `Zone #${zoneId}`
}
const nodeName = (nodeId: number) => nodes.value.find((n) => n.id === nodeId)?.name || `Node #${nodeId}`

const zonePolicyLabel = (policy?: string) => {
  switch (policy) {
    case 'entry_required': return '经本区转发节点透传中央'
    case 'direct_allowed': return '中央管理区'
    default: return '直连中央'
  }
}

const nodeAccessSummary = (node: BerthEdgeNode) => {
  if (node.connect_mode === 'reverse_tunnel') {
    return '反向隧道接入'
  }
  if ((node.public_addr || '').trim() !== '') {
    return node.public_addr!
  }
  return node.tunnel_addr ? `网内中转 (${node.tunnel_addr})` : '网内中转'
}

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

const formatTime = (iso: string): string => {
  try {
    return new Date(iso).toLocaleTimeString()
  } catch {
    return iso
  }
}

const deriveRoles = (zoneId: number, connectMode: string, publicAddr: string, isRelay: boolean, isLanding: boolean): string[] => {
  const roles: string[] = []
  if (connectMode !== 'reverse_tunnel' && isRelay) {
    roles.push('transit')
    if (publicAddr.trim() !== '') {
      roles.push('ingress_relay')
      if (findZone(zoneId)?.default_mgmt_policy === 'entry_required') {
        roles.push('mgmt_entry')
      }
    }
  }
  if (isLanding) {
    roles.push('landing')
  }
  if (roles.length === 0) {
    roles.push('transit')
  }
  return roles
}

const loadAll = async () => {
  loading.value = true
  try {
    const [z, n, l, r] = await Promise.all([
      berthNetworkAPI.listZones(),
      berthNetworkAPI.listNodes(),
      berthNetworkAPI.listLinks(),
      berthNetworkAPI.listEdgeReleases().catch(() => []),
    ])
    zones.value = z
    nodes.value = n
    links.value = l
    releases.value = r
  } catch (err: any) {
    appStore.showError(err?.message || '加载节点数据失败')
  } finally {
    loading.value = false
  }
}

const toggleLandingRole = async (node: BerthEdgeNode) => {
  const currentlyLanding = hasRole(node, 'landing')
  const zoneId = node.zone_id || zones.value[0]?.id || 1
  const nextRoles = deriveRoles(zoneId, node.connect_mode || 'direct', node.public_addr || '', isRelayNode(node), !currentlyLanding)
  togglingNodeIds.add(node.id)
  try {
    await berthNetworkAPI.updateNode(node.id, {
      name: node.name,
      zone_id: zoneId,
      roles: nextRoles,
      public_addr: node.public_addr || '',
      tunnel_addr: node.tunnel_addr || '',
      mgmt_entry_addr: node.mgmt_entry_addr || '',
      connect_mode: node.connect_mode || 'direct',
      provider_region: node.provider_region || '',
      exit_ip: node.exit_ip || '',
      exit_country_code: node.exit_country_code || '',
      exit_timezone: node.exit_timezone || '',
      exit_locale: node.exit_locale || '',
      exit_asn_class: node.exit_asn_class || '',
      pubkey_ed25519: node.pubkey_ed25519 || '',
      status: node.status,
      max_bytes_month: node.max_bytes_month,
    })
    appStore.showSuccess(
      currentlyLanding
        ? `已关闭 ${node.name} 落地功能（节点将在 ≤15 秒内心跳热停用）`
        : `已开启 ${node.name} 落地功能（节点将在 ≤15 秒内心跳热启，现可在「代理管理」中选用）`
    )
    await loadAll()
  } catch (err: any) {
    appStore.showError(err?.message || '切换落地功能失败')
  } finally {
    togglingNodeIds.delete(node.id)
  }
}

// Create / Edit Node Modal
const showNodeModal = ref(false)
const editingNodeId = ref<number | null>(null)
const nodeForm = reactive({
  name: '',
  zone_id: 1,
  connect_mode: 'direct',
  public_addr: '',
  tunnel_addr: '',
  mgmt_entry_addr: '',
  is_relay: true,
  is_landing: true,
  exit_ip: '',
  exit_country_code: 'US',
  exit_timezone: 'America/Chicago',
  exit_locale: 'en_US.UTF-8',
  pubkey_ed25519: '',
  status: 'active',
  max_gb_month: 0,
})

const openCreateNodeModal = () => {
  editingNodeId.value = null
  nodeForm.name = ''
  nodeForm.zone_id = zones.value.find((z) => z.slug === 'overseas')?.id || zones.value[0]?.id || 1
  nodeForm.connect_mode = 'direct'
  nodeForm.public_addr = ''
  nodeForm.tunnel_addr = ''
  nodeForm.mgmt_entry_addr = ''
  nodeForm.is_relay = true
  nodeForm.is_landing = true
  nodeForm.exit_ip = ''
  nodeForm.exit_country_code = 'US'
  nodeForm.exit_timezone = 'America/Chicago'
  nodeForm.exit_locale = 'en_US.UTF-8'
  nodeForm.pubkey_ed25519 = ''
  nodeForm.status = 'active'
  nodeForm.max_gb_month = 0
  showNodeModal.value = true
}

const openEditNodeModal = (node: BerthEdgeNode) => {
  editingNodeId.value = node.id
  nodeForm.name = node.name
  nodeForm.zone_id = node.zone_id || zones.value[0]?.id || 1
  nodeForm.connect_mode = node.connect_mode || 'direct'
  nodeForm.public_addr = node.public_addr || ''
  nodeForm.tunnel_addr = node.tunnel_addr || ''
  nodeForm.mgmt_entry_addr = node.mgmt_entry_addr || ''
  nodeForm.is_relay = isRelayNode(node)
  nodeForm.is_landing = hasRole(node, 'landing')
  nodeForm.exit_ip = node.exit_ip || ''
  nodeForm.exit_country_code = node.exit_country_code || ''
  nodeForm.exit_timezone = node.exit_timezone || ''
  nodeForm.exit_locale = node.exit_locale || ''
  nodeForm.pubkey_ed25519 = node.pubkey_ed25519 || ''
  nodeForm.status = node.status || 'active'
  nodeForm.max_gb_month = node.max_bytes_month > 0 ? Math.round(node.max_bytes_month / (1024 * 1024 * 1024)) : 0
  showNodeModal.value = true
}

const submitNode = async () => {
  if (!nodeForm.name.trim()) {
    appStore.showError('请填写节点名称')
    return
  }
  const publicAddr = nodeForm.connect_mode === 'reverse_tunnel' ? '' : nodeForm.public_addr.trim()
  const tunnelAddr = nodeForm.connect_mode === 'reverse_tunnel' ? '' : nodeForm.tunnel_addr.trim()
  const roles = deriveRoles(nodeForm.zone_id, nodeForm.connect_mode, publicAddr, nodeForm.is_relay, nodeForm.is_landing)
  submitting.value = true
  try {
    const payload = {
      name: nodeForm.name.trim(),
      zone_id: nodeForm.zone_id,
      roles,
      public_addr: publicAddr,
      tunnel_addr: tunnelAddr,
      mgmt_entry_addr: nodeForm.mgmt_entry_addr.trim(),
      connect_mode: nodeForm.connect_mode,
      exit_ip: nodeForm.exit_ip.trim(),
      exit_country_code: nodeForm.exit_country_code.trim().toUpperCase(),
      exit_timezone: nodeForm.exit_timezone.trim(),
      exit_locale: nodeForm.exit_locale.trim(),
      pubkey_ed25519: nodeForm.pubkey_ed25519.trim(),
      status: nodeForm.status,
      max_bytes_month: nodeForm.max_gb_month > 0 ? Math.round(nodeForm.max_gb_month * 1024 * 1024 * 1024) : 0,
    }
    if (editingNodeId.value) {
      await berthNetworkAPI.updateNode(editingNodeId.value, payload)
      appStore.showSuccess('节点已更新（配置将在 ≤15 秒内心跳热同步）')
    } else {
      await berthNetworkAPI.createNode(payload)
      appStore.showSuccess('服务器节点已创建')
    }
    showNodeModal.value = false
    await loadAll()
  } catch (err: any) {
    appStore.showError(err?.message || '保存节点失败')
  } finally {
    submitting.value = false
  }
}

// Zone & Link Modals
const showZoneModal = ref(false)
const zoneForm = reactive({ slug: '', display_name: '' })
const submitZone = async () => {
  if (!zoneForm.slug.trim() || !zoneForm.display_name.trim()) {
    appStore.showError('请填写分区标识和名称')
    return
  }
  submitting.value = true
  try {
    await berthNetworkAPI.createZone({ slug: zoneForm.slug.trim(), display_name: zoneForm.display_name.trim() })
    appStore.showSuccess('分区已创建')
    showZoneModal.value = false
    zoneForm.slug = ''
    zoneForm.display_name = ''
    await loadAll()
  } catch (err: any) {
    appStore.showError(err?.message || '创建分区失败')
  } finally {
    submitting.value = false
  }
}

const showLinkModal = ref(false)
const linkForm = reactive({
  src_node_id: 0,
  dst_node_id: 0,
  direction: 'bidirectional',
  link_class: 'direct',
  rtt_ms: 50,
  weight: 10,
})
const openCreateLinkModal = () => {
  linkForm.src_node_id = nodes.value[0]?.id || 0
  linkForm.dst_node_id = nodes.value[1]?.id || nodes.value[0]?.id || 0
  showLinkModal.value = true
}
const submitLink = async () => {
  if (!linkForm.src_node_id || !linkForm.dst_node_id || linkForm.src_node_id === linkForm.dst_node_id) {
    appStore.showError('请选择两个不同的节点')
    return
  }
  submitting.value = true
  try {
    await berthNetworkAPI.createLink({ ...linkForm, enabled: true })
    appStore.showSuccess('链路已创建')
    showLinkModal.value = false
    await loadAll()
  } catch (err: any) {
    appStore.showError(err?.message || '创建链路失败')
  } finally {
    submitting.value = false
  }
}
const handleDeleteLink = async (link: BerthServerLink) => {
  try {
    await berthNetworkAPI.deleteLink(link.id)
    appStore.showSuccess('链路已删除')
    await loadAll()
  } catch (err: any) {
    appStore.showError(err?.message || '删除链路失败')
  }
}

onMounted(loadAll)
</script>
