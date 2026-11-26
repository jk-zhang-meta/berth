<template>
  <section
    class="mb-6 rounded-2xl border border-gray-200/80 bg-white p-5 shadow-sm dark:border-dark-700 dark:bg-dark-800"
    data-test="berth-edge-ip-panel"
  >
    <!-- Header + KPI Strip -->
    <div class="flex flex-wrap items-center justify-between gap-3 border-b border-gray-100 pb-4 dark:border-dark-700">
      <div>
        <div class="flex items-center gap-2.5">
          <h2 class="text-base font-semibold text-gray-900 dark:text-white">
            {{ isAdmin ? 'Berth Edge 节点与落地授权管理' : 'Berth 落地节点申请与授权' }}
          </h2>
          <span
            v-if="isAdmin && pendingCount > 0"
            class="inline-flex items-center gap-1 rounded-full bg-amber-100 px-2.5 py-0.5 text-xs font-semibold text-amber-800 dark:bg-amber-900/40 dark:text-amber-300"
            data-test="pending-badge"
          >
            <span class="h-1.5 w-1.5 rounded-full bg-amber-500 animate-pulse" />
            {{ pendingCount }} 条待审批
          </span>
        </div>
        <p class="mt-0.5 text-xs text-gray-500 dark:text-gray-400">
          {{
            isAdmin
              ? '管理员统一维护中转/落地 Edge 节点；用户提交落地节点申请后，需在此审批通过并自动下发隔离代理。'
              : '落地节点由管理员统一提供与隔离托管；提交申请并获管理员批准后即可通过 bh CLI 或账号绑定使用。'
          }}
        </p>
      </div>

      <div class="flex flex-wrap items-center gap-2">
        <button
          v-if="isAdmin"
          type="button"
          class="btn btn-primary text-xs"
          data-test="open-direct-grant-btn"
          @click="openDirectGrantModal()"
        >
          直接发放授权
        </button>
        <button
          type="button"
          class="btn btn-secondary text-xs"
          :disabled="loading"
          @click="refreshAll"
        >
          {{ loading ? '刷新中...' : '刷新' }}
        </button>
      </div>
    </div>

    <!-- Error banner -->
    <div
      v-if="errorMessage"
      class="mt-3 rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-xs text-red-700 dark:border-red-900/50 dark:bg-red-950/40 dark:text-red-300"
    >
      {{ errorMessage }}
    </div>

    <!-- ======================= ADMIN VIEW ======================= -->
    <template v-if="isAdmin">
      <!-- KPI Cards -->
      <div class="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-4">
        <div class="rounded-xl border border-gray-100 bg-gray-50/70 px-3.5 py-2.5 dark:border-dark-700 dark:bg-dark-900/40">
          <div class="text-xs text-gray-500 dark:text-gray-400">Edge 节点在线</div>
          <div class="mt-1 text-lg font-semibold text-gray-900 dark:text-white">
            {{ activeNodesCount }} <span class="text-xs font-normal text-gray-400">/ {{ nodes.length }}</span>
          </div>
        </div>
        <div class="rounded-xl border border-gray-100 bg-gray-50/70 px-3.5 py-2.5 dark:border-dark-700 dark:bg-dark-900/40">
          <div class="text-xs text-gray-500 dark:text-gray-400">落地节点在线</div>
          <div class="mt-1 text-lg font-semibold text-emerald-600 dark:text-emerald-400">
            {{ activeLandingsCount }} <span class="text-xs font-normal text-gray-400">/ {{ landingNodes.length }}</span>
          </div>
        </div>
        <div class="rounded-xl border border-gray-100 bg-gray-50/70 px-3.5 py-2.5 dark:border-dark-700 dark:bg-dark-900/40">
          <div class="text-xs text-gray-500 dark:text-gray-400">待审批申请</div>
          <div
            class="mt-1 text-lg font-semibold"
            :class="pendingCount > 0 ? 'text-amber-600 dark:text-amber-400' : 'text-gray-900 dark:text-white'"
          >
            {{ pendingCount }}
          </div>
        </div>
        <div class="rounded-xl border border-gray-100 bg-gray-50/70 px-3.5 py-2.5 dark:border-dark-700 dark:bg-dark-900/40">
          <div class="text-xs text-gray-500 dark:text-gray-400">已生效落地授权</div>
          <div class="mt-1 text-lg font-semibold text-primary-600 dark:text-primary-400">
            {{ activeGrantsCount }}
          </div>
        </div>
      </div>

      <!-- Admin Sub-Tabs -->
      <div class="mt-4 flex flex-wrap gap-2 border-b border-gray-100 pb-3 dark:border-dark-700">
        <button
          type="button"
          class="rounded-lg px-3 py-1.5 text-xs font-medium transition"
          :class="
            adminTab === 'nodes'
              ? 'bg-primary-600 text-white shadow-sm'
              : 'bg-gray-100 text-gray-700 hover:bg-gray-200 dark:bg-dark-700 dark:text-gray-300 dark:hover:bg-dark-600'
          "
          data-test="tab-admin-nodes"
          @click="adminTab = 'nodes'"
        >
          Edge 与落地节点 ({{ nodes.length }})
        </button>
        <button
          type="button"
          class="inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-medium transition"
          :class="
            adminTab === 'grants'
              ? 'bg-primary-600 text-white shadow-sm'
              : 'bg-gray-100 text-gray-700 hover:bg-gray-200 dark:bg-dark-700 dark:text-gray-300 dark:hover:bg-dark-600'
          "
          data-test="tab-admin-grants"
          @click="adminTab = 'grants'"
        >
          <span>落地授权与审批 ({{ adminGrants.length }})</span>
          <span
            v-if="pendingCount > 0"
            class="rounded-full bg-amber-500 px-1.5 py-0.2 text-[10px] font-bold text-white"
          >
            {{ pendingCount }}
          </span>
        </button>
        <button
          type="button"
          class="rounded-lg px-3 py-1.5 text-xs font-medium transition"
          :class="
            adminTab === 'topology'
              ? 'bg-primary-600 text-white shadow-sm'
              : 'bg-gray-100 text-gray-700 hover:bg-gray-200 dark:bg-dark-700 dark:text-gray-300 dark:hover:bg-dark-600'
          "
          data-test="tab-admin-topology"
          @click="adminTab = 'topology'"
        >
          区域与拓扑链路 ({{ zones.length }} 区 / {{ links.length }} 链路)
        </button>
      </div>

      <!-- Admin Tab 1: Edge & Landing Nodes -->
      <div v-if="adminTab === 'nodes'" class="mt-4 overflow-x-auto">
        <table class="min-w-full divide-y divide-gray-100 text-left text-xs dark:divide-dark-700">
          <thead class="bg-gray-50/70 text-[11px] uppercase text-gray-500 dark:bg-dark-900/50 dark:text-gray-400">
            <tr>
              <th class="px-3 py-2">节点</th>
              <th class="px-3 py-2">角色</th>
              <th class="px-3 py-2">出口 IP / 地区时区</th>
              <th class="px-3 py-2">连接方式</th>
              <th class="px-3 py-2">状态</th>
              <th class="px-3 py-2">月流量</th>
              <th class="px-3 py-2 text-right">操作</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-gray-100 dark:divide-dark-700">
            <tr v-for="node in nodes" :key="node.id" class="hover:bg-gray-50/60 dark:hover:bg-dark-700/30">
              <td class="px-3 py-2.5 font-medium text-gray-900 dark:text-white">
                <div>{{ node.name }}</div>
                <div class="text-[11px] font-normal text-gray-400">#{{ node.id }}</div>
              </td>
              <td class="px-3 py-2.5">
                <div class="flex flex-wrap gap-1">
                  <span
                    v-for="role in node.roles"
                    :key="role"
                    class="rounded px-1.5 py-0.5 text-[10px] font-medium"
                    :class="roleBadgeClass(role)"
                  >
                    {{ role }}
                  </span>
                </div>
              </td>
              <td class="px-3 py-2.5">
                <div class="font-mono text-gray-800 dark:text-gray-200">{{ node.exit_ip || '-' }}</div>
                <div class="text-[11px] text-gray-500 dark:text-gray-400">
                  {{ node.exit_country_code || '-' }} · {{ node.exit_timezone || '-' }} · {{ node.exit_locale || '-' }}
                </div>
              </td>
              <td class="px-3 py-2.5 text-gray-600 dark:text-gray-300">
                <div>{{ node.connect_mode || 'direct' }}</div>
                <div v-if="node.public_addr" class="font-mono text-[10px] text-gray-400">{{ node.public_addr }}</div>
              </td>
              <td class="px-3 py-2.5">
                <span
                  class="inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[11px] font-medium"
                  :class="
                    node.status === 'active'
                      ? 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300'
                      : 'bg-gray-100 text-gray-600 dark:bg-dark-700 dark:text-gray-400'
                  "
                >
                  <span
                    class="h-1.5 w-1.5 rounded-full"
                    :class="node.status === 'active' ? 'bg-emerald-500' : 'bg-gray-400'"
                  />
                  {{ node.status }}
                </span>
              </td>
              <td class="px-3 py-2.5 font-mono text-[11px] text-gray-600 dark:text-gray-300">
                {{ formatBytes(node.used_bytes_month) }} / {{ node.max_bytes_month > 0 ? formatBytes(node.max_bytes_month) : '不限' }}
              </td>
              <td class="px-3 py-2.5 text-right">
                <button
                  v-if="node.roles.includes('landing') || node.roles.includes('compat')"
                  type="button"
                  class="rounded-md bg-primary-50 px-2.5 py-1 text-[11px] font-medium text-primary-700 hover:bg-primary-100 dark:bg-primary-900/30 dark:text-primary-300 dark:hover:bg-primary-900/50"
                  @click="openDirectGrantModal(node.id)"
                >
                  发放授权
                </button>
                <span v-else class="text-[11px] text-gray-400">中转节点</span>
              </td>
            </tr>
            <tr v-if="!loading && nodes.length === 0">
              <td colspan="7" class="px-3 py-6 text-center text-gray-400">暂无注册 Edge 节点</td>
            </tr>
          </tbody>
        </table>
      </div>

      <!-- Admin Tab 2: Grants & Approval Queue -->
      <div v-else-if="adminTab === 'grants'" class="mt-4 overflow-x-auto">
        <table class="min-w-full divide-y divide-gray-100 text-left text-xs dark:divide-dark-700">
          <thead class="bg-gray-50/70 text-[11px] uppercase text-gray-500 dark:bg-dark-900/50 dark:text-gray-400">
            <tr>
              <th class="px-3 py-2">ID / 状态</th>
              <th class="px-3 py-2">申请用户</th>
              <th class="px-3 py-2">目标落地节点</th>
              <th class="px-3 py-2">申请理由 / 审批备注</th>
              <th class="px-3 py-2">配额与用量</th>
              <th class="px-3 py-2 text-right">操作</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-gray-100 dark:divide-dark-700">
            <tr
              v-for="g in adminGrants"
              :key="g.id"
              :class="g.status === 'pending' ? 'bg-amber-50/40 dark:bg-amber-950/15' : 'hover:bg-gray-50/60 dark:hover:bg-dark-700/30'"
            >
              <td class="px-3 py-2.5">
                <div class="flex items-center gap-1.5">
                  <span class="font-mono text-gray-500">#{{ g.id }}</span>
                  <span class="rounded-full px-2 py-0.5 text-[11px] font-medium" :class="grantStatusClass(g.status)">
                    {{ grantStatusLabel(g.status) }}
                  </span>
                </div>
                <div v-if="g.proxy_id" class="mt-0.5 text-[10px] text-gray-400">Proxy #{{ g.proxy_id }}</div>
              </td>
              <td class="px-3 py-2.5">
                <div class="font-medium text-gray-900 dark:text-white">{{ g.grantee_email || `User #${g.grantee_user_id}` }}</div>
                <div class="text-[11px] text-gray-400">UID {{ g.grantee_user_id }}</div>
              </td>
              <td class="px-3 py-2.5">
                <div class="font-medium text-gray-900 dark:text-white">{{ g.node_name || `Node #${g.node_id}` }}</div>
                <div class="text-[11px] text-gray-500 dark:text-gray-400">
                  {{ g.exit_country_code }} · {{ g.exit_timezone }}
                  <span v-if="g.node_exit_ip" class="font-mono">({{ g.node_exit_ip }})</span>
                </div>
              </td>
              <td class="max-w-xs px-3 py-2.5 text-gray-600 dark:text-gray-300">
                <div v-if="g.request_reason" class="truncate" :title="g.request_reason">
                  <span class="text-gray-400">申请：</span>{{ g.request_reason }}
                </div>
                <div v-if="g.review_note" class="truncate text-amber-700 dark:text-amber-300" :title="g.review_note">
                  <span class="text-gray-400">审批：</span>{{ g.review_note }}
                </div>
                <div v-if="g.notes && !g.request_reason && !g.review_note" class="truncate text-gray-500" :title="g.notes">
                  {{ g.notes }}
                </div>
                <span v-if="!g.request_reason && !g.review_note && !g.notes" class="text-gray-400">-</span>
              </td>
              <td class="px-3 py-2.5 font-mono text-[11px] text-gray-600 dark:text-gray-300">
                <div>{{ formatBytes(g.used_bytes) }} / {{ g.max_bytes > 0 ? formatBytes(g.max_bytes) : '不限' }}</div>
                <div class="text-[10px] text-gray-400">
                  账号≤{{ g.max_accounts }} · 并发{{ g.max_concurrency || '不限' }} · RPM{{ g.max_rpm || '不限' }}
                </div>
              </td>
              <td class="px-3 py-2.5 text-right">
                <div class="inline-flex items-center gap-1.5">
                  <button
                    v-if="g.status === 'pending'"
                    type="button"
                    class="rounded-md bg-emerald-600 px-2.5 py-1 text-[11px] font-medium text-white hover:bg-emerald-700"
                    :data-test="`approve-grant-${g.id}`"
                    @click="openApproveModal(g)"
                  >
                    批准
                  </button>
                  <button
                    v-if="g.status === 'pending'"
                    type="button"
                    class="rounded-md bg-red-50 px-2.5 py-1 text-[11px] font-medium text-red-700 hover:bg-red-100 dark:bg-red-900/30 dark:text-red-300"
                    :data-test="`reject-grant-${g.id}`"
                    @click="openRejectModal(g)"
                  >
                    拒绝
                  </button>
                  <button
                    v-if="g.status === 'active'"
                    type="button"
                    class="rounded-md bg-red-50 px-2.5 py-1 text-[11px] font-medium text-red-700 hover:bg-red-100 dark:bg-red-900/30 dark:text-red-300"
                    @click="handleRevokeGrant(g)"
                  >
                    吊销
                  </button>
                </div>
              </td>
            </tr>
            <tr v-if="!loading && adminGrants.length === 0">
              <td colspan="6" class="px-3 py-6 text-center text-gray-400">暂无落地节点申请或授权记录</td>
            </tr>
          </tbody>
        </table>
      </div>

      <!-- Admin Tab 3: Zones & Links -->
      <div v-else class="mt-4 space-y-4">
        <div class="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <div
            v-for="z in zones"
            :key="z.id"
            class="rounded-xl border border-gray-100 bg-gray-50/70 p-3 dark:border-dark-700 dark:bg-dark-900/40"
          >
            <div class="font-medium text-gray-900 dark:text-white">{{ z.display_name }}</div>
            <div class="font-mono text-[11px] text-primary-600 dark:text-primary-400">{{ z.slug }}</div>
            <div class="mt-1 text-[11px] text-gray-500 dark:text-gray-400">{{ z.description || '-' }}</div>
          </div>
        </div>
        <div class="overflow-x-auto">
          <table class="min-w-full divide-y divide-gray-100 text-left text-xs dark:divide-dark-700">
            <thead class="bg-gray-50/70 text-[11px] uppercase text-gray-500 dark:bg-dark-900/50 dark:text-gray-400">
              <tr>
                <th class="px-3 py-2">源节点 → 目标节点</th>
                <th class="px-3 py-2">链路类型</th>
                <th class="px-3 py-2">RTT / 权重</th>
                <th class="px-3 py-2">状态</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-gray-100 dark:divide-dark-700">
              <tr v-for="l in links" :key="l.id">
                <td class="px-3 py-2 font-medium text-gray-800 dark:text-gray-200">
                  {{ nodeNameById(l.src_node_id) }} → {{ nodeNameById(l.dst_node_id) }}
                </td>
                <td class="px-3 py-2 font-mono text-[11px] text-gray-600 dark:text-gray-300">{{ l.link_class }}</td>
                <td class="px-3 py-2 font-mono text-[11px] text-gray-600 dark:text-gray-300">
                  {{ l.rtt_ms }}ms · w={{ l.weight }}
                </td>
                <td class="px-3 py-2">
                  <span
                    class="rounded-full px-2 py-0.5 text-[11px]"
                    :class="l.enabled ? 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300' : 'bg-gray-100 text-gray-500'"
                  >
                    {{ l.enabled ? '启用' : '停用' }}
                  </span>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </template>

    <!-- ======================= NORMAL USER VIEW ======================= -->
    <template v-else>
      <div class="mt-4 grid grid-cols-1 gap-5 lg:grid-cols-2">
        <!-- Available Admin-Provided Landing Nodes -->
        <div>
          <h3 class="mb-2.5 text-xs font-semibold uppercase tracking-wide text-gray-500 dark:text-gray-400">
            可申请的落地节点（{{ availableNodes.length }}）
          </h3>
          <div class="space-y-2">
            <div
              v-for="node in availableNodes"
              :key="node.id"
              class="flex items-center justify-between rounded-xl border border-gray-100 bg-gray-50/70 px-3.5 py-2.5 dark:border-dark-700 dark:bg-dark-900/40"
            >
              <div>
                <div class="flex items-center gap-2">
                  <span class="text-sm font-medium text-gray-900 dark:text-white">{{ node.name }}</span>
                  <span
                    class="rounded-full px-2 py-0.5 text-[10px] font-medium"
                    :class="
                      node.status === 'active'
                        ? 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300'
                        : 'bg-gray-200 text-gray-600 dark:bg-dark-700 dark:text-gray-400'
                    "
                  >
                    {{ node.status === 'active' ? '在线' : '离线' }}
                  </span>
                </div>
                <div class="mt-0.5 text-xs text-gray-500 dark:text-gray-400">
                  {{ node.exit_country_code }} · {{ node.exit_timezone }} · {{ node.exit_locale }}
                </div>
              </div>
              <div>
                <span
                  v-if="node.has_active_grant"
                  class="rounded-md bg-emerald-100 px-2.5 py-1 text-xs font-medium text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300"
                >
                  已获授权
                </span>
                <span
                  v-else-if="node.has_pending_request"
                  class="rounded-md bg-amber-100 px-2.5 py-1 text-xs font-medium text-amber-800 dark:bg-amber-900/30 dark:text-amber-300"
                >
                  待管理员审批
                </span>
                <button
                  v-else
                  type="button"
                  class="btn btn-primary px-3 py-1 text-xs"
                  :data-test="`apply-node-${node.id}`"
                  @click="openApplyModal(node)"
                >
                  申请使用
                </button>
              </div>
            </div>
            <div v-if="!loading && availableNodes.length === 0" class="rounded-xl border border-dashed border-gray-200 p-6 text-center text-xs text-gray-400 dark:border-dark-700">
              当前暂无可申请的落地节点
            </div>
          </div>
        </div>

        <!-- My Applications & Active Grants -->
        <div>
          <h3 class="mb-2.5 text-xs font-semibold uppercase tracking-wide text-gray-500 dark:text-gray-400">
            我的申请与落地授权（{{ userGrants.length }}）
          </h3>
          <div class="space-y-2">
            <div
              v-for="g in userGrants"
              :key="g.id"
              class="rounded-xl border border-gray-100 bg-gray-50/70 px-3.5 py-2.5 dark:border-dark-700 dark:bg-dark-900/40"
            >
              <div class="flex items-center justify-between gap-2">
                <div class="flex items-center gap-2">
                  <span class="text-sm font-medium text-gray-900 dark:text-white">{{ g.node_name || `Node #${g.node_id}` }}</span>
                  <span class="rounded-full px-2 py-0.5 text-[10px] font-medium" :class="grantStatusClass(g.status)">
                    {{ grantStatusLabel(g.status) }}
                  </span>
                </div>
                <button
                  v-if="g.status === 'pending'"
                  type="button"
                  class="text-xs font-medium text-red-600 hover:underline dark:text-red-400"
                  :data-test="`cancel-grant-${g.id}`"
                  @click="handleCancelApplication(g)"
                >
                  撤回申请
                </button>
              </div>
              <div class="mt-1 text-xs text-gray-500 dark:text-gray-400">
                {{ g.exit_country_code }} · {{ g.exit_timezone }} · 流量 {{ formatBytes(g.used_bytes) }} / {{ g.max_bytes > 0 ? formatBytes(g.max_bytes) : '不限' }} · 账号上限 {{ g.max_accounts }}
              </div>
              <div v-if="g.request_reason" class="mt-1 text-xs text-gray-600 dark:text-gray-300">
                申请说明：{{ g.request_reason }}
              </div>
              <div v-if="g.review_note" class="mt-1 text-xs text-amber-700 dark:text-amber-300">
                管理员回复：{{ g.review_note }}
              </div>
            </div>
            <div v-if="!loading && userGrants.length === 0" class="rounded-xl border border-dashed border-gray-200 p-6 text-center text-xs text-gray-400 dark:border-dark-700">
              尚未申请落地节点，请从左侧选择节点提交申请
            </div>
          </div>
        </div>
      </div>
    </template>

    <!-- ======================= MODALS ======================= -->
    <!-- User Apply Modal -->
    <div
      v-if="applyTarget"
      class="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4"
      @click.self="applyTarget = null"
    >
      <div class="w-full max-w-md rounded-2xl bg-white p-5 shadow-xl dark:bg-dark-800">
        <h3 class="text-base font-semibold text-gray-900 dark:text-white">
          申请落地节点：{{ applyTarget.name }}
        </h3>
        <p class="mt-1 text-xs text-gray-500 dark:text-gray-400">
          地区：{{ applyTarget.exit_country_code }} · {{ applyTarget.exit_timezone }}（提交后需管理员审批）
        </p>
        <div class="mt-4 space-y-3">
          <div>
            <label class="mb-1 block text-xs font-medium text-gray-700 dark:text-gray-300">申请理由 / 用途</label>
            <textarea
              v-model="applyForm.request_reason"
              rows="3"
              class="input w-full text-xs"
              placeholder="例如：日常 Codex / Claude 开发使用"
              data-test="apply-reason-input"
            />
          </div>
          <div class="grid grid-cols-2 gap-3">
            <div>
              <label class="mb-1 block text-xs font-medium text-gray-700 dark:text-gray-300">期望账号数</label>
              <input v-model.number="applyForm.max_accounts" type="number" min="1" max="50" class="input w-full text-xs" />
            </div>
            <div>
              <label class="mb-1 block text-xs font-medium text-gray-700 dark:text-gray-300">期望流量配额 (GB, 0=管理员定)</label>
              <input v-model.number="applyForm.max_gb" type="number" min="0" step="1" class="input w-full text-xs" />
            </div>
          </div>
        </div>
        <div class="mt-5 flex justify-end gap-2">
          <button type="button" class="btn btn-secondary text-xs" @click="applyTarget = null">取消</button>
          <button
            type="button"
            class="btn btn-primary text-xs"
            :disabled="submitting"
            data-test="submit-apply-btn"
            @click="submitApply"
          >
            {{ submitting ? '提交中...' : '提交申请' }}
          </button>
        </div>
      </div>
    </div>

    <!-- Admin Approve Modal -->
    <div
      v-if="approveTarget"
      class="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4"
      @click.self="approveTarget = null"
    >
      <div class="w-full max-w-md rounded-2xl bg-white p-5 shadow-xl dark:bg-dark-800">
        <h3 class="text-base font-semibold text-gray-900 dark:text-white">
          批准落地授权申请 #{{ approveTarget.id }}
        </h3>
        <p class="mt-1 text-xs text-gray-500 dark:text-gray-400">
          用户：{{ approveTarget.grantee_email || `UID ${approveTarget.grantee_user_id}` }} → 节点：{{ approveTarget.node_name }}
        </p>
        <p v-if="approveTarget.request_reason" class="mt-1 rounded-lg bg-gray-50 p-2 text-xs text-gray-600 dark:bg-dark-900/60 dark:text-gray-300">
          申请说明：{{ approveTarget.request_reason }}
        </p>
        <div class="mt-4 grid grid-cols-2 gap-3">
          <div>
            <label class="mb-1 block text-xs font-medium text-gray-700 dark:text-gray-300">流量上限 (GB, 0=不限)</label>
            <input v-model.number="approveForm.max_gb" type="number" min="0" step="1" class="input w-full text-xs" />
          </div>
          <div>
            <label class="mb-1 block text-xs font-medium text-gray-700 dark:text-gray-300">最大账号数</label>
            <input v-model.number="approveForm.max_accounts" type="number" min="1" class="input w-full text-xs" />
          </div>
          <div>
            <label class="mb-1 block text-xs font-medium text-gray-700 dark:text-gray-300">最大并发 (0=不限)</label>
            <input v-model.number="approveForm.max_concurrency" type="number" min="0" class="input w-full text-xs" />
          </div>
          <div>
            <label class="mb-1 block text-xs font-medium text-gray-700 dark:text-gray-300">最大 RPM (0=不限)</label>
            <input v-model.number="approveForm.max_rpm" type="number" min="0" class="input w-full text-xs" />
          </div>
          <div class="col-span-2">
            <label class="mb-1 block text-xs font-medium text-gray-700 dark:text-gray-300">审批备注（用户可见）</label>
            <input v-model="approveForm.review_note" type="text" class="input w-full text-xs" placeholder="例如：已批准使用" />
          </div>
        </div>
        <div class="mt-5 flex justify-end gap-2">
          <button type="button" class="btn btn-secondary text-xs" @click="approveTarget = null">取消</button>
          <button
            type="button"
            class="btn btn-primary text-xs"
            :disabled="submitting"
            data-test="confirm-approve-btn"
            @click="submitApprove"
          >
            {{ submitting ? '批准中...' : '确认批准并下发代理' }}
          </button>
        </div>
      </div>
    </div>

    <!-- Admin Reject Modal -->
    <div
      v-if="rejectTarget"
      class="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4"
      @click.self="rejectTarget = null"
    >
      <div class="w-full max-w-md rounded-2xl bg-white p-5 shadow-xl dark:bg-dark-800">
        <h3 class="text-base font-semibold text-gray-900 dark:text-white">
          拒绝落地授权申请 #{{ rejectTarget.id }}
        </h3>
        <div class="mt-3">
          <label class="mb-1 block text-xs font-medium text-gray-700 dark:text-gray-300">拒绝理由</label>
          <textarea
            v-model="rejectReason"
            rows="3"
            class="input w-full text-xs"
            placeholder="请填写拒绝原因（用户可见）"
          />
        </div>
        <div class="mt-5 flex justify-end gap-2">
          <button type="button" class="btn btn-secondary text-xs" @click="rejectTarget = null">取消</button>
          <button
            type="button"
            class="btn btn-danger text-xs"
            :disabled="submitting"
            data-test="confirm-reject-btn"
            @click="submitReject"
          >
            {{ submitting ? '处理中...' : '确认拒绝' }}
          </button>
        </div>
      </div>
    </div>

    <!-- Admin Direct Grant Modal -->
    <div
      v-if="showDirectGrantModal"
      class="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4"
      @click.self="showDirectGrantModal = false"
    >
      <div class="w-full max-w-md rounded-2xl bg-white p-5 shadow-xl dark:bg-dark-800">
        <h3 class="text-base font-semibold text-gray-900 dark:text-white">直接发放落地节点授权</h3>
        <div class="mt-4 space-y-3">
          <div>
            <label class="mb-1 block text-xs font-medium text-gray-700 dark:text-gray-300">落地节点</label>
            <select v-model.number="directForm.node_id" class="input w-full text-xs">
              <option v-for="n in landingNodes" :key="n.id" :value="n.id">
                {{ n.name }} ({{ n.exit_country_code }} · {{ n.exit_timezone }} · {{ n.status }})
              </option>
            </select>
          </div>
          <div>
            <label class="mb-1 block text-xs font-medium text-gray-700 dark:text-gray-300">目标用户</label>
            <select v-model.number="directForm.grantee_user_id" class="input w-full text-xs">
              <option v-for="u in users" :key="u.id" :value="u.id">
                {{ u.email }} (UID {{ u.id }}{{ u.role === 'admin' ? ', 管理员' : '' }})
              </option>
            </select>
          </div>
          <div class="grid grid-cols-2 gap-3">
            <div>
              <label class="mb-1 block text-xs font-medium text-gray-700 dark:text-gray-300">流量上限 (GB, 0=不限)</label>
              <input v-model.number="directForm.max_gb" type="number" min="0" step="1" class="input w-full text-xs" />
            </div>
            <div>
              <label class="mb-1 block text-xs font-medium text-gray-700 dark:text-gray-300">最大账号数</label>
              <input v-model.number="directForm.max_accounts" type="number" min="1" class="input w-full text-xs" />
            </div>
            <div>
              <label class="mb-1 block text-xs font-medium text-gray-700 dark:text-gray-300">最大并发 (0=不限)</label>
              <input v-model.number="directForm.max_concurrency" type="number" min="0" class="input w-full text-xs" />
            </div>
            <div>
              <label class="mb-1 block text-xs font-medium text-gray-700 dark:text-gray-300">最大 RPM (0=不限)</label>
              <input v-model.number="directForm.max_rpm" type="number" min="0" class="input w-full text-xs" />
            </div>
          </div>
          <div>
            <label class="mb-1 block text-xs font-medium text-gray-700 dark:text-gray-300">备注</label>
            <input v-model="directForm.notes" type="text" class="input w-full text-xs" placeholder="可选备注" />
          </div>
        </div>
        <div class="mt-5 flex justify-end gap-2">
          <button type="button" class="btn btn-secondary text-xs" @click="showDirectGrantModal = false">取消</button>
          <button
            type="button"
            class="btn btn-primary text-xs"
            :disabled="submitting"
            @click="submitDirectGrant"
          >
            {{ submitting ? '发放中...' : '确认发放' }}
          </button>
        </div>
      </div>
    </div>
  </section>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import {
  berthNetworkAPI,
  type BerthAvailableLandingNode,
  type BerthEdgeNode,
  type BerthLandingGrant,
  type BerthNetworkZone,
  type BerthServerLink,
  type BerthSimpleUser,
} from '@/api/berthNetwork'

const props = defineProps<{
  isAdmin: boolean
}>()

const emit = defineEmits<{
  (e: 'grant-changed'): void
}>()

const loading = ref(false)
const submitting = ref(false)
const errorMessage = ref('')
const adminTab = ref<'nodes' | 'grants' | 'topology'>('nodes')

// Admin state
const zones = ref<BerthNetworkZone[]>([])
const nodes = ref<BerthEdgeNode[]>([])
const links = ref<BerthServerLink[]>([])
const adminGrants = ref<BerthLandingGrant[]>([])
const users = ref<BerthSimpleUser[]>([])

// User state
const availableNodes = ref<BerthAvailableLandingNode[]>([])
const userGrants = ref<BerthLandingGrant[]>([])

// Modals
const applyTarget = ref<BerthAvailableLandingNode | null>(null)
const applyForm = reactive({ request_reason: '', max_accounts: 2, max_gb: 0 })

const approveTarget = ref<BerthLandingGrant | null>(null)
const approveForm = reactive({ max_gb: 0, max_accounts: 2, max_concurrency: 0, max_rpm: 0, review_note: '' })

const rejectTarget = ref<BerthLandingGrant | null>(null)
const rejectReason = ref('')

const showDirectGrantModal = ref(false)
const directForm = reactive({
  node_id: 0,
  grantee_user_id: 1,
  max_gb: 0,
  max_accounts: 5,
  max_concurrency: 0,
  max_rpm: 0,
  notes: '',
})

const landingNodes = computed(() =>
  nodes.value.filter((n) => n.roles.includes('landing') || n.roles.includes('compat'))
)
const activeNodesCount = computed(() => nodes.value.filter((n) => n.status === 'active').length)
const activeLandingsCount = computed(() => landingNodes.value.filter((n) => n.status === 'active').length)
const pendingCount = computed(() => adminGrants.value.filter((g) => g.status === 'pending').length)
const activeGrantsCount = computed(() => adminGrants.value.filter((g) => g.status === 'active').length)

function nodeNameById(id: number): string {
  return nodes.value.find((n) => n.id === id)?.name || `Node #${id}`
}

function formatBytes(bytes: number): string {
  if (!bytes || bytes <= 0) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let v = bytes
  let idx = 0
  while (v >= 1024 && idx < units.length - 1) {
    v /= 1024
    idx++
  }
  return `${v >= 100 || idx === 0 ? Math.round(v) : v.toFixed(1)} ${units[idx]}`
}

function roleBadgeClass(role: string): string {
  switch (role) {
    case 'landing':
      return 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300'
    case 'ingress_relay':
      return 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300'
    case 'transit':
      return 'bg-violet-100 text-violet-700 dark:bg-violet-900/30 dark:text-violet-300'
    case 'mgmt_entry':
      return 'bg-amber-100 text-amber-800 dark:bg-amber-900/30 dark:text-amber-300'
    default:
      return 'bg-gray-100 text-gray-700 dark:bg-dark-700 dark:text-gray-300'
  }
}

function grantStatusLabel(status: string): string {
  const map: Record<string, string> = {
    pending: '待审批',
    active: '已生效',
    paused: '已暂停',
    revoked: '已吊销',
    rejected: '已拒绝',
    expired: '已过期',
    quota_exhausted: '配额耗尽',
  }
  return map[status] || status
}

function grantStatusClass(status: string): string {
  switch (status) {
    case 'pending':
      return 'bg-amber-100 text-amber-800 dark:bg-amber-900/40 dark:text-amber-300'
    case 'active':
      return 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300'
    case 'rejected':
    case 'revoked':
      return 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300'
    default:
      return 'bg-gray-100 text-gray-600 dark:bg-dark-700 dark:text-gray-400'
  }
}

async function refreshAll() {
  loading.value = true
  errorMessage.value = ''
  try {
    if (props.isAdmin) {
      const [z, n, l, g, u] = await Promise.all([
        berthNetworkAPI.listZones(),
        berthNetworkAPI.listNodes(),
        berthNetworkAPI.listLinks(),
        berthNetworkAPI.listAdminGrants(),
        berthNetworkAPI.listUsers().catch(() => [] as BerthSimpleUser[]),
      ])
      zones.value = z
      nodes.value = n
      links.value = l
      adminGrants.value = g
      users.value = u
      if (g.some((item) => item.status === 'pending')) {
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
  } catch (err: unknown) {
    errorMessage.value = err instanceof Error ? err.message : '加载 Berth 网络与授权数据失败'
  } finally {
    loading.value = false
  }
}

function openApplyModal(node: BerthAvailableLandingNode) {
  applyTarget.value = node
  applyForm.request_reason = ''
  applyForm.max_accounts = 2
  applyForm.max_gb = 0
}

async function submitApply() {
  if (!applyTarget.value) return
  submitting.value = true
  errorMessage.value = ''
  try {
    await berthNetworkAPI.applyLandingGrant({
      node_id: applyTarget.value.id,
      request_reason: applyForm.request_reason.trim(),
      max_accounts: applyForm.max_accounts || 1,
      max_bytes: Math.max(0, Math.round((applyForm.max_gb || 0) * 1024 * 1024 * 1024)),
    })
    applyTarget.value = null
    await refreshAll()
  } catch (err: unknown) {
    errorMessage.value = err instanceof Error ? err.message : '提交申请失败'
  } finally {
    submitting.value = false
  }
}

async function handleCancelApplication(g: BerthLandingGrant) {
  submitting.value = true
  errorMessage.value = ''
  try {
    await berthNetworkAPI.cancelPendingApplication(g.id)
    await refreshAll()
  } catch (err: unknown) {
    errorMessage.value = err instanceof Error ? err.message : '撤回申请失败'
  } finally {
    submitting.value = false
  }
}

function openApproveModal(g: BerthLandingGrant) {
  approveTarget.value = g
  approveForm.max_gb = g.max_bytes > 0 ? Math.round(g.max_bytes / (1024 * 1024 * 1024)) : 0
  approveForm.max_accounts = g.max_accounts || 2
  approveForm.max_concurrency = g.max_concurrency || 0
  approveForm.max_rpm = g.max_rpm || 0
  approveForm.review_note = ''
}

async function submitApprove() {
  if (!approveTarget.value) return
  submitting.value = true
  errorMessage.value = ''
  try {
    await berthNetworkAPI.approveAdminGrant(approveTarget.value.id, {
      max_bytes: Math.max(0, Math.round((approveForm.max_gb || 0) * 1024 * 1024 * 1024)),
      max_accounts: approveForm.max_accounts || 1,
      max_concurrency: approveForm.max_concurrency || 0,
      max_rpm: approveForm.max_rpm || 0,
      review_note: approveForm.review_note.trim(),
    })
    approveTarget.value = null
    await refreshAll()
    emit('grant-changed')
  } catch (err: unknown) {
    errorMessage.value = err instanceof Error ? err.message : '审批失败'
  } finally {
    submitting.value = false
  }
}

function openRejectModal(g: BerthLandingGrant) {
  rejectTarget.value = g
  rejectReason.value = ''
}

async function submitReject() {
  if (!rejectTarget.value) return
  submitting.value = true
  errorMessage.value = ''
  try {
    await berthNetworkAPI.rejectAdminGrant(rejectTarget.value.id, rejectReason.value.trim())
    rejectTarget.value = null
    await refreshAll()
  } catch (err: unknown) {
    errorMessage.value = err instanceof Error ? err.message : '拒绝申请失败'
  } finally {
    submitting.value = false
  }
}

async function handleRevokeGrant(g: BerthLandingGrant) {
  submitting.value = true
  errorMessage.value = ''
  try {
    await berthNetworkAPI.revokeAdminGrant(g.id, 'revoked by admin')
    await refreshAll()
    emit('grant-changed')
  } catch (err: unknown) {
    errorMessage.value = err instanceof Error ? err.message : '吊销授权失败'
  } finally {
    submitting.value = false
  }
}

function openDirectGrantModal(preselectNodeId?: number) {
  directForm.node_id = preselectNodeId || landingNodes.value[0]?.id || 0
  directForm.grantee_user_id = users.value[0]?.id || 1
  directForm.max_gb = 0
  directForm.max_accounts = 5
  directForm.max_concurrency = 0
  directForm.max_rpm = 0
  directForm.notes = ''
  showDirectGrantModal.value = true
}

async function submitDirectGrant() {
  if (!directForm.node_id || !directForm.grantee_user_id) return
  submitting.value = true
  errorMessage.value = ''
  try {
    await berthNetworkAPI.createAdminGrant({
      node_id: directForm.node_id,
      grantee_user_id: directForm.grantee_user_id,
      max_bytes: Math.max(0, Math.round((directForm.max_gb || 0) * 1024 * 1024 * 1024)),
      max_accounts: directForm.max_accounts || 1,
      max_concurrency: directForm.max_concurrency || 0,
      max_rpm: directForm.max_rpm || 0,
      notes: directForm.notes.trim(),
    })
    showDirectGrantModal.value = false
    adminTab.value = 'grants'
    await refreshAll()
    emit('grant-changed')
  } catch (err: unknown) {
    errorMessage.value = err instanceof Error ? err.message : '发放授权失败'
  } finally {
    submitting.value = false
  }
}

onMounted(() => {
  void refreshAll()
})
</script>
