<template>
  <AppLayout>
    <div class="marketplace space-y-5">
      <div v-if="isDemo" role="status" class="flex flex-wrap items-center justify-between gap-3 rounded-lg bg-amber-50 px-4 py-3 text-sm text-amber-900 dark:bg-amber-950/30 dark:text-amber-200">
        <span>演示预览 · 商品、订单和收入均为模拟数据，不会扣款；操作仅供查看。</span>
        <a href="/marketplace" class="font-medium underline">返回真实市场</a>
      </div>
      <div class="text-sm leading-6 text-gray-500 dark:text-gray-400">
        <p v-if="commission">平台抽成：租金 {{ commission.rent_commission_bps / 100 }}%，API 调用收入 {{ commission.usage_commission_bps / 100 }}%；其余收入归出租方。租金抽成以订单创建时的比例为准。</p>
        <p v-if="settingsError" role="alert">{{ settingsError }} <button class="underline" @click="loadSettings">重新加载抽成设置</button></p>
      </div>

      <nav class="flex flex-wrap gap-1 border-b border-gray-200 pb-2 dark:border-dark-700" aria-label="租赁市场栏目">
        <button v-for="item in tabs" :key="item.id" type="button" class="rounded-lg px-4 py-2 text-sm font-medium transition-colors" :class="tab === item.id ? 'bg-primary-100 text-primary-800 dark:bg-primary-900/40 dark:text-primary-200' : 'text-gray-500 hover:bg-gray-100 dark:text-gray-400 dark:hover:bg-dark-800'" :aria-current="tab === item.id ? 'page' : undefined" @click="selectTab(item.id)">{{ item.label }}</button>
      </nav>

      <section v-if="tab === 'orders' || tab === 'mine' || tab === 'all'" aria-label="用量收入" class="space-y-2">
        <p class="text-sm text-gray-500">{{ auth.isAdmin ? '全平台' : '我的出租服务' }} API 用量收入（不含租金）；待收款在租用方补足余额后入账。</p>
        <p v-if="revenueLoading" class="text-sm text-gray-500">正在加载用量收入…</p>
        <p v-else-if="revenueError" role="alert" class="text-sm text-red-600">{{ revenueError }} <button class="underline" @click="loadRevenue">重试收入统计</button></p>
        <dl v-else-if="revenue" class="grid grid-cols-2 gap-3 lg:grid-cols-4">
          <div v-for="item in revenueCards" :key="item.label" class="card p-4"><dt class="text-xs text-gray-500">{{ item.label }}</dt><dd class="mt-2 text-lg font-semibold tabular-nums">{{ usageMoney(item.amount) }}</dd></div>
        </dl>
      </section>

      <form v-if="auth.isAdmin && tab === 'all'" id="market-commission" class="rounded-xl border border-gray-200 p-4 dark:border-dark-700" @submit.prevent="saveSettings">
        <h2 class="font-semibold">平台抽成设置</h2>
        <p class="mt-1 text-sm text-gray-500">租金与 API 调用分别计提，默认均为 0%。租金修改仅影响新订单。</p>
        <div class="my-3 grid gap-3 sm:grid-cols-2">
          <label class="text-sm">租金抽成（%）<input v-model="commissionDraft.rent" data-testid="rent-commission" class="input mt-1" inputmode="decimal" required :disabled="!commission || savingSettings" /></label>
          <label class="text-sm">API 调用抽成（%）<input v-model="commissionDraft.usage" data-testid="usage-commission" class="input mt-1" inputmode="decimal" required :disabled="!commission || savingSettings" /></label>
        </div>
        <p v-if="saveSettingsError" role="alert" class="mb-2 text-sm text-red-600">{{ saveSettingsError }}</p>
        <button class="btn btn-primary" :disabled="!commission || savingSettings">{{ savingSettings ? '正在保存…' : '保存抽成设置' }}</button>
      </form>

      <div class="flex flex-wrap items-center gap-3">
        <div class="ml-auto flex gap-2 order-last">
          <a v-if="!isDemo" href="/marketplace?demo=1" class="btn btn-secondary">查看演示数据</a>
          <button type="button" class="btn btn-secondary" :disabled="loading" @click="load">刷新</button>
          <button type="button" class="btn btn-primary" @click="openPublish">发布租赁</button>
        </div>
        <label class="sr-only" for="market-search">搜索标题</label>
        <input id="market-search" v-model="search" class="input max-w-sm" placeholder="搜索标题" type="search" />
        <label class="sr-only" for="market-type">资源类型</label>
        <select id="market-type" v-model="typeFilter" class="input w-auto">
          <option value="">全部资源</option><option value="account">账号</option><option value="proxy">代理</option>
        </select>
        <span v-if="!loading && !loadError" class="text-sm text-gray-500">{{ filteredItems.length }} 项</span>
      </div>

      <div v-if="loadError" role="alert" class="rounded-xl border border-red-200 bg-red-50 p-4 text-sm text-red-700 dark:border-red-800 dark:bg-red-950/20 dark:text-red-300">
        {{ loadError }} <button class="ml-2 underline" type="button" @click="load">重试</button>
      </div>
      <div v-if="loading" role="status" class="card p-10 text-center text-gray-500">正在加载租赁信息…</div>
      <div v-else-if="!loadError && !filteredItems.length" class="card p-10 text-center">
        <h2 class="font-medium text-gray-900 dark:text-white">{{ tab === 'orders' ? '暂无租赁订单' : '暂无符合条件的租赁' }}</h2>
        <p class="mt-2 text-sm text-gray-500">{{ search || typeFilter ? '尝试调整搜索条件。' : tab === 'mine' ? '发布自己拥有的账号或代理，让其他用户租用。' : '刷新查看最新信息，或发布自己的资源。' }}</p>
      </div>

      <div v-else-if="!loadError && tab !== 'orders'" class="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        <article v-for="listing in visibleListings" :key="listing.id" class="card flex flex-col overflow-hidden" :data-listing="listing.id">
          <div class="flex flex-1 flex-col gap-4 p-5">
            <div class="flex items-center justify-between gap-3 text-xs">
              <span class="rounded-md bg-gray-100 px-2 py-1 font-medium text-gray-600 dark:bg-dark-700 dark:text-gray-300">{{ resourceName(listing.resource_type) }} · #{{ listing.id }}</span>
              <span :class="listing.status === 'active' ? 'text-emerald-600 dark:text-emerald-400' : 'text-gray-500'">{{ listing.status === 'active' ? '已上架' : '已下架' }}</span>
            </div>
            <div><h2 class="break-words text-lg font-semibold text-gray-900 dark:text-white">{{ listing.title }}</h2><p class="mt-2 whitespace-pre-line break-words text-sm leading-6 text-gray-500 dark:text-gray-400">{{ listing.description || '暂无补充说明' }}</p></div>
            <p v-if="listing.resource_type === 'account'" class="text-xs text-gray-500">API 调用另计 · {{ listing.usage_rate_multiplier ?? 1 }} 倍</p>
            <div class="mt-auto flex items-end justify-between gap-3 border-t border-gray-100 pt-4 dark:border-dark-700">
              <div><strong class="text-2xl font-semibold tabular-nums text-gray-900 dark:text-white">{{ money(listing.price_cents) }}</strong><span class="ml-1 text-xs text-gray-500">/ {{ listing.duration_hours }} 小时</span></div>
              <span class="text-right text-xs leading-5 text-gray-500">同时在租<br /><strong class="tabular-nums text-gray-700 dark:text-gray-200">{{ listing.active_rentals }} / {{ listing.capacity }}</strong></span>
            </div>
          </div>
          <div class="flex gap-2 border-t border-gray-100 bg-gray-50 px-5 py-3 dark:border-dark-700 dark:bg-dark-800/50">
            <button v-if="listing.seller_id !== auth.user?.id && tab === 'market'" type="button" class="btn btn-primary flex-1" :disabled="listing.status !== 'active' || listing.active_rentals >= listing.capacity" @click="openCheckout(listing)">{{ listing.active_rentals >= listing.capacity ? '名额已满' : '租用此资源' }}</button>
            <span v-else-if="tab === 'market'" class="py-2 text-sm text-gray-500">你发布的资源</span>
            <button v-if="canManage(listing)" type="button" class="btn btn-secondary" :disabled="statusBusy === listing.id || (listing.admin_suspended && !auth.isAdmin)" @click="changeStatus(listing)">{{ listing.admin_suspended && !auth.isAdmin ? '管理员已下架' : listing.status === 'active' ? '下架' : '上架' }}</button>
          </div>
        </article>
      </div>

      <div v-else-if="!loadError && tab === 'orders'" class="space-y-4">
        <article v-for="order in visibleOrders" :key="order.id" class="card p-5" :data-order="order.id">
          <div class="flex flex-wrap justify-between gap-4">
            <div><p class="text-xs text-gray-500">订单 #{{ order.id }} · {{ order.buyer_id === auth.user?.id ? '我租用的' : order.seller_id === auth.user?.id ? '我出租的' : '平台订单' }} · {{ resourceName(order.resource_type) }}</p><h2 class="mt-1 text-lg font-semibold text-gray-900 dark:text-white">{{ order.title }}</h2></div>
            <div class="text-right"><strong class="font-semibold tabular-nums">{{ money(order.price_cents) }}</strong><p class="mt-1 text-xs text-gray-500">{{ orderStatus(order.status) }}</p></div>
          </div>
          <dl class="mt-4 grid gap-3 text-sm sm:grid-cols-2 lg:grid-cols-4">
            <div><dt class="text-gray-500">开始时间</dt><dd class="mt-1">{{ date(order.starts_at) }}</dd></div>
            <div><dt class="text-gray-500">结束时间</dt><dd class="mt-1">{{ date(order.ends_at) }}</dd></div>
            <div><dt class="text-gray-500">出租方已结算净收入</dt><dd class="mt-1">{{ money(order.seller_earned_cents) }}</dd></div>
            <div><dt class="text-gray-500">平台已结算租金抽成</dt><dd class="mt-1">{{ money(order.platform_commission_cents) }}<span v-if="order.rent_commission_bps != null">（{{ order.rent_commission_bps / 100 }}%）</span></dd></div>
            <div><dt class="text-gray-500">已退租金</dt><dd class="mt-1">{{ money(order.refund_cents) }}</dd></div>
          </dl>
          <div v-if="order.status === 'active'" class="mt-4 flex flex-wrap items-center gap-3 border-t border-gray-100 pt-4 dark:border-dark-700">
            <template v-if="order.buyer_id === auth.user?.id">
              <template v-if="order.resource_type === 'account'">
                <button type="button" class="btn btn-secondary" @click="openService(order)">服务详情</button>
                <RouterLink v-if="!isDemo" to="/keys" class="btn btn-secondary">管理 API 密钥</RouterLink>
                <span v-if="!isDemo" class="text-xs text-gray-500">{{ order.group_id ? `创建密钥时选择租赁分组 #${order.group_id}。` : '在服务详情中查看租赁分组，再创建自己的 API 密钥。' }}</span>
              </template>
              <template v-else>
                <RouterLink v-if="!isDemo" to="/accounts" class="btn btn-secondary">为账号绑定代理</RouterLink>
                <button v-if="order.rental_proxy_id" type="button" class="btn btn-secondary" @click="openProxyBinding(order)">绑定到我的账号</button>
                <span class="text-xs text-gray-500">租赁代理仅用于站内账号绑定，不提供连接凭据。</span>
              </template>
            </template>
            <button type="button" class="btn btn-secondary text-red-600" @click="terminationTarget = order; actionError = ''">提前终止</button>
          </div>
        </article>
      </div>
    </div>

    <BaseDialog :show="publishOpen" title="发布租赁" :show-close-button="!publishing" :close-on-escape="!publishing" @close="publishOpen = false">
      <form id="market-publish" class="space-y-4" @submit.prevent="publish">
        <p class="text-sm leading-6 text-gray-500">选择自己拥有的资源，发布后直接上架。共享名额表示可同时租用的人数，不是账号请求并发数。</p>
        <div v-if="resourceError" role="alert" class="text-sm text-red-600">{{ resourceError }} <button type="button" class="underline" @click="loadResources">重新加载资源</button></div>
        <p v-if="resourcesLoading" role="status" class="text-sm text-gray-500">正在加载可出租资源…</p>
        <label class="block text-sm">资源类型<select v-model="draft.resource_type" class="input mt-1" @change="draft.resource_id = ''"><option value="account">账号</option><option value="proxy">代理</option></select></label>
        <label class="block text-sm">自己的资源<select v-model="draft.resource_id" class="input mt-1" required :disabled="resourcesLoading"><option value="" disabled>请选择资源</option><option v-for="resource in resourceOptions" :key="resource.id" :value="String(resource.id)">{{ resource.name }}{{ 'platform' in resource ? ` · ${resource.platform}` : '' }}</option></select></label>
        <p v-if="!resourcesLoading && !resourceError && !resourceOptions.length" class="text-sm text-gray-500">暂无可出租的{{ resourceName(draft.resource_type) }}。先在<RouterLink :to="draft.resource_type === 'account' ? '/accounts' : '/proxies'" class="text-primary-600 underline">资源管理</RouterLink>添加自己的资源。</p>
        <label class="block text-sm">租赁标题<input v-model="draft.title" class="input mt-1" required maxlength="120" placeholder="描述服务用途，勿填写密钥或密码" /></label>
        <label class="block text-sm">服务说明<textarea v-model="draft.description" class="input mt-1" rows="3" maxlength="2000" placeholder="说明用途与限制，勿填写账号凭据或代理地址" /></label>
        <div class="grid gap-3 sm:grid-cols-3">
          <label class="block text-sm">租期（小时）<input v-model.number="draft.duration_hours" type="number" class="input mt-1" min="1" step="1" required /></label>
          <label class="block text-sm">整期租金（美元）<input v-model="draft.price" type="text" inputmode="decimal" class="input mt-1" placeholder="10.00" required /></label>
          <label class="block text-sm">同时租用名额<input v-model.number="draft.capacity" type="number" class="input mt-1" min="1" step="1" required /></label>
        </div>
        <label v-if="draft.resource_type === 'account'" class="block text-sm">API 调用计费倍率<input v-model.number="draft.usage_rate_multiplier" data-testid="usage-multiplier" type="number" class="input mt-1" min="0.0001" max="1000" step="0.0001" required /><span class="mt-1 block text-xs text-gray-500">默认 1 倍，按模型调用价格乘以此倍率计费；调用收入扣除平台抽成后归出租方，租金另计。</span></label>
        <p v-if="actionError" role="alert" class="text-sm text-red-600">{{ actionError }}</p>
      </form>
      <template #footer><div class="flex justify-end gap-2"><button class="btn btn-secondary" :disabled="publishing" @click="publishOpen = false">取消</button><button type="submit" form="market-publish" class="btn btn-primary" :disabled="publishing || resourcesLoading || !!resourceError || !resourceOptions.length">{{ publishing ? '正在发布…' : '发布并上架' }}</button></div></template>
    </BaseDialog>

    <BaseDialog :show="!!checkoutTarget" title="确认租用" width="narrow" :show-close-button="!checkingOut" :close-on-escape="!checkingOut" @close="checkoutTarget = null">
      <div v-if="checkoutTarget" class="space-y-4 text-sm">
        <h2 class="font-semibold">{{ checkoutTarget.title }}</h2>
        <p>租期 {{ checkoutTarget.duration_hours }} 小时，本次从站内余额支付 <strong>{{ money(checkoutTarget.price_cents) }}</strong>。</p>
        <p class="leading-6 text-gray-500">API 调用费用另计。租赁服务不交付原始账号或代理凭据。提前终止会收回使用权限，剩余时间的租金按比例退还。</p>
		<p v-if="checkoutTarget.resource_type === 'account'" class="text-sm text-gray-500">支持普通 API 请求及 Responses WebSocket；暂不支持实时音视频、异步视频和批量图片任务。</p>
        <p v-if="actionError" role="alert" class="text-red-600">{{ actionError }}；可使用下方按钮重试，本次请求不会重复扣款。</p>
      </div>
      <template #footer><div class="flex justify-end gap-2"><button class="btn btn-secondary" :disabled="checkingOut" @click="checkoutTarget = null">取消</button><button class="btn btn-primary" data-testid="confirm-checkout" :disabled="checkingOut" @click="checkout">{{ checkingOut ? '正在租用…' : '确认支付并租用' }}</button></div></template>
    </BaseDialog>

    <BaseDialog :show="!!terminationTarget" title="提前终止租赁" width="narrow" :show-close-button="!terminating" :close-on-escape="!terminating" @close="terminationTarget = null">
      <div v-if="terminationTarget" class="space-y-3 text-sm"><p>终止「{{ terminationTarget.title }}」后，租用方将立即失去对应服务的使用权限。</p><p class="leading-6 text-gray-500">已使用时间的租金结算给出租方，剩余时间按比例退款；准确金额以服务器处理结果为准。API 调用费用不在本次退款范围内。</p><p v-if="actionError" role="alert" class="text-red-600">{{ actionError }}</p></div>
      <template #footer><div class="flex justify-end gap-2"><button class="btn btn-secondary" :disabled="terminating" @click="terminationTarget = null">保留租赁</button><button class="btn btn-danger" :disabled="terminating" @click="terminate">{{ terminating ? '正在终止…' : '确认终止' }}</button></div></template>
    </BaseDialog>

    <BaseDialog :show="!!proxyBinding" title="绑定租赁代理" :show-close-button="!bindingProxy" @close="proxyBinding = null">
      <p class="mb-3 text-sm text-gray-500">绑定会替换所选账号当前的代理。租期结束后该代理停止使用，需要重新选择可用代理。</p>
      <p v-if="resourceError" role="alert" class="text-sm text-red-600">{{ resourceError }}</p>
      <label class="block text-sm">我的账号<select v-model="bindingAccountID" class="input mt-2" :disabled="resourcesLoading || bindingProxy"><option value="">请选择账号</option><option v-for="account in resources.accounts" :key="account.id" :value="String(account.id)">{{ account.name }}</option></select></label>
      <p v-if="bindingError" role="alert" class="mt-3 text-sm text-red-600">{{ bindingError }}</p>
      <template #footer><button class="btn btn-primary" :disabled="!bindingAccountID || bindingProxy" @click="bindProxy">{{ bindingProxy ? '正在绑定…' : '确认绑定' }}</button></template>
    </BaseDialog>

    <BaseDialog :show="!!serviceTarget" title="租赁服务详情" @close="serviceTarget = null">
      <p v-if="serviceLoading" role="status" class="text-sm text-gray-500">正在加载服务信息…</p>
      <p v-else-if="serviceError" role="alert" class="text-sm text-red-600">{{ serviceError }} <button type="button" class="underline" @click="serviceTarget && openService(serviceTarget)">重试</button></p>
      <div v-else-if="service" class="space-y-4 text-sm">
        <p><strong>{{ service.group_name }}</strong> · 分组 #{{ service.group_id }} · {{ service.platform }}</p>
        <p v-if="!isDemo" class="text-gray-500">在<RouterLink to="/keys" class="text-primary-600 underline">密钥管理</RouterLink>创建自己的 API 密钥并选择此分组。以下信息不包含资源凭据。</p>
        <p v-else class="text-gray-500">以下为模拟服务状态、响应耗时与测试报告，不对应真实账号。</p>
        <ul class="divide-y divide-gray-100 dark:divide-dark-700"><li v-for="account in service.accounts" :key="account.id" class="flex flex-wrap justify-between gap-2 py-3"><span>{{ account.name }} · {{ account.status }}</span><span class="text-gray-500">首字 {{ latency(account.first_token_ms) }} · 总耗时 {{ latency(account.duration_ms) }}</span></li></ul>
        <p v-if="!service.accounts.length" class="text-gray-500">暂无可展示的服务状态。</p>
        <h3 class="font-medium">最近测试记录</h3>
        <ul class="space-y-2"><li v-for="(report,index) in service.test_reports" :key="index" class="flex flex-wrap justify-between gap-2 text-xs"><span>{{ report.kind }} · {{ report.status }}</span><span>{{ latency(report.latency_ms) }} · {{ date(report.created_at) }}</span></li></ul>
        <p v-if="!service.test_reports.length" class="text-gray-500">暂无已保存的测试记录。</p>
      </div>
    </BaseDialog>
  </AppLayout>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { RouterLink } from 'vue-router'
import AppLayout from '@/components/layout/AppLayout.vue'
import BaseDialog from '@/components/common/BaseDialog.vue'
import { adminAPI } from '@/api/admin'
import { useAuthStore } from '@/stores/auth'
import { useAppStore } from '@/stores/app'
import { extractApiErrorMessage } from '@/utils/apiError'
import { marketplaceAPI as liveMarketplaceAPI, priceToCents, percentToBps } from './api'
import { createMarketplaceDemo } from './demo'
import type { UsageRevenue, CommissionSettings, Listing, ListingScope, OwnedResources, RentalOrder, RentalService, ResourceType } from './types'

type Tab = ListingScope | 'orders'
const auth = useAuthStore()
const isDemo = new URLSearchParams(window.location.search).get('demo') === '1'
const marketplaceAPI = isDemo ? createMarketplaceDemo(auth.user?.id ?? 1) : liveMarketplaceAPI
const app = useAppStore()
const revenue = ref<UsageRevenue | null>(null)
const revenueLoading = ref(false)
const revenueError = ref('')
const usageMoney = (value: number) => `$${value.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 8 })}`
const revenueCards = computed(() => revenue.value ? [
  { label: '用量收入总额', amount: revenue.value.gross_amount },
  { label: '出租方已到账净收入', amount: revenue.value.available_income },
  { label: '出租方待收款', amount: revenue.value.pending_income },
  { label: '平台用量应计抽成', amount: revenue.value.platform_amount },
] : [])
async function loadRevenue() {
  if (revenueLoading.value) return
  revenueLoading.value = true
  revenueError.value = ''
  try { revenue.value = await marketplaceAPI.revenue() }
  catch (error) { revenueError.value = extractApiErrorMessage(error, '用量收入暂不可用') }
  finally { revenueLoading.value = false }
}
const commission = ref<CommissionSettings | null>(null)
const commissionDraft = reactive({ rent: '', usage: '' })
const settingsError = ref('')
const saveSettingsError = ref('')
const savingSettings = ref(false)
function applySettings(value: CommissionSettings) {
  commission.value = value
  commissionDraft.rent = String(value.rent_commission_bps / 100)
  commissionDraft.usage = String(value.usage_commission_bps / 100)
}
async function loadSettings() {
  settingsError.value = ''
  try { applySettings(await marketplaceAPI.settings()) }
  catch (error) { settingsError.value = extractApiErrorMessage(error, '抽成设置暂不可用') }
}
async function saveSettings() {
  if (!auth.isAdmin || !commission.value || savingSettings.value) return
  saveSettingsError.value = ''
  const rent = percentToBps(commissionDraft.rent.trim())
  const usage = percentToBps(commissionDraft.usage.trim())
  if (rent == null || usage == null) { saveSettingsError.value = '抽成须为 0 至 100，最多两位小数。'; return }
  savingSettings.value = true
  try {
    applySettings(await marketplaceAPI.updateSettings({ rent_commission_bps: rent, usage_commission_bps: usage }))
    app.showSuccess('抽成设置已保存')
  } catch (error) { saveSettingsError.value = extractApiErrorMessage(error, '保存失败，请重试') }
  finally { savingSettings.value = false }
}
const tab = ref<Tab>('market')
const tabs = computed<{ id: Tab; label: string }[]>(() => [
  { id: 'market', label: '浏览市场' }, { id: 'mine', label: '我的上架' },
  { id: 'orders', label: auth.isAdmin ? '租赁订单' : '我的租赁' },
  ...(auth.isAdmin ? [{ id: 'all' as const, label: '平台管理' }] : []),
])
const listings = ref<Listing[]>([])
const orders = ref<RentalOrder[]>([])
const search = ref('')
const typeFilter = ref<ResourceType | ''>('')
const loading = ref(false)
const loadError = ref('')
let loadSequence = 0
const matches = (item: Listing | RentalOrder) => (!typeFilter.value || item.resource_type === typeFilter.value) && item.title.toLowerCase().includes(search.value.trim().toLowerCase())
const visibleListings = computed(() => listings.value.filter(matches))
const visibleOrders = computed(() => orders.value.filter(matches))
const filteredItems = computed(() => tab.value === 'orders' ? visibleOrders.value : visibleListings.value)
const money = (cents: number | undefined) => cents == null ? '—' : `$${(cents / 100).toFixed(2)}`
const resourceName = (type: ResourceType) => type === 'account' ? '账号' : '代理'
const date = (value: string) => value && Number.isFinite(Date.parse(value)) ? new Date(value).toLocaleString() : '—'
const latency = (value: number | undefined) => value == null ? '暂无数据' : `${value} ms`
const orderStatus = (status: RentalOrder['status']) => ({ active: '租用中', completed: '已完成', terminated: '已终止' })[status] ?? status
const canManage = (listing: Listing) => listing.seller_id === auth.user?.id || auth.isAdmin

async function load() {
  if (tab.value !== 'market') void loadRevenue()
  const sequence = ++loadSequence
  loading.value = true
  loadError.value = ''
  try {
    if (tab.value === 'orders') {
      const result = await marketplaceAPI.orders()
      if (sequence === loadSequence) orders.value = result
    } else {
      const result = await marketplaceAPI.listings(tab.value)
      if (sequence === loadSequence) listings.value = result
    }
  } catch (error) {
    if (sequence === loadSequence) loadError.value = extractApiErrorMessage(error, '加载失败，请重试')
  } finally {
    if (sequence === loadSequence) loading.value = false
  }
}
function selectTab(next: Tab) {
  if (next === 'all' && !auth.isAdmin) return
  tab.value = next
  void load()
}

const resources = ref<OwnedResources>({ accounts: [], proxies: [] })
const resourcesLoading = ref(false)
const resourceError = ref('')
const publishOpen = ref(false)
const publishing = ref(false)
const actionError = ref('')
const draft = reactive({ resource_type: 'account' as ResourceType, resource_id: '', title: '', description: '', duration_hours: 24, price: '', capacity: 1, usage_rate_multiplier: 1 })
const resourceOptions = computed(() => draft.resource_type === 'account' ? resources.value.accounts : resources.value.proxies)
async function loadResources() {
  resourcesLoading.value = true
  resourceError.value = ''
  try { resources.value = await marketplaceAPI.resources() }
  catch (error) { resourceError.value = extractApiErrorMessage(error, '无法加载自己的可出租资源') }
  finally { resourcesLoading.value = false }
}
function openPublish() {
  actionError.value = ''
  publishOpen.value = true
  void loadResources()
}
async function publish() {
  if (publishing.value) return
  actionError.value = ''
  const cents = priceToCents(draft.price.trim())
  if (draft.resource_type === 'account' && (!Number.isFinite(draft.usage_rate_multiplier) || draft.usage_rate_multiplier <= 0 || draft.usage_rate_multiplier > 1000)) {
    actionError.value = 'API 调用倍率须大于 0 且不超过 1000。'
    return
  }
  if (cents == null || !Number.isSafeInteger(draft.duration_hours) || draft.duration_hours < 1 || !Number.isSafeInteger(draft.capacity) || draft.capacity < 1 || !draft.title.trim() || !resourceOptions.value.some(item => item.id === Number(draft.resource_id))) {
    actionError.value = '请选择自己的资源，填写标题、正整数租期与名额；租金须大于零且最多两位小数。'
    return
  }
  publishing.value = true
  try {
    await marketplaceAPI.publish({ resource_type: draft.resource_type, resource_id: Number(draft.resource_id), title: draft.title.trim(), description: draft.description.trim(), duration_hours: draft.duration_hours, price_cents: cents, capacity: draft.capacity, ...(draft.resource_type === 'account' ? { usage_rate_multiplier: draft.usage_rate_multiplier } : {}) })
    publishOpen.value = false
    Object.assign(draft, { resource_id: '', title: '', description: '', price: '' })
    app.showSuccess('租赁已发布并上架')
    selectTab('mine')
  } catch (error) { actionError.value = extractApiErrorMessage(error, '发布失败，请重试') }
  finally { publishing.value = false }
}

const checkoutTarget = ref<Listing | null>(null)
const checkingOut = ref(false)
let checkoutAttempt: { listingId: number; key: string } | null = null
function openCheckout(listing: Listing) {
  if (!checkoutAttempt || checkoutAttempt.listingId !== listing.id) checkoutAttempt = { listingId: listing.id, key: crypto.randomUUID() }
  checkoutTarget.value = listing
  actionError.value = ''
}
async function checkout() {
  if (checkingOut.value || !checkoutTarget.value || !checkoutAttempt) return
  checkingOut.value = true
  actionError.value = ''
  try {
    await marketplaceAPI.checkout(checkoutTarget.value.id, checkoutAttempt.key)
    checkoutTarget.value = null
    checkoutAttempt = null
    app.showSuccess('租用成功，可在租赁订单中使用服务')
    selectTab('orders')
  } catch (error) { actionError.value = extractApiErrorMessage(error, '租用结果暂未确认') }
  finally { checkingOut.value = false }
}

const statusBusy = ref<number | null>(null)
async function changeStatus(listing: Listing) {
  if (statusBusy.value != null) return
  statusBusy.value = listing.id
  try {
    await marketplaceAPI.setStatus(listing.id, listing.status === 'active' ? 'inactive' : 'active')
    app.showSuccess(listing.status === 'active' ? '已下架，已有租赁继续按订单执行' : '已上架')
    await load()
  } catch (error) { app.showError(extractApiErrorMessage(error, '更新上架状态失败')) }
  finally { statusBusy.value = null }
}

const terminationTarget = ref<RentalOrder | null>(null)
const terminating = ref(false)
async function terminate() {
  if (!terminationTarget.value || terminating.value) return
  terminating.value = true
  actionError.value = ''
  try {
    const result = await marketplaceAPI.terminate(terminationTarget.value.id)
    terminationTarget.value = null
    app.showSuccess(`租赁已终止，退还租金 ${money(result.refund_cents)}`)
    await load()
  } catch (error) { actionError.value = extractApiErrorMessage(error, '终止失败，请重试') }
  finally { terminating.value = false }
}

const serviceTarget = ref<RentalOrder | null>(null)
const proxyBinding = ref<RentalOrder | null>(null)
const bindingAccountID = ref('')
const bindingProxy = ref(false)
const bindingError = ref('')
function openProxyBinding(order: RentalOrder) {
  proxyBinding.value = order
  bindingAccountID.value = ''
  bindingError.value = ''
  void loadResources()
}
async function bindProxy() {
  if (isDemo) { bindingError.value = '演示数据仅供预览，不会绑定真实账号。'; return }
  if (!proxyBinding.value?.rental_proxy_id || !bindingAccountID.value || bindingProxy.value) return
  bindingProxy.value = true
  bindingError.value = ''
  try {
    await adminAPI.accounts.update(Number(bindingAccountID.value), { proxy_id: proxyBinding.value.rental_proxy_id })
    proxyBinding.value = null
    app.showSuccess('租赁代理已绑定到账号')
  } catch (error) { bindingError.value = extractApiErrorMessage(error, '绑定失败，请重试') }
  finally { bindingProxy.value = false }
}
const service = ref<RentalService | null>(null)
const serviceLoading = ref(false)
const serviceError = ref('')
let serviceSequence = 0
async function openService(order: RentalOrder) {
  const sequence = ++serviceSequence
  serviceTarget.value = order
  service.value = null
  serviceLoading.value = true
  serviceError.value = ''
  try {
    const result = await marketplaceAPI.service(order.id)
    if (sequence === serviceSequence) service.value = result
  } catch (error) {
    if (sequence === serviceSequence) serviceError.value = extractApiErrorMessage(error, '服务详情暂不可用')
  } finally { if (sequence === serviceSequence) serviceLoading.value = false }
}

onMounted(() => { void load(); void loadSettings() })
</script>
