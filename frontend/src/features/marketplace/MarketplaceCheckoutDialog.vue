<template>
  <BaseDialog
    :show="show"
    :title="dialogTitle"
    width="narrow"
    :show-close-button="!submitting"
    :close-on-escape="!submitting"
    @close="handleClose"
  >
    <div class="space-y-4 text-sm">
      <!-- Shortfall breakdown -->
      <div v-if="listing && shortfall && phase === 'select'" class="space-y-4">
        <p class="text-gray-600 dark:text-gray-300">
          余额不足以支付「<strong>{{ listing.title }}</strong>」。补足差额后系统将自动为您开通租赁。
        </p>
        <dl class="rounded-xl bg-gray-50 p-4 space-y-2 dark:bg-dark-800">
          <div class="flex justify-between">
            <dt class="text-gray-500">租赁价格</dt>
            <dd class="font-medium tabular-nums">{{ formatCents(shortfall.price_cents) }}</dd>
          </div>
          <div class="flex justify-between">
            <dt class="text-gray-500">当前可用余额</dt>
            <dd class="font-medium tabular-nums">{{ formatCents(shortfall.available_balance_cents) }}</dd>
          </div>
          <div class="flex justify-between border-t border-gray-200 pt-2 dark:border-dark-700">
            <dt class="font-medium text-gray-900 dark:text-white">需补足差额</dt>
            <dd class="font-semibold text-primary-600 tabular-nums dark:text-primary-400" data-testid="shortfall-amount">
              {{ formatCents(shortfall.shortfall_cents) }}
            </dd>
          </div>
        </dl>

        <p v-if="loadingMethods" role="status" class="text-gray-500">正在加载支付方式…</p>
        <div v-else-if="checkoutInfo?.balance_disabled" role="alert" class="rounded-lg bg-amber-50 p-3 text-amber-800 dark:bg-amber-950/30 dark:text-amber-200">
          当前系统已禁用余额在线充值，请先联系管理员充值后再试。
        </div>
        <div v-else-if="!methodOptions.length" role="alert" class="rounded-lg bg-amber-50 p-3 text-amber-800 dark:bg-amber-950/30 dark:text-amber-200">
          暂无可用的在线支付通道。
        </div>
        <PaymentMethodSelector
          v-else
          :methods="methodOptions"
          :selected="selectedMethod"
          @select="selectedMethod = $event"
        />

        <p v-if="errorMessage" role="alert" class="text-red-600 dark:text-red-400">{{ errorMessage }}</p>
      </div>

      <!-- Stripe Inline Element -->
      <div v-else-if="phase === 'stripe' && paymentOrder && checkoutInfo?.stripe_publishable_key" class="space-y-3">
        <StripePaymentInline
          :order-id="paymentOrder.order_id"
          :amount="paymentOrder.amount"
          :pay-amount="paymentOrder.pay_amount"
          :currency="paymentOrder.currency"
          :client-secret="paymentOrder.client_secret || ''"
          :publishable-key="checkoutInfo.stripe_publishable_key"
          order-type="balance"
          @success="handleVerifyNow"
          @done="handleVerifyNow"
          @back="resetToSelect"
        />
      </div>

      <!-- Waiting / QR / Redirect / Polling State -->
      <div v-else-if="phase === 'waiting'" class="flex flex-col items-center space-y-4">
        <div v-if="paymentOrder?.qr_code" class="rounded-2xl bg-white p-4 shadow-sm dark:bg-dark-800">
          <canvas ref="qrCanvas" class="mx-auto"></canvas>
        </div>
        <div v-else class="flex flex-col items-center py-3">
          <div class="h-9 w-9 animate-spin rounded-full border-4 border-primary-500 border-t-transparent"></div>
          <p class="mt-3 text-gray-500">请在新打开的支付页面完成付款，系统将自动检测并开通租赁。</p>
          <button v-if="paymentOrder?.pay_url" type="button" class="btn btn-secondary mt-3" @click="reopenPayWindow">
            重新打开支付窗口
          </button>
        </div>
        <div v-if="paymentOrder" class="w-full rounded-xl bg-gray-50 p-3 text-xs space-y-1 dark:bg-dark-800">
          <div class="flex justify-between">
            <span class="text-gray-500">应付金额</span>
            <strong class="tabular-nums">{{ paymentCurrencySymbol }}{{ paymentOrder.pay_amount.toFixed(2) }}</strong>
          </div>
          <div class="flex justify-between">
            <span class="text-gray-500">预计到账余额</span>
            <strong class="tabular-nums">${{ paymentOrder.amount.toFixed(2) }}</strong>
          </div>
        </div>
        <p class="text-xs text-gray-500">正在等待支付确认与自动开通…</p>
        <p v-if="errorMessage" role="alert" class="text-red-600 dark:text-red-400">{{ errorMessage }}</p>
      </div>

      <!-- Checkout failed after balance credit (slot filled / listing paused) -->
      <div v-else-if="phase === 'checkout_failed' && intentState" role="alert" class="space-y-3 rounded-xl border border-amber-200 bg-amber-50 p-4 text-amber-900 dark:border-amber-800 dark:bg-amber-950/30 dark:text-amber-200">
        <p class="font-semibold">支付已成功入账，但租赁未能自动开通</p>
        <p>
          您支付的 <strong>${{ intentState.topup_credited_usd.toFixed(2) }}</strong> 已安全计入站内可用余额，资金无损失。
        </p>
        <p class="text-xs opacity-90">
          原因：{{ intentState.failure_message || intentState.failure_code || '资源名额已满或状态变化' }}
        </p>
      </div>

      <!-- Cancelled / Expired -->
      <div v-else-if="phase === 'expired'" class="space-y-3 text-center py-2">
        <p class="font-medium text-red-600 dark:text-red-400">支付订单已取消或超时关闭</p>
        <p class="text-gray-500">您可以返回重新选择支付方式发起支付。</p>
      </div>
    </div>

    <template #footer>
      <div class="flex justify-end gap-2">
        <template v-if="phase === 'select'">
          <button type="button" class="btn btn-secondary" :disabled="submitting" @click="handleClose">取消</button>
          <button
            type="button"
            class="btn btn-primary"
            data-testid="start-shortfall-payment"
            :disabled="submitting || loadingMethods || !selectedMethod || checkoutInfo?.balance_disabled"
            @click="startPayment"
          >
            {{ submitting ? '正在创建支付订单…' : '去支付并自动开通' }}
          </button>
        </template>
        <template v-else-if="phase === 'waiting'">
          <button type="button" class="btn btn-secondary" :disabled="verifying" @click="handleClose">稍后查看</button>
          <button
            type="button"
            class="btn btn-primary"
            data-testid="verify-payment-intent"
            :disabled="verifying"
            @click="handleVerifyNow"
          >
            {{ verifying ? '正在核验…' : '我已完成支付，立即核验' }}
          </button>
        </template>
        <template v-else-if="phase === 'expired'">
          <button type="button" class="btn btn-secondary" @click="handleClose">关闭</button>
          <button v-if="listing && shortfall" type="button" class="btn btn-primary" @click="resetToSelect">重新支付</button>
        </template>
        <template v-else-if="phase === 'checkout_failed'">
          <button type="button" class="btn btn-primary" @click="handleClose">我知道了</button>
        </template>
      </div>
    </template>
  </BaseDialog>
</template>

<script setup lang="ts">
import { computed, nextTick, onUnmounted, ref, watch } from 'vue'
import QRCode from 'qrcode'
import BaseDialog from '@/components/common/BaseDialog.vue'
import PaymentMethodSelector, { type PaymentMethodOption } from '@/components/payment/PaymentMethodSelector.vue'
import StripePaymentInline from '@/components/payment/StripePaymentInline.vue'
import { currencySymbol } from '@/components/payment/currency'
import { decidePaymentLaunch, getVisibleMethods } from '@/components/payment/paymentFlow'
import { getPaymentPopupFeatures } from '@/components/payment/providerConfig'
import { paymentAPI } from '@/api/payment'
import { extractApiErrorMessage } from '@/utils/apiError'
import type { CheckoutInfoResponse, CreateOrderResult } from '@/types/payment'
import { marketplaceAPI } from './api'
import type { CheckoutShortfallMetadata, Listing, MarketplacePaymentIntent, RentalOrder } from './types'

const props = defineProps<{
  show: boolean
  listing: Listing | null
  idempotencyKey: string
  shortfall: CheckoutShortfallMetadata | null
  initialIntentId?: number | null
}>()

const emit = defineEmits<{
  close: []
  completed: [order: RentalOrder | null]
  balanceCredited: [intent: MarketplacePaymentIntent]
}>()

type DialogPhase = 'select' | 'waiting' | 'stripe' | 'checkout_failed' | 'expired'

const phase = ref<DialogPhase>('select')
const loadingMethods = ref(false)
const submitting = ref(false)
const verifying = ref(false)
const errorMessage = ref('')
const checkoutInfo = ref<CheckoutInfoResponse | null>(null)
const selectedMethod = ref('')
const intentId = ref<number | null>(null)
const paymentOrder = ref<CreateOrderResult | null>(null)
const intentState = ref<MarketplacePaymentIntent | null>(null)
const qrCanvas = ref<HTMLCanvasElement | null>(null)

let pollTimer: ReturnType<typeof setInterval> | null = null
let pollTicks = 0

const dialogTitle = computed(() => {
  switch (phase.value) {
    case 'waiting':
      return '完成支付并自动开通'
    case 'stripe':
      return '在线支付补足差额'
    case 'checkout_failed':
      return '余额已入账'
    case 'expired':
      return '支付未完成'
    default:
      return '余额不足 · 补足差额并租用'
  }
})

const methodOptions = computed<PaymentMethodOption[]>(() => {
  if (!checkoutInfo.value?.methods) return []
  const visible = getVisibleMethods(checkoutInfo.value.methods)
  return Object.entries(visible).map(([type, limit]) => ({
    type,
    display_name: limit.display_name,
    fee_rate: limit.fee_rate ?? 0,
    available: limit.available !== false,
  }))
})

const paymentCurrencySymbol = computed(() => currencySymbol(paymentOrder.value?.currency || 'CNY'))

function formatCents(cents: number): string {
  return `$${(cents / 100).toFixed(2)}`
}

function stopPolling() {
  if (pollTimer) {
    clearInterval(pollTimer)
    pollTimer = null
  }
  pollTicks = 0
}

function resetToSelect() {
  stopPolling()
  phase.value = 'select'
  errorMessage.value = ''
  paymentOrder.value = null
  intentState.value = null
  intentId.value = null
}

function handleClose() {
  stopPolling()
  emit('close')
}

async function loadCheckoutMethods() {
  loadingMethods.value = true
  errorMessage.value = ''
  try {
    const { data } = await paymentAPI.getCheckoutInfo()
    checkoutInfo.value = data
    const firstAvailable = methodOptions.value.find(item => item.available)
    selectedMethod.value = firstAvailable?.type ?? ''
  } catch (error) {
    errorMessage.value = extractApiErrorMessage(error, '无法加载支付配置，请稍后重试')
  } finally {
    loadingMethods.value = false
  }
}

async function renderQRCode(qrCode: string) {
  if (!qrCode) return
  await nextTick()
  if (!qrCanvas.value) return
  try {
    await QRCode.toCanvas(qrCanvas.value, qrCode, { width: 220, margin: 2 })
  } catch {
    // Ignore canvas rendering failure in headless test environments.
  }
}

function reopenPayWindow() {
  if (paymentOrder.value?.pay_url) {
    window.open(paymentOrder.value.pay_url, 'paymentPopup', getPaymentPopupFeatures())
  }
}

function handleIntentUpdate(intent: MarketplacePaymentIntent) {
  intentState.value = intent
  if (intent.status === 'completed') {
    stopPolling()
    emit('completed', intent.marketplace_order ?? null)
  } else if (intent.status === 'checkout_failed') {
    stopPolling()
    phase.value = 'checkout_failed'
    emit('balanceCredited', intent)
  } else if (intent.status === 'cancelled' || intent.status === 'expired') {
    stopPolling()
    phase.value = 'expired'
  }
}

async function pollIntentReadOnly() {
  if (!intentId.value) return
  pollTicks += 1
  try {
    // Strictly read-only GET polling; every 4th tick (~10s) explicitly triggers POST /verify
    // so providers with missed webhooks still converge smoothly.
    const intent = pollTicks % 4 === 0
      ? await marketplaceAPI.verifyPaymentIntent(intentId.value)
      : await marketplaceAPI.getPaymentIntent(intentId.value)
    handleIntentUpdate(intent)
  } catch {
    // Keep polling transiently until user cancels or closes.
  }
}

function startPolling(id: number) {
  stopPolling()
  intentId.value = id
  pollTimer = setInterval(() => {
    void pollIntentReadOnly()
  }, 2500)
}

async function handleVerifyNow() {
  if (!intentId.value || verifying.value) return
  verifying.value = true
  errorMessage.value = ''
  try {
    const intent = await marketplaceAPI.verifyPaymentIntent(intentId.value)
    handleIntentUpdate(intent)
    if (intent.status === 'pending') {
      errorMessage.value = '暂未收到支付成功通知，请完成付款后稍等几秒再试。'
    }
  } catch (error) {
    errorMessage.value = extractApiErrorMessage(error, '核验支付状态失败，请重试')
  } finally {
    verifying.value = false
  }
}

async function startPayment() {
  if (!props.listing || !selectedMethod.value || submitting.value) return
  submitting.value = true
  errorMessage.value = ''
  try {
    const isMobileDevice = /mobile|android|iphone|ipad|ipod/i.test(navigator.userAgent || '')
    const isWechat = /micromessenger/i.test(navigator.userAgent || '')
    const result = await marketplaceAPI.checkoutPayment(props.listing.id, {
      idempotency_key: props.idempotencyKey,
      payment_type: selectedMethod.value,
      return_url: `${window.location.origin}/marketplace`,
      is_mobile: isMobileDevice,
    })

    if (result.mode === 'balance_completed') {
      emit('completed', result.order ?? null)
      return
    }

    if (!result.payment) {
      errorMessage.value = '支付订单创建异常，请重试'
      return
    }

    paymentOrder.value = result.payment
    const decision = decidePaymentLaunch(result.payment, {
      visibleMethod: selectedMethod.value,
      orderType: 'balance',
      isMobile: isMobileDevice,
      isWechatBrowser: isWechat,
      forceQRCode: checkoutInfo.value?.alipay_force_qrcode,
      mobilePrecreateDeepLink: checkoutInfo.value?.alipay_mobile_precreate_deep_link,
    })

    if (decision.kind === 'wechat_oauth' && decision.oauth?.authorize_url) {
      window.location.href = decision.oauth.authorize_url
      return
    }

    if (result.intent_id) {
      startPolling(result.intent_id)
    }

    if ((decision.kind === 'stripe_route' || decision.kind === 'stripe_popup') && result.payment.client_secret && checkoutInfo.value?.stripe_publishable_key) {
      phase.value = 'stripe'
      return
    }

    phase.value = 'waiting'
    if (result.payment.qr_code) {
      await renderQRCode(result.payment.qr_code)
    } else if (result.payment.pay_url) {
      window.open(result.payment.pay_url, 'paymentPopup', getPaymentPopupFeatures())
    }
  } catch (error) {
    errorMessage.value = extractApiErrorMessage(error, '发起支付失败，请重试')
  } finally {
    submitting.value = false
  }
}

watch(
  () => props.show,
  async (open) => {
    stopPolling()
    errorMessage.value = ''
    intentState.value = null
    paymentOrder.value = null
    if (!open) return

    if (props.initialIntentId && props.initialIntentId > 0) {
      phase.value = 'waiting'
      startPolling(props.initialIntentId)
      await handleVerifyNow()
      return
    }

    phase.value = 'select'
    await loadCheckoutMethods()
  },
  { immediate: true },
)

onUnmounted(() => stopPolling())
</script>
