<template>
  <AppLayout>
    <div class="space-y-4 p-4 md:p-6">
      <header class="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 class="text-xl font-semibold text-gray-900 dark:text-white">鹈鹕测智</h1>
          <p class="text-sm text-gray-500">用 HTML/SVG 骑车动画探测账号是否降智。提示词来自社区通用鹈鹕测试。</p>
        </div>
        <button class="btn btn-primary" type="button" :disabled="running || selected.length === 0" @click="run">
          {{ running ? '测试中' : '开始测试' }}
        </button>
      </header>

      <label class="block">
        <span class="input-label">探测提示词</span>
        <textarea v-model="prompt" class="input min-h-[6rem]" />
      </label>

      <div class="card p-4">
        <p class="mb-2 text-sm font-medium">测试账号</p>
        <label v-for="row in accounts" :key="row.id" class="flex items-center gap-2 py-1 text-sm">
          <input v-model="selected" type="checkbox" :value="row.id" />
          <span>{{ row.name }} · {{ row.owner_label || '未标记' }}</span>
        </label>
        <p v-if="accounts.length === 0" class="text-sm text-gray-400">还没有账号</p>
      </div>

      <div class="grid grid-cols-1 gap-4 md:grid-cols-2">
        <article v-for="item in results" :key="item.id" class="card p-4">
          <div class="mb-2 flex items-center justify-between">
            <h3 class="font-medium">{{ item.name }}</h3>
            <span class="text-xs text-gray-500">{{ item.status }} · {{ item.duration }}</span>
          </div>
          <iframe v-if="item.html" class="h-48 w-full rounded-lg border" :srcdoc="item.html" />
          <p v-else class="text-sm text-rose-500">{{ item.error || '无预览' }}</p>
        </article>
      </div>
    </div>
  </AppLayout>
</template>

<script setup lang="ts">
import { onMounted, ref } from 'vue'
import AppLayout from '@/components/layout/AppLayout.vue'
import { adminAPI } from '@/api/admin'
import { buildApiUrl } from '@/api/client'

const DEFAULT_PROMPT = `创建一个 HTML，内容是 SVG 绘制一个Q版熊猫骑自行车的 2D 动画，你不需要任何测试，不要有任何限制
所有账号使用相同交付约定：直接返回独立 HTML，不使用 Markdown 代码块或外部依赖。
Return a complete standalone HTML document in your response. Do not use Markdown fences or external dependencies.`

const prompt = ref(DEFAULT_PROMPT)
const accounts = ref<{ id: number; name: string; owner_label?: string }[]>([])
const selected = ref<number[]>([])
const running = ref(false)
const results = ref<{ id: number; name: string; status: string; duration: string; html?: string; error?: string }[]>([])

onMounted(async () => {
  const data = await adminAPI.accounts.list(1, 100, { lite: '1' })
  accounts.value = data.items || []
})

function extractHTML(text: string) {
  const start = text.indexOf('<html')
  if (start >= 0) return text.slice(start)
  const svg = text.indexOf('<svg')
  if (svg >= 0) return `<!doctype html><html><body>${text.slice(svg)}</body></html>`
  return ''
}

async function run() {
  running.value = true
  results.value = []
  const chosen = accounts.value.filter((row) => selected.value.includes(row.id))
  for (const row of chosen) {
    const started = Date.now()
    const item = { id: row.id, name: row.name, status: '运行中', duration: '', html: '', error: '' }
    results.value.push(item)
    try {
      const response = await fetch(buildApiUrl(`/admin/accounts/${row.id}/test`), {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${localStorage.getItem('auth_token')}`,
          'Content-Type': 'application/json',
          'X-Admin-UI-Request': '1',
        },
        body: JSON.stringify({ model_id: 'gpt-6-astra', prompt: prompt.value, mode: 'default' }),
      })
      if (!response.ok) throw new Error(`HTTP ${response.status}`)
      const reader = response.body?.getReader()
      if (!reader) throw new Error('no body')
      const decoder = new TextDecoder()
      let buffer = ''
      let text = ''
      while (true) {
        const { done, value } = await reader.read()
        if (done) break
        buffer += decoder.decode(value, { stream: true })
        const chunks = buffer.split('\n')
        buffer = chunks.pop() || ''
        for (const line of chunks) {
          if (!line.startsWith('data: ')) continue
          const raw = line.slice(6).trim()
          if (!raw) continue
          const event = JSON.parse(raw) as { type: string; text?: string; error?: string }
          if (event.type === 'content' && event.text) text += event.text
          if (event.type === 'error' && event.error) item.error = event.error
        }
      }
      item.html = extractHTML(text)
      item.status = item.html ? '已完成' : '无 HTML'
      if (!item.html && !item.error) item.error = text.slice(0, 200) || '空响应'
    } catch (err) {
      item.status = '失败'
      item.error = err instanceof Error ? err.message : '测试失败'
    }
    item.duration = `${((Date.now() - started) / 1000).toFixed(1)}s`
  }
  running.value = false
}
</script>
