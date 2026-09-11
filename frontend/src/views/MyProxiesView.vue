<template>
  <AppLayout>
    <div class="space-y-6">
      <p class="text-sm text-gray-500 dark:text-gray-400">
        每个号可以绑自己的出口。这些代理只属于你，不会出现在别人的账号上。
      </p>

      <form class="card flex flex-wrap items-end gap-3 p-4" @submit.prevent="createProxy">
        <label class="w-40">
          <span class="input-label">名称</span>
          <input v-model="draft.name" class="input" required placeholder="洛杉矶住宅" />
        </label>
        <label class="w-28">
          <span class="input-label">协议</span>
          <select v-model="draft.protocol" class="input">
            <option value="http">http</option>
            <option value="https">https</option>
            <option value="socks5">socks5</option>
            <option value="socks5h">socks5h</option>
          </select>
        </label>
        <label class="min-w-[10rem] flex-1">
          <span class="input-label">主机</span>
          <input v-model="draft.host" class="input" required />
        </label>
        <label class="w-24">
          <span class="input-label">端口</span>
          <input v-model.number="draft.port" class="input" type="number" min="1" max="65535" required />
        </label>
        <label class="w-36">
          <span class="input-label">用户名</span>
          <input v-model="draft.username" class="input" />
        </label>
        <label class="w-36">
          <span class="input-label">密码</span>
          <input v-model="draft.password" class="input" type="password" />
        </label>
        <button class="btn btn-primary" type="submit">添加</button>
      </form>

      <p v-if="error" class="text-sm text-red-500">{{ error }}</p>

      <div class="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
        <article v-for="row in proxies" :key="row.id" class="card flex flex-col gap-2 p-5">
          <h3 class="font-medium text-gray-900 dark:text-white">{{ row.name }}</h3>
          <p class="font-mono text-xs text-gray-500">{{ row.protocol }}://{{ row.host }}:{{ row.port }}</p>
          <p class="text-xs text-gray-400">{{ row.status }}</p>
        </article>
      </div>
    </div>
  </AppLayout>
</template>

<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import AppLayout from '@/components/layout/AppLayout.vue'
import { createBerthProxy, listBerthProxies, type BerthProxy } from '@/api/berth'

const proxies = ref<BerthProxy[]>([])
const error = ref('')
const draft = reactive({
  name: '',
  protocol: 'http',
  host: '',
  port: 1080,
  username: '',
  password: '',
})

async function load() {
  error.value = ''
  try {
    proxies.value = await listBerthProxies()
  } catch (err) {
    error.value = err instanceof Error ? err.message : '加载失败'
  }
}

async function createProxy() {
  try {
    await createBerthProxy({ ...draft })
    draft.name = ''
    draft.host = ''
    draft.username = ''
    draft.password = ''
    await load()
  } catch (err) {
    error.value = err instanceof Error ? err.message : '添加失败'
  }
}

onMounted(load)
</script>
