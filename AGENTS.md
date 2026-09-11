# Berth (Sub2API fork) contract

## Scope and source of truth

- 只约束本仓库。这是 [Wei-Shaw/sub2api](https://github.com/Wei-Shaw/sub2api) 的 GitHub fork，产品名 Berth（泊位）。
- GitHub：`jk-zhang-meta/berth`。远程：`origin` = 本 fork，`upstream` = `Wei-Shaw/sub2api`。
- 产品分支是 `berth`。`main` 跟随上游默认分支，不在 `main` 上堆本地功能。
- 以后要吸收上游新功能。判断改动时先问：合入上游下一版时，双方功能还能同时留下吗。

## Operating constraints

### 上游吸收

- Rule: 本地产品放新文件；上游文件只加薄挂钩。禁止为方便而重写、重排或整理上游模块。
- 必须改上游文件时：只加必要调用、字段或路由；不改无关格式、命名、默认值或测试断言。
- 不要再删除或关闭上游能力，除非当前用户明确点名；已拿掉的计费/公告/渠道/分组等不再扩大删除面。
- 合并或吸收上游时若有冲突：暂停，说明文件、双方意图和影响，询问后再改，不得擅自取舍。
- SQL 只追加新 migration，不改已有上游 migration。
- 前端新页面用新 view，样式复用 `card` / `btn` / `input` / `TablePageLayout`。不要再整页重写上游大页。`AccountsView` 卡片化已是高冲突面，后续只做最小补丁。
- 本地功能优先落点：`backend/internal/service/work_session.go`、`rental.go`、`steward.go`、`backend/migrations/238_*.sql` 起、`frontend/src/views/SessionsView.vue`、`RentalsView.vue`、`MyAccountsView.vue`、`MyProxiesView.vue`、`frontend/src/productSurface.ts`、`frontend/src/branding.ts`。
- 产品名是 Berth（泊位）。产品面保留登录、仪表盘、账号、租赁市场、会话、Key、使用记录、代理、余额/充值/兑换、个人资料。其它上游页不删文件，由 `productSurface.ts` 白名单挡掉。
- Scope: 本仓库；不要再在 `AgentOps-Hub/sub2api/` 上改产品。
- 吸收上游：`git fetch upstream --tags`，把 `upstream/main` 或正式 tag（`v*`）merge 进 `berth`。冲突暂停说明并询问，不得擅自取舍。版本号跟随上游，不加后缀。
- Reason: 无谓分歧会在吸收上游时丢功能或静默失效。
- Oracle: 能指认「新文件 vs 上游挂钩」；对上游大文件的 diff 应是挂钩级。
- Owner/status: project maintainer; active

### 底座

- Rule: 产品底座是本 Sub2API 分叉。Cockpit Tools 只作本地卡片/登录管理对照；CPA 只作 Claude/Codex 协议与伪装参考，二者都不是可替换底座。
- Reason: 网关、多用户、Key、调度、租赁都已经在这条链上；Cockpit 是本机桌面（CC BY-NC-SA），CPA 没有这套运营面。
- Oracle: 新功能仍落在本仓库新文件 + 上游薄挂钩。
- Owner/status: project maintainer; active

### 运行时

- 在本 checkout 改源码。编译、依赖、日志放到 host-local runtime `berth-local`，不要在本目录生成大型构建树。
- 日常只跑这一套；Cockpit / CPA 不是运行依赖。

## Verification oracles

- 前端：runtime 副本 `vue-tsc --noEmit` 为 0。
- 后端：在 runtime 副本编译或测试。
- 吸收上游后：双方功能都在，且无未解决冲突。

## Workflow and completion

- 易变任务状态放 runtime `TASK_STATE.md`，不写进本文件。
- 一次功能改动完成的前提：挂钩可指认，且没有扩大与上游的无关 diff。

## Map

- 会话队列、租赁、AGS id 是本地产品。调度占用目前挂在上游 `openai_account_scheduler.go` / `gateway_scheduling.go`，合并时优先核对这些挂钩。
