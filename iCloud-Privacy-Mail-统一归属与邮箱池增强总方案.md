# iCloud-Privacy-Mail 统一归属与邮箱池增强总方案

> 方案名：iCloud-Privacy-Mail 统一归属与邮箱池增强总方案
> 基线仓库：`https://github.com/biubiubiu125/iCloud-Privacy-Mail`

## 1. 总目标

- 仓库信息、作者信息、更新源、发布源、镜像源统一指向 `biubiubiu125/iCloud-Privacy-Mail`
- 每次仓库更新自动构建 Docker 镜像
- 增强邮箱池管理能力：分类、批量导出、批量删除、远程删除
- 支持账号级代理，覆盖登录与后续所有协议链路
- 保持现有登录、取码、导出、更新逻辑兼容

## 2. 统一归属与仓库信息

需要统一替换的内容：

- `README.md`
- `config.example.json`
- 作者/维护者名称
- 更新检测默认仓库配置
- 发布说明中的下载链接与仓库链接
- 更新日志中的仓库引用
- 测试里的仓库路径引用
- 代码注释、示例字符串、文档中的旧 owner

统一后的默认值建议：

- 仓库：`biubiubiu125/iCloud-Privacy-Mail`
- 更新仓库：`biubiubiu125/iCloud-Privacy-Mail`
- 发布地址：全部从新仓库读取
- 示例链接：全部改成新仓库路径

## 3. Docker 自动构建方案

### 3.1 目标

- 仓库一有更新就自动构建镜像
- 镜像名和仓库归属保持一致
- 支持持续发布和回滚

### 3.2 建议实现

- 新增 `Dockerfile`
- 新增 GitHub Actions 工作流
- 触发条件：
  - 任意分支或标签 `push`
  - 手动 `workflow_dispatch`
- 自动打镜像标签：
  - `latest`：仅默认分支
  - `commit sha`：每次构建都会生成
  - `version tag`：版本标签推送时发布
- 发布策略：默认分支和版本标签构建后推送到 GHCR；其他分支只构建、不推送，避免污染稳定镜像命名空间

### 3.3 镜像命名建议

- 推荐：`ghcr.io/biubiubiu125/icloud-privacy-mail`
- 如果后续改用其他镜像 registry，只替换 registry 前缀即可

### 3.4 额外建议

- 多架构构建：`linux/amd64`、`linux/arm64`
- 默认分支和版本标签构建后自动推送镜像；其他分支只做构建校验
- 在 README 中补上拉取方式和版本对应关系

## 4. 邮箱池二开总方案

### 4.1 分类显示

邮箱池新增分类：

- 已导出
- 未导出

这里“已导出”指已经导出过邮箱 API。

### 4.2 单选/全选导出

支持：

- 单选导出某个邮箱 API
- 全选导出当前列表
- 批量导出筛选结果

导出后自动更新导出状态，避免重复判断混乱。

### 4.3 单选/全选删除

支持：

- 单选删除某个邮箱
- 全选删除当前列表
- 批量删除选中的邮箱

删除时提供两个层级：

- 只删本地记录
- 同步删除 iCloud 创建的隐私邮箱本体

当前实现策略按远端协议区分：旧 iCloud Web 登录态先调用 Hide My Email 停用接口，再调用删除接口；Apple Account 新接口登录态直接调用对应隐私邮箱的 `DELETE /account/manage/email/private/{anonymousId}/remove` 接口。远端调用失败时不删除本地记录，并把失败邮箱返回给前端。

### 4.4 账号级代理

每个账号单独配置代理，覆盖：

- 登录
- 2FA
- 创建邮箱
- 同步邮件
- 导出
- 删除
- IMAP 拉取

建议代理配置跟账号一起存储，便于独立维护和排障。

## 5. 当前实现状态

- [x] 仓库、作者、更新源、发布源、镜像归属统一为 `biubiubiu125/iCloud-Privacy-Mail`
- [x] 新增 `Dockerfile`，支持构建版本、提交号和构建时间
- [x] 新增 GitHub Actions：任意分支都会构建验证；默认分支和版本标签才推送 GHCR。非推送的多架构构建使用 `cacheonly` 输出，避免 Buildx 失败。第三方 Action 固定到提交 SHA
- [x] 镜像统一为 `ghcr.io/biubiubiu125/icloud-privacy-mail`
- [x] 账号模型增加代理地址，并覆盖 Apple 登录、2FA、创建、同步、导出、删除和 IMAP 链路
- [x] 前端支持账号代理配置、脱敏显示和清除代理
- [x] 邮箱模型增加远程匿名 ID、远程来源和 API 导出时间
- [x] 邮箱池支持全部/已导出/未导出筛选
- [x] 邮箱池支持单选、当前页全选、筛选结果全选、批量导出 API 和批量导出邮箱
- [x] 未绑定邮箱可在首页和管理页选择同一平台用户的 Apple 账号补绑定，管理员跨用户绑定按邮箱原归属校验
- [x] 邮箱池支持单个/批量删除本地记录，或同步删除 iCloud 隐私邮箱本体
- [x] 批量远端删除采用逐条处理，失败项保留本地记录并返回失败明细
- [x] 增加代理、导出状态、远端删除、账号代理同步、归属权限、登录态合并和跨协议状态测试
- [x] 兼容分层保存的旧 iCloud Web Cookie，并修复 Apple Account 登录态的账号状态显示
- [x] 统一前端公开登录态能力判断，并修正分层 Cookie 的数量统计
- [x] 代理底层 Transport 类型异常时返回可诊断错误，不再触发类型断言崩溃
- [x] Apple Account 列表分页合并顶层与嵌套元数据，避免漏读后续页面
- [x] 创建结果不确定时持久化账号级待核对状态，阻止手动/定时创建跨接口重复尝试；成功同步 Apple Account 列表后自动解除
- [x] Apple Account 远端删除失败时保存此前已成功刷新的登录态
- [x] GitHub Release 和自定义 manifest 更新资产均强制 SHA-256 校验
- [x] 完整状态导出和邮箱 API 导出设置 `no-store`，避免敏感下载被浏览器或中间缓存复用
- [x] 状态文件写入采用私有临时文件、`fsync` 和原子替换，降低进程崩溃导致半写文件的风险
- [x] README、配置示例和本方案文档同步更新
- [x] WSL 完成格式化、单元测试、竞态测试、`go vet`、生产构建和前端脚本语法检查

## 6. 推荐实施顺序

1. 统一仓库归属、默认更新源、所有旧链接
2. 增加 Dockerfile 和自动构建工作流
3. 扩展数据模型：导出状态、远程标识、代理配置
4. 改造邮箱池页面：分类、筛选、批量导出、批量删除
5. 补齐远程删除协议
6. 增加测试、回归验证和文档同步

## 7. 本次实际修改文件（含主要回归测试）

- `README.md`
- `config.example.json`
- `internal/app/config.go`
- `internal/app/models.go`
- `internal/app/store.go`
- `internal/app/server.go`
- `internal/app/templates/index.html`
- `internal/app/templates/manage.html`
- `internal/app/apple_auth_client.go`
- `internal/app/icloud_client.go`
- `internal/app/icloud_validate.go`
- `internal/app/imap_client.go`
- `internal/app/proxy.go`
- `internal/app/proxy_test.go`
- `internal/app/config_test.go`
- `internal/app/login_check_test.go`
- `internal/app/manage_template_test.go`
- `internal/app/index_template_test.go`
- `internal/app/server_test.go`
- `internal/app/review_fixes_test.go`
- `.github/workflows/docker-image.yml`
- `Dockerfile`
- `.dockerignore`
- `internal/app/updater_test.go`

## 8. 验证边界与风险点

- 远程删除 iCloud 隐私邮箱本体依赖当前 iCloud Hide My Email 接口协议；代码已隔离失败项，但仍建议先真实账号单条验证。
- 账号级代理当前只接受 HTTP/HTTPS，不接受 SOCKS5；代理认证信息随账号状态保存，公共接口只返回脱敏地址。
- 批量操作按逐条处理，已完成项不会回滚；远端删除失败项不会删除本地记录，便于重试。
- 导出的邮箱 API 和完整状态文件包含敏感信息，必须限制下载和服务器文件权限。
- GitHub Actions 推送 GHCR 需要仓库启用包写入权限；首次发布后要检查镜像包可见性和拉取权限。
- API 导出状态在服务端成功生成导出内容后更新；支持 File System Access API 的浏览器会先选择保存位置，用户取消时不会请求服务端，因此不会误标为已导出；不支持该 API 的浏览器仍走默认下载，服务端只能以请求成功生成为准。
- 旧 iCloud Web 和 Apple Account 列表同步都只对各自远端来源做缺失标记；列表响应不完整时不会执行缺失标记，Apple Account 邮箱继续通过远端 ID 和专用删除链路管理。
- 当前已完成本地 WSL 验证；没有真实 Apple 账号登录态时不会宣称已完成第三方在线接口验证。本机未安装 Docker CLI，因此 Dockerfile 未做本地 Docker 构建，改由 GitHub Actions 在仓库更新后执行多架构构建。

## 9. 后续建议

1. 增加“测试代理”按钮，在保存代理前验证 Apple Account、iCloud Mail 和 IMAP 三类连通性。
2. 批量远端操作改为后台任务，增加进度、取消、失败重试和结果下载，避免大量邮箱操作长时间占用请求。
3. 增加操作审计日志，记录操作者、邮箱、操作类型、远端结果和失败原因。
4. 增加邮箱搜索、账号筛选、导出状态、iCloud 状态和 API 状态的组合查询。
5. 增加远端一致性检查：定期比对本地邮箱池和 iCloud HME 列表，标记本地存在但远端不存在的记录。
6. 后续如需支持 SOCKS5，建议引入成熟的 Dialer 实现，不要在现有 HTTP CONNECT 代码上继续堆叠协议分支。

## 10. 2026-09-03 当前代码独立复审结果

本轮基于当前工作区源码、当前测试结果和当前运行时可用条件重新检查，没有把历史修复结论作为本轮证据。

### 10.1 本轮修复的闭环问题

- 邮箱同步下拉展示具备旧 iCloud Web 或 Apple Account 登录态的账号；未选账号的全局同步会处理所有具备可用新旧接口登录态的账号，Apple Account-only 账号和混合来源账号都会走对应的新接口列表同步。
- 未绑定账号的邮箱在存在多个账号时不再猜测任意登录态，必须明确账号归属后才能执行账号相关操作。
- 分层 Cookie 存在时，旧 iCloud Web 请求优先使用对应分层 Cookie；根 Cookie 只作为兼容回退。
- 管理员针对其他用户执行登录态或 IMAP 检测时，响应数据按被检测账号所属用户返回，避免返回管理员自己的账号列表。
- 远端删除前刷新当前邮箱状态，并按邮箱串行化远端删除；成功后的重复请求不会再次调用 iCloud。
- 旧状态文件的登录态/邮箱归属迁移、显式账号缺失反馈、导出状态持久化和删除状态持久化均补充了回归验证。
- 代理地址增加主机名校验，拒绝 `http://:7890` 这类缺少实际代理主机的地址。
- 登录态能力按类型区分：Apple Account-only 登录态不再因为存在通用根 Cookie 被误判为旧 iCloud Web 登录态。
- 旧状态文件只有在不存在类型化登录态时才从根 Cookie 推断旧 iCloud Web 登录态，避免迁移时污染 Apple Account-only 数据。
- “同步已有邮箱”会按账号可用来源分流：全局同步和具体账号同步都会分别调用旧 iCloud Web `/v2/hme/list` 与 Apple Account `account/manage/email/private` 列表接口，并继续保存远端 ID 进入专用删除链路。
- 定时创建链路保持“新接口优先 -> 可确认临时失败重试 -> 旧接口回退”的真实顺序；已提交但结果不确定时停止自动切换，并持久化账号级待核对状态。

### 10.2 已验证的主链路

1. 账号代理：账号保存或修改 -> 登录 -> 2FA -> Apple Account/iCloud Web 创建 -> 同步 -> 远端删除 -> IMAP。
2. 定时创建：账号能力识别 -> 新接口优先 -> 临时失败重试 -> 旧接口回退 -> 成功邮箱写回本地与远端来源。
3. 邮箱池：账号归属 -> 分组/搜索/已导出/未导出 -> 单选或当前筛选结果全选 -> txt/csv/tsv/jsonl 导出 -> 服务端持久化 API 导出时间。
4. 删除：权限校验 -> 本地删除或远端删除 -> 成功标记/本地删除；远端失败保留本地记录和失败原因；重复或并发删除不会重复调用远端 Provider。
5. 存储：旧字段迁移 -> 账号/邮箱/登录态归属 -> 管理员和普通用户隔离 -> 切换状态文件路径后的迁移与状态持久化。

### 10.3 当前仍需明确的边界

- Apple Account 账号在账号级和全局同步时都接入 `account/manage/email/private` 列表接口；全局同步会按每个登录态实际可用的来源处理新旧接口。Apple Account 新建邮箱保存远端 ID，并支持专用远端删除。
- 当前 WSL 没有 Docker CLI，Dockerfile 和 GitHub Actions 已做静态审查，但本机没有实际完成 Docker 构建或 GHCR 推送。
- 没有配置真实 Apple 账号环境变量，`liveapple` 仅完成编译与跳过逻辑验证，未宣称第三方在线请求成功。
- 账号代理当前仅支持 HTTP/HTTPS，不支持 SOCKS5。

## 11. 2026-09-03 本轮继续复审与修复

本轮再次从当前 `master` checkout 独立检查，没有将历史修复记录当作当前行为证据。

### 11.1 发现并修复的问题

- 发现管理员针对“全局/旧数据归属”的指定 iCloud 登录态执行检测时，如果管理员自己同时存在登录态，检测成功响应会错误返回管理员自己的会话列表。
- 增加回归测试先复现该问题，再修复 `publicSessionsForCheckedSessions`：优先按被检测会话的 Apple 账号归属解析数据所有者；归属为空时明确返回全局会话，避免被请求管理员身份覆盖。
- 清理本轮生成的临时审查差异文件，移入系统回收站；工作区不再保留 `.review_*.diff` 临时文件。

### 11.2 当前闭环复核结论

- 账号代理链路：登录表单代理 -> Apple 协议请求 -> iCloud 验证/创建/同步 -> Apple Account 管理接口 -> IMAP 取码，均按账号登录态传递代理。
- 邮箱池链路：归属过滤 -> 账号分组 -> 已导出/未导出筛选 -> 分页与全选 -> 单个/批量导出 -> `APIExportedAt` 持久化。
- 删除链路：权限校验 -> 本地删除或远端删除 -> 远端成功后本地删除；远端失败保留本地记录并记录失败状态；重复远端删除不会重复调用 Provider。
- 兼容链路：旧根 Cookie、分层 Cookie、旧邮箱池记录、Apple Account-only 登录态、管理员/普通用户归属均保留明确分支，不用猜测会话。
- 仓库与发布链路：远程仓库、更新仓库、README、配置示例、Dockerfile、GitHub Actions 和 GHCR 镜像地址统一到 `biubiubiu125/iCloud-Privacy-Mail`。

### 11.3 本轮最新验证

以下验证均在 WSL 中基于当前 checkout 执行：

- `go test -count=1 ./...`：通过。
- `go test -race -count=1 ./internal/app`：通过。
- `go vet ./...`：通过。
- `CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" ./cmd/panel`：通过。
- 从 `index.html`、`manage.html` 提取内嵌脚本并执行 `node --check`：通过。
- `git diff --check`：通过。

本机仍没有 Docker CLI，因此 Dockerfile 的实际镜像构建和 GHCR 推送由 GitHub Actions 负责，未将静态检查冒充为真实推送验证；真实 Apple/iCloud/IMAP Provider 请求也仍需配置测试账号后单条冒烟验证。

## 12. 2026-09-03 Docker 运行闭环修复

### 12.1 发现的问题

Dockerfile 虽然暴露并映射了 `8787` 端口，但程序默认监听 `127.0.0.1`。在容器内这会导致宿主机端口映射无法访问面板；同时降权运行时不能直接读取 root 拥有的只读配置挂载。

### 12.2 修复内容

- Docker 启动参数改为 `--host 0.0.0.0 --config /app/data/config.json`，仅覆盖容器网络监听地址和容器内可写配置路径，不改变本地运行默认地址。
- entrypoint 在降权前把 `/app/config.json`（或 `IPM_CONFIG_SOURCE` 指定的配置源）复制到数据卷并设置 `0600` 权限，避免宿主机只读挂载配置被 `ipm` 用户拒绝读取。已有数据卷配置默认保留，只有缺失或 `IPM_CONFIG_FORCE=1` 时才覆盖。
- 增加 Dockerfile 回归测试，确保后续修改不会再次移除容器网络监听参数。
- WSL 已先验证测试失败，再完成修复后验证通过。
- Docker 修复后的完整 WSL 回归：`go test`、`go test -race`、`go vet`、`CGO_ENABLED=0 go build`、前端 `node --check` 和 `git diff --check` 均通过。

## 13. 2026-09-04 全链路复审补强

本轮继续按当前工作区源码重新审查，不使用历史修复记忆作为当前行为证据，重点补齐“邮箱池筛选显示 -> 导出/删除请求 -> 服务端权限过滤 -> 状态持久化 -> 前端刷新”的闭环。

### 13.1 本轮继续发现并修复的问题

- POST JSON 批量导出已支持 `account_id` / `account_key`，选中邮箱导出和接口调用的账号范围不会被忽略。
- 邮箱 API 导出现在会同时继承“已导出 / 未导出”筛选和首页搜索条件，避免导出当前界面不可见的邮箱。
- 首页直接导出、后台直接导出、选中导出在 API 导出成功后都会刷新邮箱列表并清空选中状态，导出状态可立即从“未导出”变为“已导出”。
- 支持文件保存选择器的浏览器会先选保存位置再请求导出接口，用户取消保存不会提前把邮箱标记为已导出。
- 账号代理读取链路把账号配置视为权威来源；账号代理被清空后，历史登录态中的旧代理不会在读取快照时复活。
- 首页账号 TAB 在筛选后 0 条结果时仍保留当前账号范围，不会自动退回“全部”导致导出或删除误扩大范围。
- 首页邮箱池空结果会同步刷新本页全选框和“已选 N 个”，避免空列表下残留旧选择状态。
- 首页单个删除已补充异常捕获和日志，远端删除失败会在页面日志中明确提示。
- 测试数据中的旧仓库归属样式邮箱已替换为中性样例，避免仓库归属说明被旧身份字符串干扰。

### 13.2 本轮新增或强化的验证点

- 账号范围：GET / POST、`account_id` / `account_key`、`unbound` 都保持一致。
- 导出状态：已导出、未导出和全部三类筛选同时覆盖列表与导出。
- 搜索：首页搜索条件同时覆盖分页列表、全选筛选结果和直接导出。
- 保存时序：支持文件选择器时，取消保存发生在服务端导出和 `APIExportedAt` 标记之前。
- 代理权威性：保存登录态、修改账号代理、清空账号代理和读取登录态快照互不恢复旧代理。
- Docker 发布链路：Dockerfile 监听 `0.0.0.0`、安装 CA 证书、忽略本地构建产物，GitHub Actions 在 push/tag/manual 触发后推送 `ghcr.io/biubiubiu125/icloud-privacy-mail`。

### 13.3 当前剩余真实环境边界

- 本机 WSL 未安装 Docker CLI，当前只能验证 Dockerfile 与 workflow 静态闭环，不能在本机完成真实镜像 build/push。
- 未配置真实 Apple 测试账号和 App 专用密码，在线 Apple/iCloud/IMAP Provider 调用仍需拿真实账号做单条冒烟。
- 账号代理仍按当前需求只支持 HTTP/HTTPS；SOCKS5 建议作为独立后续功能。

## 14. 2026-09-04 继续复审：一致性与发布链路收口

本轮继续以当前 checkout 的实际源码和回归结果为依据，补齐以下会导致“看似成功但状态不闭环”的边界：

- iCloud 隐私邮箱列表响应现在区分“明确返回空数组”和“缺少列表字段”；检测到 `hasMore`、游标或无法解析的列表时返回 `icloud_mailbox_list_incomplete`，不会执行本地远端缺失标记。
- Provider 明确返回空数组时视为权威空列表，会把该旧 iCloud Web 账号下本地远端邮箱标记为远端不存在；缺少列表字段、分页未完成或记录缺少关键字段时不执行缺失标记。
- 邮箱同步不再仅按邮箱地址覆盖远端匿名 ID、账号和来源；远端身份、邮箱地址、账号和来源发生冲突时拒绝合并，保留原记录并返回明确冲突错误。
- 新创建远端邮箱写入本地前也会检查远端匿名 ID，避免本地持久化前后出现重复绑定；批量同步遇到身份冲突会跳过冲突项并继续处理其他邮箱。
- Provider 创建成功但本地邮箱记录保存失败时，会立即按远端来源执行补偿删除；补偿也失败时返回组合错误并保留可排查信息，避免静默产生远端孤儿邮箱。
- API 导出成功后的导出状态更新按邮箱归属分组写入，避免管理员批量导出请求在状态写回阶段跨所有者污染。
- 2FA 待验证期间保留“本次登录明确填写的代理”标记：明确填写的代理会在验证码提交后继续使用并绑定账号；留空登录则重新读取当前账号配置，避免旧待验证状态复活已清除的代理。
- 批量导出请求显式传入 `ids: null`、空数组或空字符串时统一拒绝，不再把空选择误解释为导出全部邮箱。
- 批量删除全部失败时返回 207 和逐条原因，首页和管理页都会展示失败邮箱及原因，而不是只显示一条笼统错误。
- Docker 工作流对任意 `push`、任意标签和手动触发构建；`checkout`、Buildx、登录、metadata、build-push Action 均固定到已核验提交 SHA。

### 14.1 本轮验证

- WSL 定向回归：列表完整性、空列表保护、远端身份冲突、导出归属隔离和 Docker 工作流约束均通过。
- WSL 全量 `go test -count=1 ./...` 通过。
- Docker CLI 仍未安装，因此没有把静态检查写成真实镜像构建或 GHCR 推送结果；真实 Apple/iCloud/IMAP Provider 请求仍需测试账号单条冒烟。

## 15. 2026-09-04 复审收口：账号隔离、并发和失败可见性

本轮重新从当前 checkout 的实际代码追踪登录、同步、导出、删除、持久化和 Docker 发布链路，修复剩余闭环问题：

- IMAP IDLE 监听分组现在同时隔离 `owner_id`、`account_id`、代理和 App 专用密码；同一 IMAP 端点被多个 Apple 账号复用时，不会错误共用第一账号的连接。
- 保存 IMAP 登录时，如果未传 `account_id` 且邮箱同时匹配多个不同 Apple 账号，明确返回 `imap_account_ambiguous`，不会静默绑定到第一个账号。
- 显式账号的 IMAP-only 登录态不会被重复清理逻辑误删；仍保留旧的“完整 Apple 登录态吸收孤立 IMAP 登录态”兼容行为。
- 同一账号的邮箱列表同步、远端创建和本地/远端删除共用账号级互斥门；删除先完成时，后到的旧同步结果不能重新创建已删除邮箱。
- 单邮箱远端清理也纳入账号级互斥门；清理移动邮件期间不会与远端删除并发操作同一账号。
- 远端删除失败且本地失败状态也无法持久化时，返回 `mailbox_remote_delete_state_persist_failed` 并同时保留远端和本地持久化错误，避免把关键状态写入失败静默掉。
- 账号、邮箱、远端同步、导出状态、IMAP 邮件和同步游标的本地持久化失败都会回滚内存变更并返回可诊断错误，避免重启前后状态不一致。
- Docker 工作流移除 `release.published` 重复触发，改为任意 `push`、任意标签和手动触发，兼容当前仓库已有的非 `v` 版本标签。

### 15.1 本轮验证

- WSL `gofmt` 检查通过，`go test -count=1 ./...` 通过。
- WSL `go test -race -count=1 ./internal/app` 通过，覆盖账号隔离、同步/删除并发和持久化失败回归。
- WSL `go vet ./...` 和 `CGO_ENABLED=0 go build ./cmd/panel` 通过。
- 两个 HTML 模板内联 JavaScript 均通过 `node --check`；Docker workflow 静态约束测试和 `git diff --check` 通过。
- WSL 当前未安装 Docker CLI，真实 Docker build/push 和 GHCR 登录推送仍需 GitHub Actions 环境执行。

## 16. 2026-09-04 再次复审：认证、持久化与前端失败链路收口

本轮不引用历史修复记忆，直接从当前工作树重新追踪“登录账号/代理 -> 登录态 -> 邮箱池 -> 导出/删除 -> 状态持久化 -> 前端反馈”链路，补齐以下问题：

- 用户注册、登录时间更新、用户删除、WebSession 创建和 WebSession 删除在本地状态文件写入失败时都会回滚内存状态，避免出现“接口失败但进程内已生效”的假状态。
- 注册、登录、管理员删除和退出登录接口会区分持久化失败并返回 500；退出登录持久化失败时不会提前清理浏览器 Cookie，避免服务端会话仍有效但前端误以为已退出。
- `NewServer` 在调用方未传 logger 时注入丢弃日志器，避免后台失败路径因空 logger 再次触发 panic。
- 邮箱池单个状态修改、停用、首页/管理页导出网络异常、管理页账号删除和退出登录异常都统一捕获并写入页面日志，不再产生未处理 Promise（Promise，前端异步任务）失败。
- 新旧两种 Apple 登录开始请求增加按钮忙碌态和失败反馈，避免重复点击造成并发登录请求且失败无提示。

### 16.1 本轮验证

- WSL 全量 `gofmt` 检查通过。
- WSL `go test -count=1 ./...`、`go test -race -count=1 ./internal/app`、`go vet ./...` 和 `CGO_ENABLED=0 go build ./cmd/panel` 通过。
- WSL 定向回归覆盖用户/WebSession 持久化回滚、空 logger、邮箱池状态异常、导出异常和登录开始异常，均通过。
- `index.html`、`manage.html` 内联 JavaScript 通过 `node --check`。
- Docker workflow 触发条件、镜像归属和 Action SHA 静态约束测试通过；`git diff --check` 通过。

### 16.2 当前仍需真实环境验证的边界

- WSL 未安装 Docker CLI，无法在当前机器执行真实 Docker build、GHCR 登录和 push；该链路由 GitHub Actions 执行。
- 未配置真实 Apple/iCloud/IMAP 测试账号，Provider（第三方服务）登录、2FA、代理、创建、同步和远端删除仍需单条真实冒烟。
- 当前代理实现支持 HTTP/HTTPS，不支持 SOCKS5。
- 导出内容完整生成后，服务端先持久化 `APIExportedAt` 再写出 HTTP 响应；状态文件写入失败时不会发送导出成功响应。响应写入失败时会尝试恢复导出前状态，并记录可排查告警；已经发送的导出文件不会被替换成错误 JSON。

## 17. 2026-09-04 独立复审：远端删除来源与中断恢复闭环

本轮从当前工作树重新检查“远端来源识别 -> Provider 删除接口 -> 本地记录删除 -> 进程中断恢复”链路，确认并修复以下问题：

- 旧 iCloud Web 的 `/v2/hme/list` 响应里的 `origin` 是 Apple 对邮箱创建方式的分类字段，不是本项目选择删除 Provider 的路由字段；同步时统一记录为 `ICLOUD_WEB`，避免把 `ON_DEMAND`、`MAIL` 等值误当成接口来源。
- 远端删除现在只接受 `APPLE_ACCOUNT` 或 `ICLOUD_WEB` 两种明确来源；来源为空或未知时直接返回 `icloud_mailbox_remote_origin_unknown`，不再错误调用旧 iCloud Web 删除接口。
- 上次远端删除中断后持久化为 `unknown` 的邮箱，单删和批删均支持显式 `confirm_unknown` 后重新执行远端删除；未确认时继续拒绝，避免重复删除未知状态造成误判。
- 远端删除成功后才删除本地记录；Provider 失败保留本地记录和失败状态；本地写入失败仍返回明确错误，便于人工复核和重试。
- 首页和管理页均显示“远端待核对”，并在选择远端删除时显式携带确认参数；只删除本地记录不会意外确认或调用远端接口。

### 17.1 本轮新增验证

- WSL 验证旧 iCloud Web 列表无论响应中的 `origin` 是什么，都落库为 `ICLOUD_WEB`。
- WSL 验证未知远端来源不会产生任何 Provider 请求，并返回 `icloud_mailbox_remote_origin_unknown`。
- WSL 验证单个和批量 `unknown` 远端删除在显式确认后可以恢复执行。
- WSL 全量测试、竞态测试、静态检查、构建、内联 JavaScript 语法和 `git diff --check` 在最终修改后重新执行。

### 17.2 当前真实环境边界

- 当前 WSL 未安装 Docker CLI，不能在本机完成 Docker build、GHCR 登录和推送；GitHub Actions 工作流只能做静态检查，真实镜像发布需由 GitHub Actions 执行。
- 当前未配置真实 Apple/iCloud/IMAP 测试账号，Provider 登录、2FA、代理、创建、同步和远端删除仍需真实账号做单条冒烟。
- 当前代理实现仍只支持 HTTP/HTTPS，不包含 SOCKS5。

## 18. 2026-09-05 独立复审：远端删除传输中断状态闭环

本轮从当前工作树重新追踪“远端删除请求 -> 网络返回 -> 本地状态 -> 重试/本地清理”链路，发现并修复一个会导致误判的边界：

- 远端删除遇到 `context.Canceled`、超时、EOF、连接重置等传输层错误时，无法证明 iCloud 没有收到请求；现在统一记录为 `unknown`，不会直接当作确定失败。
- `unknown` 状态继续阻止邮箱被领取，也阻止未确认的重复远端删除；管理员核对 iCloud 远端状态后，必须显式携带 `confirm_unknown` 才能重试。
- 已收到明确 HTTP/业务错误响应的删除仍记录为 `failed`；远端删除成功后才允许删除本地邮箱记录。
- `unknown` 状态本身的持久化失败也会保留进程内的待核对状态，并返回 `mailbox_remote_delete_state_persist_failed`，避免恢复为可误操作的普通状态。

### 18.1 本轮验证

- WSL 定向验证传输超时会记录 `unknown`，普通 Provider 错误和明确 HTTP 502 仍记录为 `failed`。
- WSL 全量测试、竞态测试、静态检查、无 CGO 构建、内联 JavaScript 语法检查和 `git diff --check` 均重新执行。

### 18.2 当前真实环境边界

- WSL 未安装 Docker CLI，不能在本机完成真实 Docker build、GHCR 登录和推送；实际镜像发布由 GitHub Actions 执行。
- 未配置真实 Apple/iCloud/IMAP 测试账号，Provider 登录、2FA、代理、创建、同步和远端删除仍需真实账号单条冒烟。
- 当前代理实现只支持 HTTP/HTTPS，不包含 SOCKS5；代理地址及其他登录态保存在本地状态文件中，应按敏感配置保护。

## 19. 2026-09-05 继续复审：监听任务与远端删除状态收口

本轮重新检查邮箱池状态变更后，后台轮询监听、IMAP IDLE 监听和取码同步是否仍会使用已经进入远端删除流程的邮箱，发现监听分组入口仍只判断了启用状态，虽然下游同步会再次过滤，但会产生无效监听连接和无效 IMAP 基线检查。

### 19.1 修复内容

- `mailWatcherGroups` 和 `mailWatcherIMAPGroups` 统一复用 `mailboxEligibleForMessageSync`。
- `pending`、`unknown`、`succeeded` 三种远端删除状态在监听分组入口直接排除。
- 邮箱进入远端删除流程后，不再创建新的轮询监听、IMAP IDLE 监听或 IMAP 基线任务；已经运行的同步仍由下游二次校验保护。
- 增加回归测试，分别验证普通监听分组和 IMAP 监听分组只保留可同步邮箱。

### 19.2 当前复审结论

- 账号代理、登录态保存/刷新、邮箱创建/同步、邮箱池筛选、API 导出、远端删除、本地删除、取码同步和监听任务均已形成状态约束闭环。
- 远端删除状态不会被领取、取码、监听、同步或重新激活逻辑绕过。
- Docker 自动构建发布链路仍指向自有仓库 `biubiubiu125/iCloud-Privacy-Mail` 和 GHCR 镜像 `ghcr.io/biubiubiu125/icloud-privacy-mail`。

### 19.3 本轮验证

- WSL 定向回归：监听分组排除远端删除中的邮箱，通过。
- WSL 全量 `go test -count=1 ./...`、`go test -race -count=1 ./internal/app`、`go vet ./...` 和 `CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" ./cmd/panel` 均通过。
- WSL `gofmt` 检查、`git diff --check` 和三个 HTML 模板的内联 JavaScript `node --check` 均通过。

### 19.4 当前真实环境边界

- WSL 未安装 Docker CLI，不能在本机完成 Docker build、GHCR 登录和推送；实际镜像发布由 GitHub Actions 执行。
- 未配置真实 Apple/iCloud/IMAP 测试账号，Provider 登录、2FA、代理、创建、同步和远端删除仍需真实账号单条冒烟。
- 当前代理实现只支持 HTTP/HTTPS，不包含 SOCKS5。

## 20. 2026-09-05 独立复审：导出与列表筛选闭环

本轮重新追踪当前代码中的“邮箱池筛选 -> 文件生成 -> HTTP 响应 -> 已导出状态”和管理员“全局邮箱列表”链路，修复以下问题：

- API 和纯邮箱地址导出统一要求 `POST`，拒绝会改变 `APIExportedAt` 的 `GET` 请求。
- API、CSV、TSV、JSONL 和纯邮箱导出都会检查最终生成记录数；筛选结果为空时返回 `404 mailbox_export_empty`，不再下载空附件或误报成功。
- 导出状态在导出内容生成并成功写入状态文件后标记；响应写入失败时会尝试恢复导出前状态，避免把失败响应误标为已导出。
- 管理员邮箱列表的 `owner_id=__global` 与导出接口保持一致，只返回未绑定平台用户的全局邮箱。
- 多架构 Docker 构建的 QEMU Action 已固定到提交 SHA，仓库每次 push 继续自动构建并推送 `ghcr.io/biubiubiu125/icloud-privacy-mail`。

### 20.1 Apple Account 列表同步边界

Apple Account 账号级和全局同步都接入 `account/manage/email/private` 列表接口；旧 iCloud Web 仍使用 `/v2/hme/list`。列表完整时只对当前远端来源做缺失标记，不能跨 Provider 误禁用邮箱；列表不完整时会中止缺失标记。Apple Account 创建返回的远端匿名 ID、单删/批删、结果不确定锁定和同步解锁链路仍然有效。

## 21. 2026-09-06 全真实链路闭环修复

本轮根据重新独立审查得到的闭环问题直接修复，并补充服务端、存储层和前端回归验证：

- `MarkMailboxesRemoteMissingForOrigin` 增加远端来源隔离；旧 iCloud Web 同步只标记 `ICLOUD_WEB` 邮箱，Apple Account 同步只标记 `APPLE_ACCOUNT` 邮箱，避免混合登录态下跨 Provider 误禁用。
- Apple Account-only 登录态现在出现在首页“同步范围”下拉框，明确显示“新接口”；全局同步选项改为“全部可同步登录态”，会覆盖所有可用的新旧接口来源。
- 管理员执行全局同步时，后端会收集所有归属用户和全局登录态，再按旧接口全局同步规则处理，不再只同步管理员自己的登录态。
- 管理员全量会话收集复用账号级代理解析，确保全局同步仍使用每个 Apple 账号的权威代理配置。
- 新增混合来源同步、Apple Account-only 前端入口和管理员全量同步回归测试。

### 21.1 验证与边界

- WSL `go test -count=1 ./...` 通过。
- WSL `go test -race -count=1 ./internal/app`、`go vet ./...`、`go build ./cmd/panel` 通过。
- `git diff --check` 通过。
- 未配置真实 Apple/iCloud/IMAP 账号，未宣称第三方在线 Provider 验证；WSL 未安装 Docker CLI，未在本机执行 Docker build 或 GHCR 推送。
