# iCloud Privacy Mail 取码平台

作者/维护：biubiubiu125

独立 Go 服务，用来登录 iCloud、创建 Hide My Email 隐私邮箱、同步验证码邮件，并给外部注册项目提供取码 API。

当前版本是 **全协议后端**：不依赖比特浏览器、CDP、浏览器页面脚本或手动复制 Cookie。

## 功能总览

- 账号密码注册/登录：第一个注册账号自动成为管理员，后续账号为普通用户。
- 管理员数据管理：管理员可查看所有用户、iCloud 登录态和隐私邮箱；普通用户只能操作自己的数据。
- 旧接口登录态：后端发起 iCloud 登录，用户收到 2FA 后提交 6 位验证码保存登录态。
- 多 Apple 登录态：同一平台账号可保存多个 Apple/iCloud 登录态，前端按账号 TAB 分开显示和操作。
- 隐私邮箱创建：优先调用 Apple Account 新接口创建，账号只有旧登录态时使用 iCloud Hide My Email `generate + reserve`；已提交但结果不确定时不会自动切换接口，必须先同步远端列表核对。
- 批量/定时创建：可勾选多个 Apple 登录态；手动创建会让选中账号同时跑一轮，定时只设置间隔，失败账号只在本次定时创建中临时跳过，其他账号继续创建，直到本次账号全部失败后等待下一次。
- 邮件同步：创建邮箱的 Apple 登录态只用于创建；验证码收件使用 iCloud 邮箱账号 + App 专用密码，通过 IMAP 监听和同步最新验证码邮件。
- 取码 API：每个隐私邮箱自动生成独立 `api_token`，复制时分别提供 API URL 和 API Token。
- 自动取号 API：外部项目可用全局 `api_key` 领取可用邮箱，领取后自动标记为已使用。
- 登录态检测：可手动检测 iCloud Mail 是否还能同步，也可在前端开启定时检测。
- 账号级代理：每个 Apple/iCloud 账号可单独配置 HTTP/HTTPS 或 SOCKS5 代理，登录、2FA、创建、同步、导出、删除和 IMAP 收件都会沿用该代理。
- 邮箱池分类：邮箱池支持按“全部 / 已导出 / 未导出”筛选，已导出表示已经导出过邮箱 API。
- 邮箱池批量操作：支持单选、当前页全选、筛选结果全选后批量导出邮箱 API、批量删除本地记录，或同步删除 iCloud 隐私邮箱本体。
- 数据导出：管理员可导出完整运行时状态；普通用户只能按权限导出邮箱 API 和邮箱地址；邮箱/API 导出支持按 Apple 登录态筛选。
- 瞬断重试：iCloud 登录后续步骤和 Hide My Email 列表同步遇到 EOF/timeout 等临时网络错误会短重试；2FA/OTP 校验不会重复提交。

## 目录结构

```text
cmd/panel/                 Go 服务入口
internal/app/              后端业务、协议客户端、状态存储和模板
internal/app/templates/    前端页面模板
config.example.json        配置模板
README.md                  使用与部署说明
更新日志.md                 公开版功能更新记录
```

以下目录是运行或排障产物，默认被 `.gitignore` 排除，不应提交或打包给别人：

```text
bin/
dist/
data/
logs/
captures/
.anna_skills/
.anna_manifest_tmp.json
config.json
```

## Apple Account 协议排障约定

新版 Apple Account 新接口登录/隐私邮箱创建协议，只以本机 Roxy 浏览器实操链路作为一手证据。

排查时必须使用用户指定的 Roxy 窗口，通过 CDP 重新打开目标页面、实际登录、提交 2FA，并记录本次请求顺序、method/path、状态码、关键响应头指纹和脱敏请求体。`C:\Users\Administrator\Desktop\*.har` 等用户历史抓包只能作为背景材料；除非用户明确要求，不得作为实现依据，不得用它覆盖 Roxy 实操结论。

涉及验证码/2FA 时，禁止同时触发多种发码方式；默认使用 `signin/complete` 自动下发的受信任设备验证码，不额外重发、不自动切短信。提交验证码时只按本次实际发码方式验证。

证据记录禁止保存或输出完整 Cookie、scnt、session、API key、密码、验证码。

## 配置

复制配置模板：

```powershell
Copy-Item .\config.example.json .\config.json
```

配置字段：

| 字段 | 说明 |
| --- | --- |
| `host` | 监听地址，本地默认 `127.0.0.1`；服务器建议仍监听 `127.0.0.1`，由 Nginx/Caddy 反代 |
| `port` | 监听端口，默认 `8787` |
| `data_path` | 服务器状态文件，默认 `data/state.json` |
| `api_key` | 全局 API Key，用于健康检查、自动取号、批量查询和按邮箱取码的请求头；管理面板不使用它登录 |
| `public_base_url` | 对外复制 API 地址用的公网地址，例如 `https://www.example.com` |
| `icloud_default_host` | iCloud 登录态校验 Host，默认 `www.icloud.com.cn` |
| `icloud_client_id` | iCloud Web 公共 Client ID，通常不用修改 |
| `update_enabled` | 是否启用面板“检测更新/在线更新”，默认 `true` |
| `update_repository` | 未配置 manifest 时读取的 GitHub 仓库，默认 `biubiubiu125/iCloud-Privacy-Mail` |
| `update_manifest_url` | 可选的更新 manifest 地址；配置后优先按 manifest 选择当前系统架构的二进制和 sha256 |
| `update_asset_name` | 可选的发布资产文件名；不填时自动匹配当前 `os/arch` |

示例：

```json
{
  "host": "127.0.0.1",
  "port": 8787,
  "data_path": "/opt/icloud-privacy-mail/data/state.json",
  "api_key": "CHANGE_ME_GLOBAL_API_KEY",
  "public_base_url": "https://www.example.com",
  "icloud_default_host": "www.icloud.com.cn",
  "icloud_client_id": "d39ba9916b7251055b22c7f910e2ea796ee65e98b2ddecea8f5dde8d9d1a815d",
  "update_enabled": true,
  "update_repository": "biubiubiu125/iCloud-Privacy-Mail",
  "update_manifest_url": "",
  "update_asset_name": ""
}
```

> 管理面板只支持账号密码登录；旧版 Admin Key 管理入口已移除。
>
> `data_path` 是唯一真实数据源，里面包含平台用户、Apple 登录态、隐私邮箱、邮件缓存和每个邮箱的 `api_token`。部署、迁移或合并数据前必须先备份这个文件。

### 在线更新

面板顶部会显示当前版本；鼠标移到版本号上会显示最新版本号、发布时间和更新内容。管理员检测到新版本后可点击“更新”下载对应系统架构的二进制并替换当前程序，`data_path` 不会被覆盖。

在线更新默认读取 GitHub 最新 Release，并自动匹配文件名中包含当前 `GOOS/GOARCH` 的资产；Release 资产必须在 `SHA256SUMS` 中有匹配校验值。自定义 `update_manifest_url` 的匹配资产也必须提供有效的 64 位十六进制 `sha256`，否则拒绝在线替换。如果仓库还没有发布 Release，面板会退回读取 GitHub 默认分支最新 commit：当前程序编译时写入的 commit 与默认分支一致时显示已是最新源码；默认分支已有新提交但没有 Release 资产时，只提示源码有更新，不显示一键更新按钮。更稳妥的公开发布方式是配置 `update_manifest_url`，manifest 格式如下：

```json
{
  "version": "2026.07.02",
  "name": "2026.07.02",
  "notes": "修复登录态保活显示，新增在线更新检测。",
  "published_at": "2026-07-02T00:00:00Z",
  "assets": [
    {
      "name": "icloud-privacy-mail_linux_amd64",
      "os": "linux",
      "arch": "amd64",
      "url": "https://github.com/biubiubiu125/iCloud-Privacy-Mail/releases/download/2026.07.02/icloud-privacy-mail_linux_amd64",
      "sha256": "..."
    }
  ]
}
```

Linux 服务器建议使用 systemd 托管并设置 `Restart=on-failure` 或 `Restart=always`。在线更新替换二进制后会用非 0 退出码结束当前进程，交给 systemd 自动拉起新版。Windows 运行中的 exe 不支持安全自替换，面板只提供检测，不执行在线替换。

版本标签推送后，`.github/workflows/release.yml` 会自动构建 Linux amd64、Linux arm64 和 Windows amd64 裸二进制，先创建草稿 Release、上传全部资产，再发布为正式 Release。构建或上传失败时 Release 会保持草稿状态，不会被更新器选为最新版本；已有草稿 Release 可以重跑，已发布的同名 Release 不允许覆盖，修复后必须创建新的版本标签。

发布边界：

- 每次修复功能、问题或公开行为，都必须提升 `AppVersion`、提交 Git，并推送新的版本标签；Release 工作流会自动发布对应 GitHub Release。
- GitHub Release 必须上传裸二进制资产，至少包含 `icloud-privacy-mail_linux_amd64` 和对应的 `SHA256SUMS` 条目；Windows 可附带 `icloud-privacy-mail_windows_amd64.exe` 供手动下载并加入同一校验文件。
- 在线更新只读取 GitHub `latest release` 或 `update_manifest_url` 指向的最新版本，不要求用户逐个中间版本升级；从任意旧版本点击更新都会直接更新到最新 Release。
- `data_path`、`config.json`、Apple 登录态、Cookie、取码缓存和运行数据不属于 Release 资产，更新时不覆盖。

## Docker 镜像

默认分支和版本标签推送后，GitHub Actions 会构建 `linux/amd64`、`linux/arm64` 并推送到 GHCR。其他分支同样跑构建验证，但不推送到稳定标签。私有包需要先 `docker login ghcr.io`。

| 标签 | 何时更新 | 用途 |
| --- | --- | --- |
| `ghcr.io/biubiubiu125/icloud-privacy-mail:latest` | 默认分支 push | 滚动版 |
| `ghcr.io/biubiubiu125/icloud-privacy-mail:<git-tag>` | 推送版本标签 | 可回滚的发布版 |
| `ghcr.io/biubiubiu125/icloud-privacy-mail:sha-<短SHA>` | 默认分支或版本标签 | 对应某次提交 |
| 默认分支名，例如 `master` | 默认分支 push | 与 latest 同一构建 |

容器内请用拉镜像升级，不要用面板“在线更新”替换二进制。挂载的 `config.json` 里 `data_path` 必须指向容器内 `/app/data/state.json` 或相对路径 `data/state.json`，不要写成宿主机 `/opt/...` 路径。

```powershell
docker pull ghcr.io/biubiubiu125/icloud-privacy-mail:latest
```

运行示例：

```powershell
docker run -d --name icloud-privacy-mail `
  -p 8787:8787 `
  -v ${PWD}\config.json:/app/config.json `
  -v ${PWD}\data:/app/data `
  ghcr.io/biubiubiu125/icloud-privacy-mail:latest
```

容器启动时会以 root 修复 `/app/data` 权限，把只读挂载的 `/app/config.json` 复制为 `/app/data/config.json`（仅当数据卷里还没有配置，或设置了 `IPM_CONFIG_FORCE=1`），再降权为 `ipm` 用户运行；因此配置文件和 `state.json` 都从可写的数据卷读取。自定义配置源可通过 `IPM_CONFIG_SOURCE` 指定。

## 本地运行

```powershell
go run ./cmd/panel --config .\config.json
```

打开：

```text
http://127.0.0.1:8787/login
```

首次注册的账号自动成为管理员。

## 账号与权限

| 角色 | 权限 |
| --- | --- |
| 管理员 | 查看全部用户、全部 iCloud 登录态、全部隐私邮箱；可导出全量数据 |
| 普通用户 | 只能查看和操作自己的 iCloud 登录态和隐私邮箱；只能导出自己有权访问的邮箱 API 和邮箱地址 |

所有管理接口默认要求登录后的 HttpOnly Cookie。外部取码接口推荐使用单邮箱 `api_token` 的 Bearer 请求头，也兼容全局 `api_key` 请求头；不接受全局 key 放在 URL 查询参数里。

## 使用流程

### 1. 保存旧接口登录态

1. 进入 `/login` 注册或登录平台账号。
2. 进入首页，在 `保存 Apple 登录态` 输入 Apple ID 和密码。
3. 点击 `保存旧接口登录态`。
4. 如果 Apple 要求 2FA，在受信任设备允许后，把 6 位验证码填入面板。
5. 点击 `提交旧接口验证码`。
6. 后端会完成 `2sv/trust`、`accountLogin` 和 `setup/ws/1/validate`，并把 iCloud Cookie 写入服务器 `data_path`。

密码只参与当前登录请求，不写入状态文件、不返回前端、不写日志。

同一平台账号可以保存多个 Apple 登录态。保存成功后会生成一个内部 `account_id`，后续创建、同步、导出都会用这个 `account_id` 绑定数据；前端会用 TAB 展示不同 Apple 账号，避免多个账号的邮箱混在一起。

登录时可以在“账号代理”填写单个账号专用的 HTTP/HTTPS 或 SOCKS5 代理，例如 `http://user:pass@127.0.0.1:7890` 或 `socks5://127.0.0.1:1080`。代理地址会跟 Apple 账号绑定，前端只显示脱敏结果；登录框留空会沿用该账号已保存代理，如需清除，请在账号列表点击“设置代理”并留空保存。修改代理后新登录、同步和 IMAP 连接会使用新配置。

### 2. 保存新接口登录态

这是正式面板功能，不是 live 测试专用代码。它用于保存 Apple Account 新接口登录态，后续创建 Hide My Email 时走 `account/manage/email/private/*` 新接口。

1. 进入首页，在 `保存 Apple 登录态` 输入 Apple ID 和密码。
2. 点击 `保存新接口登录态`。
3. Apple 返回需要 2FA 时，默认等待受信任设备验证码；收到 6 位验证码后填入面板。
4. 点击 `提交新接口验证码`。
5. 后端会在 2FA 通过后尝试补一次 Apple 信任确认，并保存独立的新接口登录态，包含 `scnt`、管理接口 Cookie、动态 `apiKey` 等必要字段。

新接口和旧 iCloud Web 登录态分别保存在同一个 Apple 账号记录的 `login_states` 中：

- `icloud_web`：旧 Hide My Email/iCloud 邮件接口使用，每小时约 5 个创建额度。
- `apple_account`：Apple Account 管理接口使用，每小时约 20 个创建额度。

创建邮箱时，后端会优先使用 `apple_account` 新接口；如果账号只有旧 `icloud_web` 登录态，则仍可按旧接口创建。两种登录态互不覆盖，账号数据、邮箱归属和 API 地址仍沿用原来的保存方式。两种登录态都保存后可以一起创建：新接口每小时约 20 个，旧接口每小时约 5 个，合计约 25 个/小时。

新接口的 `account/manage` 管理态和浏览器里的 “Remember me” 不等同于旧 iCloud Web 的长效 Cookie。Apple Account 管理接口返回的是短期活动窗口，后端会按 Apple 返回的 TTL 到期时间刷新 `scnt`、Cookie 和 `apiKey`；刷新成功后才写回状态文件，非 2xx 失败响应不会覆盖已保存的 `scnt` 或 Cookie。旧接口之所以更长效，是因为它额外完成 `2sv/trust`、`accountLogin` 的 `extended_login` 交换，并保存 iCloud WebServices Cookie。

新接口保活默认约 4 分钟一轮，整轮超时 60 秒（从真正请求 Apple 时起算，单次请求不再另截 30 秒）。检测登录态时新接口、旧接口、取码分开计时，互不挤占。新接口创建/删除/同步列表同样不截 30 秒单次请求，整轮 120 秒；列表 HTML 401/403 会先刷新再试。遇到 419、空响应或带 `service_errors` 的 401/403 会先预热门户、清空 `scnt` 再刷管理态。HTML 401/403 也会尝试自救，自救仍失败才计入失败次数；纯 500/超时只推迟下一轮。检测暂时失败时芯片不会显示成完全正常，但仍留在保活队列；间隔内再点检测仍会真实打 Apple。同一账号取码或旧接口仍正常时，顶层文案会写成部分正常。创建/删除遇到 HTML 401/403 会再刷一次管理态。刷新到一半的 Cookie 会写回。失败次数按保活轮次累加，只刷新 token / 管理页、同步列表或检测碰到瞬时错误都不会把会话踢出队列。连续 3 次认证失败才停止保活并显示“新接口保活：已停止”，中间失败显示“重试中”。保活重试中或已停止时，创建会先刷新管理态。这只能尽量续上短期管理态，不能保证超过 Apple 硬超时后仍在线；真正失效后仍需重新走新接口登录。

排障时可使用 `IPM_DEBUG_APPLE_ACCOUNT=1` 查看脱敏后的请求摘要。日志只输出 method/path、状态码、Cookie 长度和响应头指纹；响应体中的 API key、token、session、账号和邮箱字段会被脱敏，不输出完整 Cookie、`scnt`、密码或验证码。

### 3. 创建隐私邮箱

1. 登录态保存成功后，在 `创建隐私邮箱` 区域填写标签、备注，并勾选参与创建的 Apple 登录态。
2. 点击 `开始创建`；当前勾选账号会在同一次请求里同时各创建 1 个。
3. 后端优先调用 Apple Account 新接口创建邮箱；没有新接口登录态时使用旧 iCloud Hide My Email 接口。已提交但没有可确认响应、远端回滚失败或返回缺少远端 ID 时会锁定该账号的创建操作，必须先同步远端列表确认后再重试，避免新旧接口重复创建。
4. 本次结果会记录成功数量和账号级失败；某个账号失败不会阻断其他账号。
5. 每个邮箱会生成独立 API URL 和 `api_token`，token 不再拼进 URL。

定时创建只保留间隔配置，默认间隔为 `60` 分钟。没有总数和每次轮数输入，面板旁边只记录累计成功/失败数量。每次定时开始后，当前勾选账号会同时创建；若某个账号在本次定时创建里达到上限或创建失败，只会临时跳过这个账号，其他账号继续创建；直到本次参与账号都临时失败后，任务才进入等待。下一次定时开始时会重新尝试全部勾选账号。

创建结果会绑定当前 Apple 登录态：

- `account_id`：内部账号 ID，用于数据归属和导出筛选。
- `account_apple_id`：前端展示用的 Apple ID。
- `account_label`：创建时填写的标签或 Apple ID。

如果从 iCloud 同步已有 Hide My Email 地址，后端会按当前登录态写入对应 `account_id`，不会再放到“未绑定 Apple 账号”分组。首页“同步范围”会展示具备旧 iCloud Web 或 Apple Account 登录态的账号；未选账号的全局同步会并发处理所有可用的新旧接口登录态，选中具体账号时按该账号的可用来源读取列表，并保存远端 ID。同步成功确认 Apple Account 列表后，会解除该账号的待核对创建锁定。Apple Account 仍支持创建结果保存、按远端 ID 删除和邮箱 API 导出。

多账号或混合 Provider（服务来源）同步时，只要有一个账号或一个账号的部分来源失败，接口返回 HTTP `207`、`success=false`、`partial=true`、`code=icloud_sync_partial`，同时在 `results` 中保留每个账号/来源的成功数量和失败原因；前端会先保留成功同步的数据，再显示失败明细。全部来源失败时返回 `502` 和 `icloud_sync_failed`。

### 4. 同步邮件和取验证码

- 面板可手动点击 `同步邮件`。
- 服务启动后会默认启用后台取码同步器；所有 `API active`、`iCloud active` 且已保存取码登录的邮箱会自动进入同步池，不需要先访问取码 API 才开始监听。
- 后台取码同步器会为每个取码登录态维持 IMAP `IDLE` 常驻连接；监听启动时先读取当前 `UIDNEXT` 作为账号级起跑线，之后 iCloud 收到新邮件并推送 `EXISTS` 事件后，后端只同步新 UID 并写入本地库。
- 同步时优先使用取码登录态里的账号级 `IMAPLastSyncUID` 做 `UID n:*` 增量抓取；兼容旧邮箱级 `LastSyncUID`，没有 UID 游标时才按日期回看兜底。
- IMAP 连接会优先使用 TCP 公共 DNS，并以 UDP DNS、本机 resolver 和 Apple IMAP IPv4 直连兜底，减少服务器 resolver 或 DNS 53 端口偶发超时导致验证码不能及时入库的问题；直连仍使用 `imap.mail.me.com` 做 TLS SNI。
- 如果对应 Apple/iCloud 账号配置了代理，IMAP 会通过该账号代理建立连接；HTTP/HTTPS 走 CONNECT，SOCKS5 走 SOCKS 握手，都支持用户名密码认证。
- 后台同步默认 3 秒一轮作为兜底；最近被取码 API 访问过的邮箱会被排到本轮前面并立即唤醒同步器，避免 IMAP 事件漏掉或连接被 Apple 断开后长时间不入库。
- 对外取码 API 会先读取本地已同步邮件；未命中时触发后台快速补抓，普通请求默认最多等待 600ms，带 `wait_ms` 时最多可等待 30 秒，仍未命中就让调用方继续轮询。
- 后台同步器或快速补抓完成后都会写入本地状态，下一次取码轮询通常直接从本地返回验证码。
- 普通取码成功后会记录本次返回的邮件 ID；同一封验证码邮件不会被默认重复返回，避免重新发码后仍命中旧码。
- 建议调用取码 API 时带 `after=<RFC3339>`，避免拿到历史旧码。

## 对外取码 API

### 按邮箱地址取码

```http
GET /api/v1/mailboxes/{email}/code?after=<RFC3339>&keyword=OpenAI
Authorization: Bearer <mailbox_api_token>
```

### 按邮箱 ID 取码

```http
GET /api/mailboxes/{id}/code?after=<RFC3339>&keyword=OpenAI
Authorization: Bearer <mailbox_api_token>
```

参数：

| 参数 | 说明 |
| --- | --- |
| `Authorization` | 必填；推荐使用该邮箱独立 token 的 Bearer 形式；也支持 `X-API-Key`。旧版 `?key=<mailbox_key>` 仅保留兼容读取，不再由系统生成或复制 |
| `after` | 建议必填；只返回该时间之后的新验证码 |
| `keyword` | 邮件关键词，默认 `OpenAI`；也可用 `project` 作为兼容别名，只有未传 `keyword` 时生效 |
| `wait_ms` | 可选；本地未命中时最多等待后台补抓多久，最大 30000；面板复制的 API 默认带 `12000` |
| `allow_stale` | 默认 false；只有排障时才建议打开，允许同步失败后回退本地缓存旧码 |
| `cache` | 默认 false；设为 `1/true` 时只读本地缓存，允许查看已返回过的旧验证码，不触发 iCloud 同步 |

取码提速相关配置：

| 配置 | 默认值 | 说明 |
| --- | --- | --- |
| `mail_watcher_enabled` / `MAIL_WATCHER_ENABLED` | `true` | 是否启用后台取码同步器 |
| `mail_watcher_poll_ms` / `MAIL_WATCHER_POLL_MS` | `3000` | 后台取码同步器轮询间隔 |
| `mail_watcher_fetch_limit` / `MAIL_WATCHER_FETCH_LIMIT` | `8` | 后台同步每轮最多扫描最近多少个邮件线程 |
| `mail_watcher_initial_fetch_limit` / `MAIL_WATCHER_INITIAL_FETCH_LIMIT` | `20` | 兼容旧配置；实时取码监听启动后会先保存当前 UID 起跑线，不再预抓历史邮件 |
| `mail_watcher_lookback_hours` / `MAIL_WATCHER_LOOKBACK_HOURS` | `24` | 兼容旧配置；实时取码监听不再按时间回看旧邮件 |
| `public_fast_sync_wait_ms` / `PUBLIC_FAST_SYNC_WAIT_MS` | `600` | 取码 API 本地未命中后，最多等待后台快速同步多久 |
| `public_sync_min_interval_ms` / `PUBLIC_SYNC_MIN_INTERVAL_MS` | `3000` | 同一用户下 iCloud 邮件同步的最小间隔，避免前端高频轮询打满 Apple 接口 |

成功响应：

```json
{
  "success": true,
  "email": "alias@icloud.com",
  "code": "123456",
  "subject": "Your OpenAI code is 123456",
  "received_at": "2026-06-21T12:00:00+08:00",
  "message_id": "msg_000001"
}
```

未收到响应：

```json
{
  "success": false,
  "code": "no_code",
  "message": "暂未收到验证码",
  "retryable": true
}
```

## 外部自动取号 API

自动取号使用全局 `api_key`，只接受请求头：

```http
POST /api/v1/mailboxes/claim
Authorization: Bearer <api_key>
Content-Type: application/json

{
  "project": "openai",
  "purpose": "register",
  "count": 1
}
```

返回一个可用邮箱，并自动标记为 `used`，避免并发重复领取：

```json
{
  "success": true,
  "mailbox": {
    "email": "alias@icloud.com",
    "api_url": "https://www.example.com/api/v1/mailboxes/alias%40icloud.com/code",
    "api_token": "...",
    "api_active": true,
    "icloud_active": true,
    "status": "used"
  }
}
```

健康检查：

```http
GET /api/v1/health
Authorization: Bearer <api_key>
```

`success` 表示服务端 API 可访问；`icloud_active` 表示当前是否存在可用于隐私邮箱操作的登录态。服务可访问但 iCloud
登录态不可用时，接口仍返回 HTTP 200 和 `success:true`，调用方应同时检查 `icloud_active`。

## 数据保存与导出

- 服务器真实数据只保存到 `config.json` 的 `data_path`。
- 前端不显示、不修改服务器数据目录。
- `导出数据` 会触发浏览器保存文件选择框；不支持 File System Access API 的浏览器会回退为默认下载。
- `导出邮箱API` 支持 `txt/csv/tsv/jsonl`，TXT 每行 `邮箱----API URL----API Token`，CSV/TSV 为邮箱、API URL、API Token 三列，JSONL 为对应字段。
- `只导出邮箱` 支持 `txt/csv/tsv/jsonl`，所有格式均保持一行一个邮箱记录。
- 前端导出可选择 `当前 TAB 账号`、`全部登录态` 或指定 Apple 登录态。
- 邮箱池支持按 `全部`、`已导出`、`未导出` 分类显示；导出邮箱 API 后会记录导出时间并显示在邮箱行上。
- 直接导出会继承当前 TAB、账号范围、首页搜索词和导出状态筛选；批量导出只处理选中的邮箱，未选择时不会误导出全量。
- 邮箱池支持单选、当前页全选和筛选结果全选。
- 删除邮箱时可以选择只删除本地记录，或先删除 iCloud 的隐私邮箱本体，远端删除失败时会保留本地记录并返回失败明细。
- 历史上未绑定 Apple 登录态的邮箱可以通过 `POST /api/mailboxes/{id}/bind` 补绑定到同一平台用户的
  `account_id`；已经绑定其他账号的邮箱不能直接改绑，避免邮件和远端身份串号。
- 完整运行时状态导出仅管理员可用；普通用户不提供包含登录态 Cookie、IMAP 密码和代理凭据的状态文件。
- 管理员导出文件包含 iCloud Cookie、IMAP 密码、代理凭据和邮箱 API token，属于敏感文件，不要发给无关人员。

### 邮箱 API token 稳定性

每个邮箱的 API token 存在 `data_path` 的 `mailboxes[].api_token` 字段里：

- 正常重启服务、重新构建程序、更新前端或重启服务器，不会改变已有邮箱的 API token。
- 修改 `public_base_url` 只会改变复制出来的 API URL 前缀，不会改变独立 API token。
- 只有删除/重建邮箱记录、手动修改状态文件、从其他机器覆盖 `state.json`、或以后实现“重置 API token”功能时，token 才会改变。
- 如果部署时用本地 `state.json` 覆盖服务器旧数据，同邮箱的 `api_token` 可能被本地值覆盖，之前发出去的 API 地址会失效。

### 安全合并状态文件

跨机器迁移或把本地数据合并到服务器时，建议规则：

1. 先备份服务器当前 `state.json`。
2. 以邮箱地址 `email` 作为唯一匹配键。
3. 服务器已有的邮箱记录必须优先保留服务器侧 `api_token`。
4. 本地只更新标签、状态、归属账号、同步时间、邮件计数等元数据。
5. 只有服务器不存在的新邮箱，才写入本地 `api_token`。
6. 合并后检查文件权限，确保服务进程能读取。

如果 token 被误覆盖，可以从部署前备份里按邮箱地址找回旧 `api_token`，再写回当前 `state.json`。

### 导出接口参数

前端按钮最终调用：

```http
POST /api/runtime/export-mailbox-apis?format=txt&account_id=<account_id>
Content-Type: application/json

{}

POST /api/runtime/export-mailbox-emails?format=txt&account_id=<account_id>
Content-Type: application/json

{}
```

参数：

| 参数 | 说明 |
| --- | --- |
| `format` | `txt`、`csv`、`tsv`、`jsonl` |
| `account_id` | 可选；只导出指定 Apple 登录态创建/同步的邮箱 |
| `owner_id` | 仅管理员可用；在账号数据管理页按平台用户过滤 |
| `ids` | 可选；逗号分隔的邮箱 ID，只导出选中的邮箱 |

普通用户即使传入别人的 `owner_id` 也不会越权，后端仍按当前登录用户的数据范围导出。

邮箱 API 和邮箱纯地址导出统一使用 `POST`，避免导出动作通过可缓存的 `GET` 请求产生状态变更。批量选择导出示例：

```http
POST /api/runtime/export-mailbox-apis?format=jsonl&account_id=<account_id>
Content-Type: application/json

{"ids":["mbx_000001","mbx_000002"]}
```

邮箱删除接口：

```http
DELETE /api/mailboxes/<mailbox_id>?delete_remote=1&confirm_unknown=1
POST /api/mailboxes/bulk-delete
Content-Type: application/json

{"ids":["mbx_000001","mbx_000002"],"delete_remote":true,"confirm_unknown":true}
```

`delete_remote=1` 或 `delete_remote:true` 会先删除 iCloud 隐私邮箱本体，再删除本地记录。若服务在上次远端删除期间中断，邮箱会显示为“远端待核对”；只有明确传入 `confirm_unknown` 后才会重试远端删除，未确认时会保留本地记录。

补绑定历史邮箱：

```http
POST /api/mailboxes/<mailbox_id>/bind
Content-Type: application/json

{"account_id":"<account_id>"}
```

绑定接口会校验邮箱和 Apple 登录态属于同一个平台用户；写入失败时不会改变本地邮箱归属。

## 服务器部署

推荐部署结构：

```text
/opt/icloud-privacy-mail/
  icloud-privacy-mail
  config.json
  data/state.json
  backups/
```

`data/state.json` 推荐只允许服务用户读写，例如：

```bash
chown -R icloud-mail:icloud-mail /opt/icloud-privacy-mail/data
chmod 700 /opt/icloud-privacy-mail/data
chmod 600 /opt/icloud-privacy-mail/data/state.json
```

如果部署后页面空白、登录态丢失或日志出现 `permission denied`，优先检查 `state.json` 的属主和权限。

构建 Linux amd64：

```powershell
$env:GOOS='linux'
$env:GOARCH='amd64'
$env:CGO_ENABLED='0'
go build -trimpath -ldflags="-s -w" -o .\dist\icloud-privacy-mail-linux-amd64 .\cmd\panel
```

systemd 示例：

```ini
[Unit]
Description=iCloud Privacy Mail
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/icloud-privacy-mail
ExecStart=/opt/icloud-privacy-mail/icloud-privacy-mail --config /opt/icloud-privacy-mail/config.json
Restart=always
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ReadWritePaths=/opt/icloud-privacy-mail

[Install]
WantedBy=multi-user.target
```

Nginx 只反代当前服务端口即可，建议开启 HTTPS：

```nginx
server {
    server_name www.example.com;

    location / {
        proxy_pass http://127.0.0.1:8787;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

发布前后建议执行：

```powershell
go test ./...
go vet ./...
go build -trimpath -o .\bin\icloud-privacy-mail.exe .\cmd\panel
```

服务器验证：

```bash
systemctl is-active icloud-privacy-mail
curl -fsS http://127.0.0.1:8787/login >/dev/null
curl -fsSI https://www.example.com/login
```

## 安全注意

- 不要提交或打包 `config.json`、`data/`、`bin/`、`captures/`。
- 不要在 URL 里放全局 `api_key`；全局 key 只放 `Authorization` 或 `X-API-Key` 请求头。
- 单邮箱 `api_token` 与 API URL 分开提供；token 泄露后仍可能读取该邮箱验证码，应按密钥保存。
- iCloud Cookie 和导出的状态文件是敏感数据，必须按账号隔离保存。
- 对外部署时务必使用 HTTPS，并限制服务器文件权限。

## 当前限制

- Apple/iCloud 网页协议可能变化；如果 Apple 风控、地区端点或接口参数变化，需要重新适配。
- 2FA pending 状态只保存在进程内；服务重启后需要重新保存登录态。
- iCloud 登录态可能过期；过期后需要重新保存登录态。
- 邮件同步依赖当前 iCloud Mail 服务地址和 Cookie。
- 账号代理当前支持 HTTP/HTTPS 和 SOCKS5；远端隐私邮箱删除依赖 iCloud Hide My Email 接口协议，建议先用真实账号做单个邮箱冒烟验证，再执行批量远端删除。
