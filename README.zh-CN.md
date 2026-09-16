# CPA Plugin Privacy Filter

[English](README.md) | 简体中文

面向 [CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI) 的协议感知型请求侧隐私过滤插件。它会在受支持的请求文本发送给上游模型前，对选定的 PII 和凭证做不可逆脱敏；默认主动终止无法安全检查的请求。

> **不要安装官方 Plugin Store 中名为 `privacyfilter` 的条目。** 截至 2026-09-15，该 [Store 记录](https://github.com/router-for-me/CLIProxyAPI-Plugins-Store/blob/main/registry.json) 属于 `rheodev`，并指向他们的旧版 v0.2.0 实现。此 `ahoo` 分支不会申请另一个冲突的 Store 标识。只应安装从本仓库不可变 Release 下载并校验过 checksum 的产物。
>
> 不要安装 `v0.3.0`：其产物集虽通过了 Release gate，但发布时仓库尚未启用 Release immutability。`v0.3.1` 的发布工作流 fail closed 后仍是未发布的 draft。`v0.3.2` 是首个不可变 Release。`v0.3.3` 因扩展后的 exact-Host assertion 尚未登记到 release-manifest validator，在创建 Release 前发布 gate 主动失败。`v0.3.4` 同时包含 Responses Lite/Codex 兼容修复和对应 validator 更新；`v0.3.5` 新增经校验的 OpenRouter `reasoning_details` replay 兼容和无值拒绝诊断。只有 GitHub 将对应 Release 标记为 immutable 后，才可安装其中通过 checksum 校验的产物。不要安装源码树或开发 build；执行下方示例前，应核对精确版本和文件名。

## 安全模型

- 理解 OpenAI Chat Completions、OpenAI Responses、Anthropic Messages、Gemini GenerateContent 和 Interactions 请求结构。
- 检查协议 walker 明确分类为模型可见的 system、user、assistant/replay、工具输入/输出、工具描述和工具 schema 文本。
- 脱敏常见 PII、Gitleaks 风格密钥，以及结构化工具数据中位于精确高置信凭证字段下的短值。
- 只改写选中的 JSON 字符串值，永不改写对象键。未修改的空白、成员顺序、重复键、转义和数字字面量保持原始字节不变。
- 使用请求内不可逆占位符。同一逻辑请求中的相同值复用一个占位符，同类型不同值会编号区分。第二次 interceptor 扫描只信任本请求实际生成过的占位符。
- 为已知协议对象中的每个字符串分配一种明确处置：可脱敏内容、明确定义的不透明控制/完整性数据，或不支持。含未知字符串的扩展会 fail closed，不会被静默跳过。
- 默认使用 `mode: redact`、`on_error: block`、内嵌规则、无模型/格式绕过、无 blocking rule ID。
- 使用 RPC schema 2 主动终止。被拒绝的请求以成功的插件 RPC envelope 返回，并设置 `Terminate: true`，避免宿主因普通 interceptor error 的 fail-open 行为而继续转发。
- 日志只包含计数、常量失败类别和经过 allowlist 限定的有界 schema 路径；未知对象键显示为 `<redacted>`。插件不会记录命中值、错误详情或请求体。

这是**不可逆脱敏**，不是可恢复 tokenization。插件不会保留原始值供后续还原。

## 支持的请求格式

`SourceFormat` 必须精确匹配：

| `SourceFormat` | 请求协议 | 检查内容 |
|---|---|---|
| `openai` | Chat Completions | 消息文本、多段文本、旧版/新版函数参数、tool role 输出、函数描述和参数 schema；经校验的 OpenRouter `reasoning`/`reasoning_content`/`reasoning_details` replay 保持不透明且字节不变 |
| `openai-response` | Responses | instructions、input/replay 文本、prompt variables、Responses Lite `additional_tools`、function/custom/namespace/tool-search/web-search 定义、当前工具历史、函数描述、输入/输出 schema、text-format schema，以及编码的 Codex turn metadata |
| `claude` | Anthropic Messages | 顶层 system、消息文本、`tool_use.input`、字符串/结构化 `tool_result.content`、工具描述和 input schema |
| `gemini` | Gemini GenerateContent | system/content 文本、函数参数/结果、可执行代码/结果、display name、函数描述和参数/响应 schema |
| `interactions` | Interactions | system instruction、嵌套 input/steps/content、函数输入/输出、工具描述和 schema |
| `gemini-cli` | Interactions 兼容别名 | 与 `interactions` 相同 |

已知控制和完整性字段保持不透明，包括 model/role/type discriminator、工具名称和 ID、call ID、status、签名、加密 reasoning、经校验的 provider reasoning replay（`reasoning`、`reasoning_content` 以及 `reasoning.text`/`reasoning.summary`/`reasoning.encrypted` detail union）、二进制/base64 数据、明确定义的 URL/文件引用，以及 Codex `client_metadata` 的已知扁平传输/会话值。编码的 `x-codex-turn-metadata` 对象和新增的未知 metadata 会递归检查，而不会仅因客户端增加 telemetry 字段就返回兼容性 422；已知扁平传输 ID 保持不透明。不支持的 Responses 根级工具类型仍会被拒绝，而不是作为不透明对象转发。

### 结构化凭证字段

在已识别的结构化工具输入/输出中，精确凭证字段下的非空、非模板字符串会被整值脱敏，即使值很短或熵很低。支持的精确字段族包括：

- `AK`、`SK`、`api_key`、`api_secret`、`api_secret_key`；
- `access_key`、`access_key_id`、`secret_key`、`secret_access_key`；
- AWS access/secret key 字段、`client_secret` 和 `private_key`；
- access/API/auth/refresh/session/ID/client/secret/bearer/OAuth token 字段；
- `password`、`passwd`、`pwd`、`credential`、`secret`、`secrets` 和 `authorization`。

字段键在 64 字节上限内进行 ASCII case-fold，并把 `-` 归一化为 `_`；匹配发生在归一化之后，`apikey`、`accesskeyid` 等连续形式作为精确条目覆盖相应 camelCase 字段。`AK` 和 `SK` 只在其自身是直接字段名时触发整值处理；它们不会像较长且歧义较小的凭证字段名那样向后代字符串传播。这样会保留普通的 DynamoDB `{"SK":{"S":"..."}}` 结构，同时仍脱敏 `{"SK":"..."}`。这是精确 allowlist，不是子串匹配：`monkey`、`token_id`、`api_key_name`、`secret_name`、`client_id` 和任意 `MY_SECRET_KEY` 风格名称不会仅凭字段名触发整值规则。通用 PII/密钥 detector 仍会检查这些字段值。模板变量和已识别的 mask 占位符保持不变。

## 检测能力与占位符

检测引擎组合了：

- 邮箱地址；
- 中国大陆手机号和身份证号；
- 通过 Luhn 校验的银行卡号；
- IPv4 地址；
- 带上下文和高熵特征的密钥检测；
- 精确结构化凭证字段检测；
- pinned Gitleaks 快照中适用于请求文本的 regex、keyword、entropy、capture group 和 allowlist 语义。

默认占位符：

| 类型 | 第一个不同值 | 第二个不同值 |
|---|---|---|
| `email` | `[邮箱]` | `[邮箱#2]` |
| `phone` | `[电话]` | `[电话#2]` |
| `id_card` | `[身份证]` | `[身份证#2]` |
| `bank_card` | `[银行卡]` | `[银行卡#2]` |
| `ip` | `[IP]` | `[IP#2]` |
| `secret` | `[密钥]` | `[密钥#2]` |

请求缓存只保留哈希和替换标签，不保留命中明文或可恢复映射。

## 固定资源边界

下列 hard maximum 不能通过配置提高或关闭：

| 资源 | Hard maximum |
|---|---:|
| Native RPC envelope | 64 MiB |
| 请求体 | 32 MiB |
| JSON 深度 | 128 |
| 外层与编码 JSON 累计 value 数 | 250,000 |
| scanner/walker 保守统计的结构保留量 | 128 MiB |
| 单个解码字符串或 replacement | 8 MiB |
| Replacement 数 | 100,000 |
| 编码后 replacement 输出 | 32 MiB |
| 累计 detector 文本 | 32 MiB |
| Detector 文本节点 | 100,000 |
| Finding 数 | 4,096 |
| 并发 native scan | 4 |
| Native admission 等待 | 100 ms |
| Native 检查 deadline | 10 秒 |

受支持工具输入/输出中的 JSON 容器，无论位于标量、typed/list 文本还是原生结构化数据的字符串字段中，都会被递归检查。编码 JSON 和递归编码 JSON 与外层请求共享 JSON node、结构、detector、finding 和 replacement 预算；另外最多递归四层编码容器。Native 工作保持同步，返回请求后不会遗留 scanner goroutine。C ABI 无法传递客户端 cancellation，因此使用内部 deadline，并在有界扫描操作之间检查取消；正在执行的单次 Go 正则表达式操作无法被强制中断。

配置可以降低、但不能提高这些 hard maximum。Payload scan/replacement 限制为零时使用对应的有界默认值；detector 限制必须为正数。

## 环境要求

- 支持 native plugin ABI 1 的官方 CLIProxyAPI build。完整 fail-closed 行为要求宿主 RPC schema 不低于 2；插件会协商 schema 2。在 schema-1 宿主上，配置 `on_error: block` 或任意 `block_rule_ids` 都会导致注册失败。
- 插件使用 CLIProxyAPI SDK v7.2.157 编译。Release 必须在 manifest 中记录隔离集成 gate 使用的官方 Host image 和精确 digest，否则不得发布。
- 从源码构建需要 Go 1.26 和 CGO。
- 对应目标平台的原生 C 工具链。

## 安装

把同一个不可变 Release 的全部 asset 下载到新目录，校验完整的九项 checksum 后，再解压目标 archive 中唯一的规范根目录库文件：

```bash
sha256sum -c checksums.txt
unzip privacyfilter_0.3.5_linux_amd64.zip
```

Archive 恰好包含一个 `privacyfilter.so`（macOS 为 `.dylib`，Windows 为 `.dll`），mode 为 `0755`，ZIP 时间戳固定。Release 还包含 `release-manifest.json`、`NOTICE`、`LICENSE` 和 `THIRD_PARTY_LICENSES.md`。

只把校验过的库放入宿主 native plugin discovery 目录。不要复制本地开发 build 或历史遗留且被忽略的 `dist/privacyfilter.so`。Linux 上 Go shared library 使用 `DF_1_NODELETE` 加载，因此加载、替换或移除插件后都必须重启 CLIProxyAPI 进程。

宿主的全局 plugin subsystem 必须已启用，并且该库必须处于 effective enabled 状态。已发现但没有 config stanza 的库是否自动启用取决于宿主版本；应检查经过字段白名单投影后的 management 状态，不能假设发现即执行。本 Release gate 使用的官方 v7.3.4 精确镜像会发现但禁用未配置的库，因此该版本要求显式启用。最小宿主 stanza 为：

```yaml
plugins:
  enabled: true
  dir: "plugins"
  configs:
    privacyfilter:
      enabled: true
```

不配置插件自有选项时，privacyfilter 默认使用 `mode: redact`、`on_error: block`、内嵌规则、空 block/skip 列表和下方有界限制。`enabled` 和 `priority` 是宿主字段；其宿主默认 priority 为 `0`。运维可以调整 priority 或插件选项，但必须根据所有 request interceptor 验证实际顺序；每个 interceptor 阶段中，priority 越低越晚执行。

## 配置说明

完整的插件自有配置示例：

```yaml
mode: redact                    # redact | audit
on_error: block                 # block | passthrough

gitleaks_toml: ""              # 为空时始终使用 pinned 内嵌规则
# gitleaks_mode: extend         # extend | replace；需要 gitleaks_toml
allow_unsupported_rules: false
block_rule_ids: []

replacements:
  email: "[EMAIL]"
  phone: "[PHONE]"
  id_card: "[ID_CARD]"
  bank_card: "[BANK_CARD]"
  ip: "[IP_ADDRESS]"
  secret: "[SECRET]"

skip_models: []                 # 显式 break-glass 绕过
skip_formats: []

limits:
  max_body_bytes: 33554432
  max_depth: 128
  max_json_nodes: 250000
  max_structural_bytes: 134217728
  max_string_bytes: 8388608
  max_replacements: 100000
  max_replacement_bytes: 33554432
  max_text_bytes: 33554432
  max_text_nodes: 100000
  max_findings: 4096
```

配置使用严格 YAML 解码。未知字段、非法枚举值、重复 blocking rule ID、不安全 replacement、多份 YAML document，或超过 hard maximum 的限制都会导致注册失败。

| 字段 | 默认值 | 说明 |
|---|---:|---|
| `mode` | `redact` | 脱敏 finding。`audit` 只统计，不改写，也不执行基于 rule 的拒绝；检查错误仍遵循 `on_error`。 |
| `on_error` | `block` | 主动终止检查失败。`passthrough` 是显式 fail-open 绕过。 |
| `gitleaks_toml` | `""` | 自定义 TOML 路径。为空时始终使用内嵌规则，绝不会读取相邻 sidecar。 |
| `gitleaks_mode` | 未设置 | 指定自定义文件时，未设置保留旧版 replace 行为；也可显式设为 `extend` 或 `replace`。 |
| `allow_unsupported_rules` | `false` | 拒绝自定义规则中的不支持语义；`true` 允许跳过并明确报告。 |
| `block_rule_ids` | `[]` | Redact 模式下，命中这些精确 rule ID 时以 422 终止，而不是替换。 |
| `replacements` | 类型化默认值 | 覆盖六种 placeholder；空字符串表示删除命中值。 |
| `skip_models` / `skip_formats` | `[]` | 可信且显式的完整检查绕过。 |
| `limits` | 如上 | 请求级上限。Payload 字段为零时使用有界默认值，detector 字段必须为正；所有值都不能超过对应 hard maximum。 |

内嵌快照是 Gitleaks v8.30.0 在 commit `6eaad039603a4de39fddd1cf5f727391efe9974e` 的精确默认配置，SHA-256 为 `e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf`。其中 222 条规则可见、217 条加载；4 条 path-constrained 规则和 1 条 path-only 规则被跳过；另有 4 项 path allowlist 条件因协议文本没有文件路径而被忽略。精确的九项兼容性报告或文件字节一旦变化，注册就会失败。可运行 `scripts/update-rules.sh --check` 验证本地快照；更新命令只获取该不可变 commit，并校验预期 digest。

## 失败处理

默认 `on_error: block` 会返回主动终止响应；`on_error: passthrough` 会显式关闭检查错误终止：

| 情况 | HTTP 状态码 |
|---|---:|
| 空请求体或外层 JSON 非法 | 400 |
| 未知格式、不支持/有歧义的协议结构、编码工具 JSON 非法，或在 redact 模式命中配置的 blocking rule | 422 |
| 超过 body/depth/node/string/structural/detector/finding/replacement 限制 | 413 |
| Native admission 饱和、deadline、插件不可用/正在 quiesce、panic 或内部失败 | 503 |

错误体使用对应协议的通用 envelope，不包含命中的请求值。

## 信任边界与限制

本插件是有界的请求体 defense-in-depth 层，**不是绝对的最终 egress DLP 边界**。以下宿主顺序观察基于 SDK v7.2.157，并且必须在每个 Release manifest 所记录的精确 image 上重新验证：

1. CLIProxyAPI 的入口 middleware 和 router 会在 request interceptor 之前看到原始请求；更早执行的可信进程内插件也可以看到它。
2. 官方宿主可能在插件处理前，把被拒绝请求的原始 body 持久化到本地 forced-error log。应保护宿主和日志访问；如果本地落盘脱敏是硬性要求，应使用 pre-ingress scrubber 或宿主 pre-log hook。
3. 部分宿主 translation/normalization 发生在 request interceptor 之后。本插件只覆盖 interceptor 阶段识别到的 body，不覆盖后续 translator 新生成的文本。真正的最终 egress 保证需要宿主提供 post-translation hook，或使用独立 egress proxy。
4. 不处理模型响应、SSE/流式输出和响应侧工具输出。
5. 不解码二进制和引用内容：图片、音频、视频、PDF/Office、inline/base64 数据及远程文件不会经过 OCR 或文档提取。
6. 协议分类表是 pinned 的。新增含字符串字段在完成审查和支持前可能返回 422。
7. 检测仍是启发式的。精确凭证字段有意避免宽泛子串匹配；通用 detector 仍可能误报或漏报。
8. `skip_models`、`skip_formats`、`on_error: passthrough` 和 `mode: audit` 都是显式安全绕过。

## 构建与验证

本地 native build 仅用于 staging：

```bash
git clone https://github.com/ahoo/cpa-plugin-privacyfilter.git
cd cpa-plugin-privacyfilter
make build
# dist/staging/<goos>-<goarch>/privacyfilter.<extension>
```

Build 使用 `GOFLAGS=-mod=readonly`，并嵌入 VCS metadata、版本和源码 revision。Linux Release job 使用 `.github/workflows/build.yml` 中 pinned 的 Debian Bookworm image，不会发布源码树中的开发 ELF。

常用源码 gate：

```bash
gofmt -w $(git ls-files '*.go')
go mod verify
GOFLAGS='' go mod tidy -diff
go vet ./...
go vet ./.github/scripts
go test ./...
go test ./.github/scripts
go test -race ./...
go test ./... -count=2
python3 -m unittest discover -s .github/scripts -p 'test_*.py'
./scripts/test-native-abi.sh
./scripts/update-rules.sh --check
./.github/scripts/generate-license-report.py --check
go test ./payload -run='^$' -fuzz='^FuzzScanNoPanic$' -fuzztime=15s
go test ./internal/privacyengine -run='^$' -fuzz='^FuzzNoPanic$' -fuzztime=15s
```

Release workflow 只发布五个平台：Linux amd64/arm64、Darwin amd64/arm64 和 Windows amd64。Workflow 使用 pinned Actions，拒绝覆盖已存在的 Release，不使用 `--clobber`，并在发布前校验 tag/version/main 完全一致。

## 来源与许可证

- 原始插件及历史：[rheodev/cpa-plugin-privacyfilter](https://github.com/rheodev/cpa-plugin-privacyfilter)
- 加固分支：[ahoo/cpa-plugin-privacyfilter](https://github.com/ahoo/cpa-plugin-privacyfilter)
- 协议安全 scanner 改编：[ToS0/cpa-plugin-privacyfilter](https://github.com/ToS0/cpa-plugin-privacyfilter)
- Detector 来源：[PackyMe/privacy-filter](https://github.com/PackyMe/privacy-filter)
- 内嵌规则：[Gitleaks](https://github.com/gitleaks/gitleaks)
- Plugin SDK：[CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI)

本仓库使用 MIT 许可证。精确 provenance、版权、源码 commit 和链接依赖许可证见 [LICENSE](LICENSE)、[NOTICE](NOTICE) 和 [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md)。
