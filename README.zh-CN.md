# CPA Plugin Privacy Filter

[English](README.md) | 简体中文

面向 [CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI) 的协议感知型、仅请求侧隐私过滤插件。它会识别模型实际可见的文本，在请求离开本机、发往上游模型前脱敏 PII 和凭证；默认情况下，无法安全检查的请求会被主动拦截。

> 当前分支是 v0.3 开发版本，已在 CLIProxyAPI v7.2.157 上完成验证，但尚未发布公开的 v0.3 Release。

## 安全特性

- 理解 OpenAI Chat Completions、OpenAI Responses、Anthropic Messages、Gemini GenerateContent 和 Interactions 请求结构。
- 检查 system、user、assistant 历史，以及工具/函数的输入和输出。
- 识别常见 PII 和 Gitleaks 风格凭证，包括常见云厂商 AK/SK。
- 只改写协议明确选中的 JSON 字符串 token；未修改的空白、字段顺序、重复键、数字字面量以及 `9007199254740993` 这类大整数保持原始字节不变。
- JSON 对象键永远不会被当作敏感值改写。
- 使用请求内、不可逆的类型化占位符。同一请求中的相同值复用同一占位符，同类型不同值会编号区分。
- 默认配置为 `mode: redact`、`on_error: block`。
- 使用 schema 2 的主动终止响应，不依赖返回 Go interceptor error，因此被拒绝的请求不会继续发往上游。
- 根据 Request ID 和脱敏后请求体哈希去重未变化的 BeforeAuth/AfterAuth 扫描；在 `request.complete` 时释放状态，并提供 TTL/LRU 兜底。
- 插件自身的检查日志只记录数量和有界元数据，不记录命中明文或请求体。

## 支持的请求格式

`SourceFormat` 必须精确匹配。支持值和检查范围如下：

| `SourceFormat` | 请求协议 | 检查的模型可见内容 |
|---|---|---|
| `openai` | Chat Completions | `messages[*].content`、多段文本、旧版/新版函数工具参数、tool role 输出 |
| `openai-response` | Responses | `instructions`、`input` 消息与文本、prompt variables、函数参数、函数及自定义工具输出 |
| `claude` | Anthropic Messages | 顶层 `system`、消息文本、`tool_use.input`、字符串或结构化 `tool_result.content` |
| `gemini` | Gemini GenerateContent | system instruction、content 文本、函数调用参数/响应、可执行代码和执行输出 |
| `interactions` | Interactions | system instruction、嵌套 input/steps/content、函数参数和函数结果/输出 |
| `gemini-cli` | Interactions 兼容别名 | 与 `interactions` 相同 |

已知的协议级完整性字段和控制字段不会被改写，包括 model/role/type、工具名称和 ID、call ID、签名、加密或签名 reasoning、协议级 URL/文件引用、工具 schema 以及二进制/base64 附件。对于无法识别的协议 block 或有歧义的控制字段，默认 fail-closed 策略会直接拒绝，而不是猜测其含义。

## 检测能力与占位符

检测引擎组合了：

- 邮箱地址；
- 中国大陆手机号和身份证号；
- 通过 Luhn 校验的银行卡号；
- IPv4 地址；
- 带上下文和高熵特征的密钥检测；
- `rules/gitleaks.toml` 固定版本规则中，与请求文本兼容的 regex、keyword、entropy、capture group 和 allowlist 语义。

默认占位符：

| 类型 | 第一个值 | 第二个不同值 |
|---|---|---|
| `email` | `[邮箱]` | `[邮箱#2]` |
| `phone` | `[电话]` | `[电话#2]` |
| `id_card` | `[身份证]` | `[身份证#2]` |
| `bank_card` | `[银行卡]` | `[银行卡#2]` |
| `ip` | `[IP]` | `[IP#2]` |
| `secret` | `[密钥]` | `[密钥#2]` |

同一值重复出现时会复用占位符。映射只存在于一个逻辑请求内且不可逆；缓存仅保留哈希和替换标签，不保留命中明文。

## 环境要求

- 支持原生插件 RPC schema 2 的 CLIProxyAPI；已验证版本为 v7.2.157。
- 从源码构建需要 Go 1.26+ 和 CGO。
- 对应目标平台的原生 C 工具链。

原生 C ABI 仍为版本 1。插件会与新版宿主协商 RPC schema 2，因为默认策略依赖主动终止和 `request.complete`。

## 构建

```bash
git clone https://github.com/ahoo/cpa-plugin-privacyfilter.git
cd cpa-plugin-privacyfilter
git checkout feat/protocol-aware-privacy-filter

make build
```

默认在仓库根目录生成一个共享库：

- Linux/FreeBSD：`privacyfilter.so`
- macOS：`privacyfilter.dylib`
- Windows：`privacyfilter.dll`

可指定输出目录和版本：

```bash
BUILD_DIR=dist VERSION=0.3.0-dev make build
```

CGO 跨平台构建需要对应的交叉编译器。GitHub Workflow 会构建 Linux amd64/arm64、macOS amd64/arm64、Windows amd64/arm64 和 FreeBSD amd64 共七种产物。

## CLIProxyAPI 配置

把共享库放到 CLIProxyAPI 能发现原生插件的位置，然后在 `config.yaml` 中启用。Gitleaks 规则已嵌入二进制，sidecar 规则文件不是必需项。

最小保护配置：

```yaml
plugins:
  enabled: true
  dir: "plugins"
  configs:
    privacyfilter:
      enabled: true
      priority: -1000
      mode: redact
      on_error: block
```

`enabled` 和 `priority` 属于宿主字段。CLIProxyAPI v7.2.157 仍会把它们包含在传给原生插件的 YAML 中，因此插件会接受但不使用，实际语义由宿主执行。`-1000` 这样的低优先级会让过滤器在每个请求拦截阶段靠后运行，从而在 provider egress 前检查其他插件已经完成的请求修改。

完整配置示例：

```yaml
plugins:
  enabled: true
  dir: "plugins"
  configs:
    privacyfilter:
      enabled: true
      priority: -1000

      mode: redact                 # redact | audit
      on_error: block              # block | passthrough

      gitleaks_toml: ""            # 为空：优先 sidecar，否则使用内嵌规则
      # gitleaks_mode: extend      # extend | replace；设置后必须有 gitleaks_toml
      allow_unsupported_rules: false
      block_rule_ids:
        - alibaba-access-key-id

      replacements:
        email: "[EMAIL]"
        phone: "[PHONE]"
        id_card: "[ID_CARD]"
        bank_card: "[BANK_CARD]"
        ip: "[IP_ADDRESS]"
        secret: "[SECRET]"

      skip_models: []              # 显式 break-glass 绕过项
      skip_formats: []

      limits:
        max_body_bytes: 33554432
        max_depth: 256
        max_json_nodes: 1000000
        max_string_bytes: 8388608
        max_replacements: 100000
        max_replacement_bytes: 33554432
        max_text_bytes: 33554432
        max_text_nodes: 100000
        max_findings: 4096
```

配置使用严格 YAML 解析：未知字段、非法枚举值、重复的 blocking rule ID、不安全的替换字符串或多个 YAML document 都会导致插件注册失败。

### 配置项说明

| 字段 | 默认值 | 说明 |
|---|---:|---|
| `mode` | `redact` | `redact` 会修改请求并执行 blocking rules；`audit` 只统计，不改写，也不执行基于规则的拒绝。检查错误仍遵循 `on_error`。 |
| `on_error` | `block` | `block` 会主动终止格式错误、未知、不支持、有歧义、超预算或内部检查失败的请求；`passthrough` 是显式 fail-open 绕过。 |
| `gitleaks_toml` | `""` | 自定义 TOML 路径；相对路径以插件目录为基准。为空时优先读取共享库旁的 `rules/gitleaks.toml`，不存在则使用内嵌版本。 |
| `gitleaks_mode` | 未设置 | 有自定义文件时，未设置会保持 v0.2 兼容行为，即替换内嵌规则；也可显式设为 `extend` 或 `replace`。 |
| `allow_unsupported_rules` | `false` | 默认拒绝自定义规则中的不支持语义；为 true 时跳过并在注册时报告。 |
| `block_rule_ids` | `[]` | 在 redact 模式下，如果 finding 保留了列表中的 rule ID，则以 HTTP 422 拒绝请求。 |
| `replacements` | 类型化默认值 | 可覆盖 `email`、`phone`、`id_card`、`bank_card`、`ip`、`secret`；空字符串表示删除该值。 |
| `skip_models` | `[]` | 完全跳过检查的可信 break-glass 模型名，对 requested/effective model 均做大小写不敏感匹配。 |
| `skip_formats` | `[]` | 完全跳过检查的可信 break-glass 来源格式。 |
| `limits` | 如上例 | 请求级、不可关闭的正数工作量与分配上限。 |

插件注册时会先扫描自定义 replacement。如果 replacement 本身会被识别为敏感信息，注册会失败，避免递归或误导性的脱敏结果。

### 自定义规则

```yaml
gitleaks_toml: custom/gitleaks.toml
gitleaks_mode: extend
allow_unsupported_rules: false
```

`extend` 会先加载内嵌规则，再加载自定义规则；`replace` 只加载自定义文件。为兼容旧版，只设置 `gitleaks_toml` 而不设置 `gitleaks_mode` 时等价于 `replace`。

检测引擎只实现适用于请求文本的 Gitleaks 语义。当前内嵌快照共有 222 条规则，其中 217 条加载成功，5 条仅依赖 path/path-only 的规则会被跳过，并在注册兼容性报告中明确显示。自定义规则只要包含不支持语义，就会默认注册失败；只有显式设置 `allow_unsupported_rules: true` 才允许跳过。

## 失败处理

默认配置下，插件会主动终止请求，并且不会把修改后的请求体交给 executor：

| 情况 | HTTP 状态码 |
|---|---:|
| 空请求体或外层 JSON 非法 | 400 |
| 未知格式、非法/歧义结构、不支持的 block、编码工具参数 JSON 非法 | 422 |
| 命中配置的 blocking rule | 422 |
| 超过 body/node/depth/finding/replacement 等预算 | 413 |
| 检测器或插件内部错误 | 503 |

错误体会按 OpenAI、Anthropic 或 Gemini 对应协议返回。请求侧诊断信息刻意保持通用，防止命中内容通过错误响应泄漏；注册/重配置错误则会保留安全的配置与规则诊断，方便运维修正启动问题。

## 重要信任边界与限制

本插件保护的是**支持范围内请求文本的 provider egress**，不是端到端 DLP 边界。

1. **CLIProxyAPI 会先看到原始请求。** HTTP middleware 和 ModelRouter 都早于原生插件的 `BeforeAuth` interceptor 执行。插件无法向宿主、路由器或更早执行的可信进程内插件隐藏输入。
2. **CLIProxyAPI v7.2.157 可能把被拒绝请求的原始 body 留在本地强制错误日志中。** 宿主在插件执行前就捕获了下游请求体，而且即便 `request-log: false`，非 2xx 响应仍会写 error log。原生 interceptor 无法改写这份已捕获副本。必须保护宿主和日志目录；如果本地落盘脱敏是硬性要求，应在入口前先清洗，或给 CLIProxyAPI 增加 pre-log redaction hook。
3. **不处理响应。** 模型响应 JSON、SSE/流式输出，以及从上游返回的工具输出不在当前里程碑内。
4. **不解析二进制和引用内容。** 图片、音频、视频、PDF/Office、inline/base64 数据以及远程文件 URL 没有 OCR 或文档提取能力，会保持不变。
5. **不扫描工具定义。** 工具/函数的实际参数和结果已覆盖；schema/control 字段和描述不会被改写。
6. **检测是启发式的。** regex/entropy 检测无法保证找出所有密钥，也无法保证零误报。应谨慎选择 blocking rules，并用代表性流量验证后再用于生产。
7. `skip_models`、`skip_formats`、`on_error: passthrough` 和 `mode: audit` 都是显式安全绕过项，适用时会记录相应告警或模式信息。

## 开发与验证

```bash
go test ./...
go test -race ./...
go vet ./...
go test ./payload -run='^$' -fuzz='^FuzzScanNoPanic$' -fuzztime=30s
go test ./internal/privacyengine -run='^$' -fuzz='^FuzzNoPanic$' -fuzztime=30s
go test -bench=BenchmarkSanitizeRequestSizes -benchmem .
```

v0.3 分支还使用 glibc Linux/amd64 构建，在隔离的 CLIProxyAPI v7.2.157 和合成 mock upstream 上对五种规范协议做黑盒验证；无需接触生产代理。

## 来源与许可证

- 原始插件：[rheodev/cpa-plugin-privacyfilter](https://github.com/rheodev/cpa-plugin-privacyfilter)
- 协议安全 JSON scanner 改编自 [ToS0/cpa-plugin-privacyfilter](https://github.com/ToS0/cpa-plugin-privacyfilter)
- PII 和密钥检测派生自 [packyme/privacy-filter](https://github.com/packyme/privacy-filter) commit `64b8de3c2060`，已在仓库内内置并按其 MIT 许可证进行加固
- 插件运行时：[router-for-me/CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI)

本仓库使用 MIT 许可证，详见 [LICENSE](LICENSE) 和 [internal/privacyengine/LICENSE](internal/privacyengine/LICENSE)。运行时不依赖 `packyme/privacy-filter`。
