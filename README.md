# CPA Plugin Privacy Filter

English | [简体中文](README.zh-CN.md)

A protocol-aware, request-side privacy filter for
[CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI). It inspects text that
will be visible to a model, redacts PII and credentials before provider egress,
and actively rejects requests it cannot inspect safely by default.

> This branch contains the v0.3 development implementation. It has been tested
> with CLIProxyAPI v7.2.157, but no public v0.3 release has been published yet.

## Security properties

- Understands OpenAI Chat Completions, OpenAI Responses, Anthropic Messages,
  Gemini GenerateContent, and Interactions request schemas.
- Inspects system, user, and assistant history plus tool/function inputs and
  outputs.
- Detects common PII and Gitleaks-style credentials, including common cloud
  access keys and secrets.
- Rewrites only selected JSON string tokens. Untouched whitespace, object order,
  duplicate keys, numeric lexemes, and values such as `9007199254740993` remain
  byte-for-byte unchanged.
- Never treats JSON object keys as sensitive values.
- Uses request-local, irreversible typed placeholders. The same value receives
  the same placeholder within a request; distinct values of one type are
  numbered.
- Defaults to `mode: redact` and `on_error: block`.
- Uses schema-2 active termination instead of returning a Go interceptor error,
  so rejected requests are not forwarded to a provider.
- Deduplicates unchanged BeforeAuth/AfterAuth scans by request ID and sanitized
  body hash, then releases state on `request.complete` with TTL/LRU fallback.
- The plugin's inspection logs contain counts and bounded metadata, not matched
  plaintext or request bodies.

## Supported request formats

`SourceFormat` matching is exact. The accepted values and selected data are:

| `SourceFormat` | Request schema | Inspected model-visible data |
|---|---|---|
| `openai` | Chat Completions | `messages[*].content`, multipart text, legacy/function tool arguments, and tool-role output |
| `openai-response` | Responses | `instructions`, `input` messages/text, prompt variables, function arguments, and function/custom-tool output |
| `claude` | Anthropic Messages | top-level `system`, message text, `tool_use.input`, and string/structured `tool_result.content` |
| `gemini` | Gemini GenerateContent | system instruction text, content text, function call arguments/responses, executable code, and execution output |
| `interactions` | Interactions | system instruction, nested input/steps/content, function arguments, and function results/output |
| `gemini-cli` | Interactions compatibility alias | the same fields as `interactions` |

Known protocol-level integrity and control fields are deliberately not rewritten:
model/role/type values, tool names and IDs, call IDs, signatures, encrypted or
signed reasoning, protocol URL/file-reference fields, tool schemas, and
binary/base64 attachment payloads.
Unrecognized protocol blocks or ambiguous control fields are rejected under the
default fail-closed policy rather than guessed.

## Detection and placeholders

The engine combines:

- email addresses;
- mainland China phone and ID-card numbers;
- Luhn-valid bank-card numbers;
- IPv4 addresses;
- contextual and high-entropy secret detection; and
- the compatible regex, keyword, entropy, capture-group, and allowlist subset of
  the pinned Gitleaks rules in `rules/gitleaks.toml`.

Default placeholders are:

| Kind | First value | Second distinct value |
|---|---|---|
| `email` | `[邮箱]` | `[邮箱#2]` |
| `phone` | `[电话]` | `[电话#2]` |
| `id_card` | `[身份证]` | `[身份证#2]` |
| `bank_card` | `[银行卡]` | `[银行卡#2]` |
| `ip` | `[IP]` | `[IP#2]` |
| `secret` | `[密钥]` | `[密钥#2]` |

Repeated occurrences of one value reuse its placeholder. Mapping state is local
to one logical request and is not reversible; the cache retains only hashes and
replacement labels, not plaintext findings.

## Requirements

- CLIProxyAPI with native plugin RPC schema 2 support; v7.2.157 is the verified
  target.
- Go 1.26+ and CGO to build from source.
- A native C toolchain for the target platform.

The native C ABI remains version 1. The plugin negotiates RPC schema 2 with a
newer host because active termination and `request.complete` are required for
the default policy.

## Build

```bash
git clone https://github.com/ahoo/cpa-plugin-privacyfilter.git
cd cpa-plugin-privacyfilter
git checkout feat/protocol-aware-privacy-filter

make build
```

The default build writes one shared library to the repository root:

- Linux/FreeBSD: `privacyfilter.so`
- macOS: `privacyfilter.dylib`
- Windows: `privacyfilter.dll`

Use `BUILD_DIR` and `VERSION` when needed:

```bash
BUILD_DIR=dist VERSION=0.3.0-dev make build
```

CGO cross-builds require an appropriate cross compiler. The GitHub workflow
builds Linux amd64/arm64, macOS amd64/arm64, Windows amd64/arm64, and FreeBSD
amd64 artifacts.

## CLIProxyAPI configuration

Place the shared library where CLIProxyAPI discovers native plugins, then enable
it in `config.yaml`. The Gitleaks snapshot is embedded, so a sidecar rule file is
optional.

A protective minimal configuration is:

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

`enabled` and `priority` are host-owned fields. CLIProxyAPI v7.2.157 also includes
them in the YAML passed to the native plugin, so the plugin accepts and ignores
them while the host enforces their meaning. A low priority such as `-1000` places
the filter late in each request-interceptor stage so earlier request mutations
are inspected before provider egress.

A complete example is:

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

      gitleaks_toml: ""            # empty: sidecar if present, otherwise embedded rules
      # gitleaks_mode: extend      # extend | replace; requires gitleaks_toml
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

      skip_models: []              # explicit break-glass bypasses
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

Configuration is strict YAML: unknown fields, invalid enum values, duplicate
blocking rule IDs, unsafe replacement strings, and multiple YAML documents make
registration fail.

### Configuration reference

| Field | Default | Meaning |
|---|---:|---|
| `mode` | `redact` | `redact` mutates requests and applies blocking rules; `audit` reports counts without mutation or rule-based rejection. Inspection errors still follow `on_error`. |
| `on_error` | `block` | `block` actively terminates malformed, unknown, unsupported, ambiguous, over-budget, or internally failed inspection. `passthrough` is an explicit fail-open bypass. |
| `gitleaks_toml` | `""` | Custom TOML path, relative to the plugin directory unless absolute. Empty uses `rules/gitleaks.toml` beside the library when present, otherwise the embedded snapshot. |
| `gitleaks_mode` | omitted | With a custom file, omitted preserves v0.2 behavior and replaces embedded rules. Set `extend` or `replace` explicitly. |
| `allow_unsupported_rules` | `false` | Reject unsupported semantics in custom rules. When true, unsupported custom rules are skipped and reported at registration. |
| `block_rule_ids` | `[]` | In redact mode, terminate with HTTP 422 when a finding retains one of these rule IDs. |
| `replacements` | typed defaults | Override `email`, `phone`, `id_card`, `bank_card`, `ip`, or `secret`. An empty string removes that value. |
| `skip_models` | `[]` | Trusted break-glass model names that bypass all inspection. Matching is case-insensitive against effective and requested model names. |
| `skip_formats` | `[]` | Trusted break-glass source formats that bypass all inspection. |
| `limits` | shown above | Positive, non-disableable work and allocation limits shared across the request. |

A configured replacement is scanned during registration. Registration fails if
the replacement itself is detected as sensitive, which prevents recursive or
misleading output.

### Custom rules

For a custom rule file:

```yaml
gitleaks_toml: custom/gitleaks.toml
gitleaks_mode: extend
allow_unsupported_rules: false
```

`extend` loads the embedded snapshot and then custom rules. `replace` loads only
the custom file. For backward compatibility, specifying `gitleaks_toml` without
`gitleaks_mode` means `replace`.

The engine intentionally implements only request-text-compatible Gitleaks
semantics. The current embedded snapshot contains 222 rules: 217 load and five
path/path-only rules are skipped with a registration compatibility report. A
custom rule with unsupported semantics fails registration unless
`allow_unsupported_rules: true` explicitly permits skipping it.

## Failure behavior

With the defaults, the plugin actively terminates and does not return a modified
request body to the executor:

| Condition | HTTP status |
|---|---:|
| Empty or malformed outer JSON | 400 |
| Unknown format, invalid/ambiguous shape, unsupported block, or malformed encoded tool arguments | 422 |
| A configured blocking rule matches | 422 |
| A size/node/depth/finding/replacement budget is exceeded | 413 |
| Internal detector/plugin failure | 503 |

Error bodies use the corresponding OpenAI-, Anthropic-, or Gemini-style envelope.
Request-derived diagnostics are intentionally generic so matched content cannot
leak through an error response. Registration/reconfiguration errors include safe
configuration and rule diagnostics so an operator can fix startup.

## Important trust boundaries and limitations

This plugin protects **provider egress from supported request text**. It is not an
end-to-end data-loss-prevention boundary.

1. **CLIProxyAPI sees the original request first.** Its HTTP middleware and
   ModelRouter run before the native `BeforeAuth` interceptor. The plugin cannot
   hide input from the host, router, or any earlier trusted in-process plugin.
2. **CLIProxyAPI v7.2.157 can retain a rejected raw body in a local forced error
   log.** The host captures the downstream body before plugin interception and
   writes non-2xx error logs even with `request-log: false`. The native response
   interceptor cannot rewrite that already captured copy. Protect access to the
   host and log directory; if local-at-rest redaction is mandatory, use a
   pre-ingress scrubber or add a pre-log redaction hook to CLIProxyAPI.
3. **Responses are not filtered.** Response JSON, streaming/SSE output, and tool
   output returning from a provider are outside this milestone.
4. **Binary and referenced content is not inspected.** Images, audio, video,
   PDFs/Office files, inline/base64 data, and remote file URLs receive no OCR or
   document extraction and are deliberately left untouched.
5. **Tool definitions are not prompt-scanned.** Tool/function arguments and
   results are covered; schema/control fields and descriptions are not rewritten.
6. **Detection is heuristic.** No regex/entropy detector can guarantee finding
   every secret or avoiding every false positive. Use blocking rules selectively
   and test representative traffic before production use.
7. `skip_models`, `skip_formats`, `on_error: passthrough`, and `mode: audit` are
   explicit security bypasses and are logged as such where applicable.

## Development and verification

```bash
go test ./...
go test -race ./...
go vet ./...
go test ./payload -run='^$' -fuzz='^FuzzScanNoPanic$' -fuzztime=30s
go test ./internal/privacyengine -run='^$' -fuzz='^FuzzNoPanic$' -fuzztime=30s
go test -bench=BenchmarkSanitizeRequestSizes -benchmem .
```

The v0.3 branch is also black-box tested with a glibc Linux/amd64 build loaded by
CLIProxyAPI v7.2.157 and a synthetic mock upstream across all five canonical
protocols. No production proxy is required for these tests.

## Credits and license

- Original plugin: [rheodev/cpa-plugin-privacyfilter](https://github.com/rheodev/cpa-plugin-privacyfilter)
- Protocol-safe JSON scanner work adapted from
  [ToS0/cpa-plugin-privacyfilter](https://github.com/ToS0/cpa-plugin-privacyfilter)
- PII and secret detection derived from
  [packyme/privacy-filter](https://github.com/packyme/privacy-filter) commit
  `64b8de3c2060`, internalized and hardened under its MIT license
- Plugin runtime: [router-for-me/CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI)

This repository is MIT licensed. See [LICENSE](LICENSE) and
[internal/privacyengine/LICENSE](internal/privacyengine/LICENSE). There is no
runtime dependency on `packyme/privacy-filter`.
