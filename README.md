# CPA Plugin Privacy Filter

English | [简体中文](README.zh-CN.md)

A protocol-aware, request-side privacy filter for
[CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI). It irreversibly
redacts selected PII and credentials before supported request text is sent to a
provider. Requests that cannot be inspected safely are actively terminated by
default.

> **Do not install the official Plugin Store entry named `privacyfilter`.** As
> of 2026-09-15, that [Store record](https://github.com/router-for-me/CLIProxyAPI-Plugins-Store/blob/main/registry.json)
> is owned by `rheodev` and resolves to their older v0.2.0 implementation. This
> `ahoo` fork deliberately does not claim a second Store identity. Install only
> a checksum-verified artifact from this repository's immutable Releases.
>
> Do not install `v0.3.0`: its artifact set passed the release gates, but it was
> published before repository release immutability was enabled. `v0.3.1` is the
> first candidate published under that policy. Install it only after GitHub marks
> the Release immutable, and only from that Release's checksum-verified artifacts.
> Never install a source-tree or development build; verify the exact version and
> filenames before following the examples below.

## Security model

- Understands OpenAI Chat Completions, OpenAI Responses, Anthropic Messages,
  Gemini GenerateContent, and Interactions request shapes.
- Inspects model-visible system, user, assistant/replay, tool input/output,
  tool-description, and tool-schema text that the supported walkers explicitly
  classify.
- Redacts common PII, Gitleaks-style secrets, and short values under exact,
  high-confidence credential fields in structured tool data.
- Rewrites only selected JSON string values. Object keys are never rewritten.
  Untouched whitespace, member order, duplicate keys, escapes, and numeric
  lexemes remain byte-for-byte unchanged.
- Uses request-local irreversible placeholders. Equal values reuse a placeholder
  inside one logical request; distinct values of the same type are numbered.
  Only placeholders actually produced by that request are trusted on a second
  interceptor pass.
- Assigns every string in a recognized protocol object one explicit disposition:
  sanitizable, enumerated opaque control/integrity data, or unsupported. Unknown
  string-bearing extensions fail closed instead of being silently skipped.
- Defaults to `mode: redact`, `on_error: block`, embedded rules, no model/format
  bypasses, and no blocking rule IDs.
- Uses RPC schema 2 active termination. A rejected request is returned as a
  successful plugin RPC envelope with `Terminate: true`, so it is not forwarded
  merely because ordinary interceptor errors are fail-open in the Host.
- Logs counts and bounded metadata only; the plugin does not log matched values
  or request bodies.

This is **irreversible redaction**, not reversible tokenization. The plugin does
not retain original values for restoration.

## Supported request formats

`SourceFormat` matching is exact:

| `SourceFormat` | Request schema | Inspected data |
|---|---|---|
| `openai` | Chat Completions | message text, multipart text, legacy/current function arguments, tool-role output, function descriptions and parameter schemas |
| `openai-response` | Responses | instructions, input/replay text, prompt variables, function/custom/MCP/shell/search/code/tool history covered by the pinned input-item union, function descriptions and input/output schemas, text-format schemas |
| `claude` | Anthropic Messages | top-level system, message text, `tool_use.input`, string/structured `tool_result.content`, tool descriptions and input schemas |
| `gemini` | Gemini GenerateContent | system/content text, function arguments/results, executable code/results, display names, function descriptions and parameter/response schemas |
| `interactions` | Interactions | system instruction, nested input/steps/content, function input/output, tool descriptions and schemas |
| `gemini-cli` | Interactions compatibility alias | same handling as `interactions` |

Known control and integrity fields remain opaque: model/role/type discriminators,
tool names and IDs, call IDs, signatures, encrypted reasoning, binary/base64
payloads, and explicitly enumerated URL/file references. Unsupported Responses
root-tool variants are rejected rather than forwarded opaquely.

### Structured credential fields

Within recognized structured tool input/output, non-empty non-template strings
under exact credential names are wholly redacted even when short or low-entropy.
Supported exact families include:

- `AK`, `SK`, `api_key`, `api_secret`, `api_secret_key`;
- `access_key`, `access_key_id`, `secret_key`, `secret_access_key`;
- AWS access/secret-key names, `client_secret`, and `private_key`;
- access/API/auth/refresh/session/ID/client/secret/bearer/OAuth token names;
- `password`, `passwd`, `pwd`, `credential`, `secret`, `secrets`, and
  `authorization`.

Keys are ASCII case-folded and `-` is normalized to `_`, within a 64-byte key
bound. Matching is exact after normalization; concatenated entries such as
`apikey` and `accesskeyid` cover their camelCase forms. `AK` and `SK` trigger
whole-value handling only as the immediate field name; unlike the longer,
less-ambiguous credential names, they do not propagate to descendant strings.
This preserves ordinary structures such as DynamoDB `{"SK":{"S":"..."}}`
while still redacting `{"SK":"..."}`. This is an exact allowlist, not
substring matching: `monkey`, `token_id`, `api_key_name`, `secret_name`,
`client_id`, and arbitrary `MY_SECRET_KEY`-style names do not trigger the
whole-field rule by name alone. Generic secret and PII detectors still inspect
their values. Template variables and recognized mask placeholders remain
unchanged.

## Detection and placeholders

The engine combines:

- email addresses;
- mainland China phone and ID-card numbers;
- Luhn-valid bank-card numbers;
- IPv4 addresses;
- contextual and high-entropy secret detection;
- exact structured credential-field detection; and
- the request-text-compatible regex, keyword, entropy, capture-group, and
  allowlist subset of the pinned Gitleaks snapshot.

Default placeholders are:

| Kind | First distinct value | Second distinct value |
|---|---|---|
| `email` | `[邮箱]` | `[邮箱#2]` |
| `phone` | `[电话]` | `[电话#2]` |
| `id_card` | `[身份证]` | `[身份证#2]` |
| `bank_card` | `[银行卡]` | `[银行卡#2]` |
| `ip` | `[IP]` | `[IP#2]` |
| `secret` | `[密钥]` | `[密钥#2]` |

The request cache retains only hashes and replacement labels. It never retains a
plaintext finding or a reversible mapping.

## Fixed resource bounds

The following hard maxima cannot be raised or disabled by configuration:

| Resource | Hard maximum |
|---|---:|
| Native RPC envelope | 64 MiB |
| Request body | 32 MiB |
| JSON depth | 128 |
| JSON values, outer and encoded JSON combined | 250,000 |
| Conservatively accounted scanner/walker structure | 128 MiB |
| One decoded string or replacement | 8 MiB |
| Replacements | 100,000 |
| Encoded replacement output | 32 MiB |
| Cumulative detector text | 32 MiB |
| Detector text nodes | 100,000 |
| Findings | 4,096 |
| Concurrent native scans | 4 |
| Native admission wait | 100 ms |
| Native inspection deadline | 10 s |

JSON containers carried by scalar, typed/list, or native structured string
fields in recognized tool input/output are inspected recursively. Encoded and
recursively encoded tool JSON shares the outer request's node, structural,
detector, finding, and replacement budgets. Recursion is additionally capped at
four nested encoded containers. Native work stays synchronous so no
scanner goroutine survives a returned request. The C ABI cannot propagate client
cancellation; it uses its internal deadline and checks cancellation between
bounded scan operations. A single in-progress Go regular-expression operation is
not forcibly interrupted.

Configuration may lower, but never raise, these hard maxima. A zero payload
scan/replacement limit selects its bounded default; detector limits must be
positive.

## Requirements

- An official CLIProxyAPI build with native plugin ABI 1. Full fail-closed
  behavior requires Host RPC schema 2 or newer; the plugin negotiates schema 2.
  On a schema-1 Host, registration fails when `on_error: block` or any
  `block_rule_ids` are configured.
- The plugin is compiled against CLIProxyAPI SDK v7.2.157. A release must not be
  published until its manifest records the exact official Host image and digest
  used by the isolated integration gate.
- Go 1.26 and CGO when building from source.
- A native C toolchain for the target platform.

## Installation

Download all assets from the same immutable Release into a fresh directory,
verify the complete nine-entry checksum set, then extract the target archive's
one canonical root library:

```bash
sha256sum -c checksums.txt
unzip privacyfilter_0.3.1_linux_amd64.zip
```

The archive contains exactly `privacyfilter.so` (`.dylib` on macOS, `.dll` on
Windows), mode `0755`, with a fixed ZIP timestamp. Release metadata also includes
`release-manifest.json`, `NOTICE`, `LICENSE`, and `THIRD_PARTY_LICENSES.md`.

Place only the verified library in the Host's native-plugin discovery directory.
Do not copy a local development build or the historical ignored
`dist/privacyfilter.so`. Loading, replacing, or removing a Go shared library
requires restarting the CLIProxyAPI process because Go shared libraries are
loaded with `DF_1_NODELETE` on Linux.

The Host's global plugin subsystem must be enabled, and the library must be
effectively enabled. Whether a discovered library without a config stanza is
enabled is Host-version-specific; verify the projected management state rather
than assuming discovery implies execution. The exact official v7.3.3 image used
by this release gate discovers but disables an unconfigured library, so it
requires explicit enablement. A minimal Host stanza is:

```yaml
plugins:
  enabled: true
  dir: "plugins"
  configs:
    privacyfilter:
      enabled: true
```

With no plugin-owned options, privacyfilter itself defaults to `mode: redact`,
`on_error: block`, embedded rules, empty block/skip lists, and the bounded limits
shown below. `enabled` and `priority` are Host-owned settings; their Host default
is priority `0`. An operator may change priority or plugin-owned options, but
should verify ordering against every other request interceptor. Lower priority
runs later in each interceptor stage.

## Configuration reference

A complete plugin-owned example is:

```yaml
mode: redact                    # redact | audit
on_error: block                 # block | passthrough

gitleaks_toml: ""              # empty always means embedded pinned rules
# gitleaks_mode: extend         # extend | replace; requires gitleaks_toml
allow_unsupported_rules: false
block_rule_ids: []

replacements:
  email: "[EMAIL]"
  phone: "[PHONE]"
  id_card: "[ID_CARD]"
  bank_card: "[BANK_CARD]"
  ip: "[IP_ADDRESS]"
  secret: "[SECRET]"

skip_models: []                 # explicit break-glass bypasses
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

Configuration uses strict YAML decoding. Unknown fields, invalid enum values,
duplicate blocking IDs, unsafe replacement strings, multiple YAML documents, or
limits above a hard maximum make registration fail.

| Field | Default | Meaning |
|---|---:|---|
| `mode` | `redact` | Redact findings. `audit` counts without mutation or rule-based rejection; inspection errors still follow `on_error`. |
| `on_error` | `block` | Actively terminate inspection failures. `passthrough` is an explicit fail-open bypass. |
| `gitleaks_toml` | `""` | Custom TOML path. Empty always uses embedded rules and never consults an adjacent sidecar. |
| `gitleaks_mode` | omitted | With a custom path, omitted preserves legacy replace behavior; otherwise explicitly `extend` or `replace`. |
| `allow_unsupported_rules` | `false` | Reject unsupported custom-rule semantics; `true` allows explicitly reported skips. |
| `block_rule_ids` | `[]` | In redact mode, terminate with 422 instead of replacing findings from these exact rule IDs. |
| `replacements` | typed defaults | Override the six placeholder kinds; empty removes the matched value. |
| `skip_models` / `skip_formats` | `[]` | Trusted, explicit inspection bypasses. |
| `limits` | values above | Request-wide bounds. Payload zeros select bounded defaults; detector limits must be positive. No value may exceed its hard maximum. |

The embedded snapshot is the exact Gitleaks v8.30.0 default configuration at
commit `6eaad039603a4de39fddd1cf5f727391efe9974e`, SHA-256
`e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf`.
It contains 222 rules: 217 load; four path-constrained rules and one path-only
rule are skipped; and four path-allowlist criteria are ignored because protocol
text has no filesystem path. Registration fails if the bytes or the exact
nine-entry compatibility report changes. Run
`scripts/update-rules.sh --check` to verify the local snapshot; the update command
fetches only that immutable commit and checks the expected digest.

## Failure behavior

With the default `on_error: block`, the plugin returns an active termination
response. `on_error: passthrough` explicitly disables error termination:

| Condition | HTTP status |
|---|---:|
| Empty or malformed outer JSON | 400 |
| Unknown format, unsupported/ambiguous protocol shape, malformed encoded tool JSON, or configured blocking rule in redact mode | 422 |
| Body/depth/node/string/structural/detector/finding/replacement limit | 413 |
| Native admission exhaustion, deadline, unavailable/quiesced plugin, panic, or internal failure | 503 |

Error bodies use protocol-appropriate generic envelopes and contain no matched
request values.

## Trust boundaries and limitations

This plugin is a bounded request-body defense-in-depth layer, **not an absolute
final-egress DLP boundary**. The Host-ordering observations below apply to SDK
v7.2.157 and must be revalidated against the exact image recorded for each
Release:

1. CLIProxyAPI's ingress middleware and router can see the raw request before the
   request interceptor runs. Earlier trusted in-process plugins can also see it.
2. The official Host can persist a rejected raw body in local forced-error logs
   before the plugin can sanitize it. Protect Host/log access. If local-at-rest
   redaction is mandatory, use a pre-ingress scrubber or a Host pre-log hook.
3. Some Host translation/normalization happens after request interception. This
   plugin covers the recognized body at its interceptor stage, not text created
   by a later translator. A true final-egress guarantee requires a Host-owned
   post-translation hook or an external egress proxy.
4. Provider responses, SSE streams, and response-side tool output are not
   filtered.
5. Binary/referenced content is not decoded: images, audio, video, PDF/Office,
   inline/base64 data, and remote files receive no OCR or document extraction.
6. Exact protocol tables are pinned. Newly introduced string-bearing fields may
   be rejected with 422 until reviewed and supported.
7. Detection remains heuristic. Exact credential-field coverage intentionally
   avoids broad substring matching; generic detectors can still have false
   positives and false negatives.
8. `skip_models`, `skip_formats`, `on_error: passthrough`, and `mode: audit` are
   explicit security bypasses.

## Build and verification

Local native builds are staging-only:

```bash
git clone https://github.com/ahoo/cpa-plugin-privacyfilter.git
cd cpa-plugin-privacyfilter
make build
# dist/staging/<goos>-<goarch>/privacyfilter.<extension>
```

`GOFLAGS=-mod=readonly`, VCS metadata, version, and source revision are embedded
in builds. Linux Release jobs use the pinned Debian Bookworm image recorded in
`.github/workflows/build.yml`; they do not publish a source-tree development ELF.

Useful source gates:

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

The release workflow publishes exactly five targets: Linux amd64/arm64, Darwin
amd64/arm64, and Windows amd64. It uses pinned Actions, refuses an existing
Release, never uses `--clobber`, and verifies tag/version/main equality before
publishing.

## Credits and license

- Original plugin and history:
  [rheodev/cpa-plugin-privacyfilter](https://github.com/rheodev/cpa-plugin-privacyfilter)
- Hardened fork: [ahoo/cpa-plugin-privacyfilter](https://github.com/ahoo/cpa-plugin-privacyfilter)
- Protocol-safe scanner adaptations:
  [ToS0/cpa-plugin-privacyfilter](https://github.com/ToS0/cpa-plugin-privacyfilter)
- Detector source: [PackyMe/privacy-filter](https://github.com/PackyMe/privacy-filter)
- Embedded rules: [Gitleaks](https://github.com/gitleaks/gitleaks)
- Plugin SDK: [CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI)

This repository is MIT licensed. See [LICENSE](LICENSE), [NOTICE](NOTICE), and
[THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md) for exact provenance,
copyrights, source commits, and linked dependency licenses.
