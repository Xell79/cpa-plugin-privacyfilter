# AGENTS.md

Instructions for coding agents working in this repository. Read this before
editing. The project language is English: code comments, docs, commit
messages, and user-facing strings.

## What this is

`privacyfilter` is a cgo shared library
(`privacyfilter.so` / `.dylib` / `.dll`) loaded by
[CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI). It redacts PII
and credentials in supported request bodies before those bodies are forwarded
to a model provider.

Redaction is irreversible. The plugin does not keep plaintext for later
restore. A request that cannot be inspected safely is terminated by default
(`on_error: block`), not forwarded.

This tree is the hardened `ahoo` fork. Do not publish it as the official
Plugin Store id `privacyfilter`. That id belongs to
`rheodev/cpa-plugin-privacyfilter` v0.2.0. Install only checksum-verified
release artifacts.

Current source version is `pluginVersion` in `main.go`. `Makefile` `VERSION`
must stay equal to it. Release CI overrides the ldflag from `main.go`; a
local `make build` uses the Makefile value.

## Layout

| Path | Role |
|---|---|
| `main.go`, `config.go`, `interceptor.go`, `redactor.go`, `reject.go`, `lifecycle.go`, `request_cache.go`, `abi.go` | Plugin root (`package main`): config, intercept, redact, cache, C ABI |
| `ml_assist.go` | Optional second-opinion scorer. Off by default |
| `payload/` | JSON scan and byte-preserving string replace. No policy |
| `walker/` | Protocol walkers. Selects mutable strings. No detection |
| `internal/privacyengine/` | PII, entropy, credential-field, and Gitleaks-style detection |
| `rules/gitleaks.toml` | Pinned embedded rules snapshot. Do not edit by hand |
| `scripts/` | Rule update check and native ABI test |
| `scripts/official-host/` | Host harness. Not part of the `.so` |
| `.github/` | Release workflow and packaging |

Do not add a new root package casually. The plugin is `package main` built
with `-buildmode=c-shared`.

## Request path

1. Host calls `PrivacyFilterPluginCall` (`abi.go`). Bodies over 64 MiB are
   rejected before copy. Panics become a terminate envelope, not a host crash.
2. `interceptor.go` skips only when `skip_models` or `skip_formats` matches.
   Those are explicit bypasses.
3. `walker` classifies every string in a known protocol object as sanitizable,
   opaque, or unsupported. Unsupported shapes fail closed (422).
4. `privacyengine.Redact` finds spans. The request renderer replaces them with
   typed placeholders. Equal values share one label inside one request;
   distinct values of the same kind are numbered (`[SECRET]`, `[SECRET#2]`).
5. Default labels are `[EMAIL]`, `[PHONE]`, `[ID]`, `[CARD]`, `[IP]`,
   `[SECRET]`. Overrides come from YAML `replacements` and are checked so a
   label is not itself a secret.
6. Limits map to HTTP 413. Unknown or ambiguous shapes map to 422. Admission
   exhaustion, deadline, and panic map to 503.

`ml_assist` runs only when the engine reported zero findings and the feature
is enabled. `audit` counts `ml_flagged` and does not change text. `enforce`
replaces the **entire** text node with one `[SECRET]`, not the offending
span. Leave it disabled unless that whole-node behavior is intended.

## Detection notes

English secrets are found by `internal/privacyengine`, not by `ml_assist`:

- Keyword context: `password`, `secret`, `token`, `api key`, `bearer`, and
  the same idea written with the Chinese keywords that sit in the same
  regexes.
- Pinned Gitleaks rules for known token shapes (`ghp_`, `AKIA`, `sk_live_`,
  private keys, and the rest of the loaded snapshot).
- High-entropy tokens of at least 20 bytes.
- Whole-value redaction of exact credential field names inside structured
  tool input/output (`api_key`, `password`, `token`, `secret`, …). `AK` and
  `SK` match only as the immediate key.

Chinese keywords in `secrets.go` and Chinese substrings in `ml_assist.go`
are detector features. Do not delete them to "translate the project". Do not
add new Chinese (or any other language) to comments, README, errors, or
placeholders. User-facing and agent-facing text stays English.

`testdata/ml_parity.json` and the Chinese sentences in `ml_assist_test.go`
are frozen against the embedded model. Changing those strings changes scores.
Do not rewrite them for style.

## Invariants

- Never log matched secrets, request bodies, or raw error text from a scan.
  Logs may carry counts, constant reason codes, and allowlisted schema paths.
  Unknown object keys in diagnostics render as `<redacted>`.
- `Finding` stores kind, rule id, and byte offsets only. No plaintext field.
- JSON replace must keep untouched bytes identical: whitespace, key order,
  duplicate keys, escapes, numbers.
- Object keys are never rewritten.
- Empty `gitleaks_toml` always means the embedded snapshot. Do not look for a
  sidecar file.
- Custom TOML requires an explicit `gitleaks_mode` of `extend` or `replace`
  when you need that behavior. Omitted mode with a path is legacy replace.
- `rules/gitleaks.toml` is pinned. Update only through
  `./scripts/update-rules.sh`. Registration fails if the bytes or the
  compatibility report drift.
- Zero config limits select safe defaults. There is no "unlimited" value.
  Do not raise a hard maximum to make a test pass.
- `sanitizeJSONText` and `sanitizeJSONTextWithLimits` exist for tests of
  encoded-JSON limit mapping. The live walk uses
  `sanitizeJSONTextWithBudget`. Do not delete the wrappers without moving
  those tests onto the live path.
- Request-cache entries store a SHA-256 and opaque renderer state, never the
  body. A change of revision, source format, or model drops the entry.

## Build and test

CGO is required for the shared library. Unit tests of the Go packages do not
need a host.

```bash
make build
gofmt -w $(git ls-files '*.go')
go test ./...
go test -race ./...
./scripts/update-rules.sh --check
```

`make build` writes `dist/staging/<goos>-<goarch>/privacyfilter.<ext>` and
deletes the generated C header. `dist/` is gitignored.

Do not hand-edit generated headers. Do not commit `*.so`, `*.dylib`, or
`*.dll`.

Release builds are CI-only: pinned toolchain image, five targets, immutable
GitHub Release, no `--clobber`. Do not tag a release from a dirty tree. If
you bump `pluginVersion`, bump `Makefile` `VERSION` in the same change.

## Local files

These stay untracked (see `.gitignore`):

- `.kilo/`, `.claude/`, `.cursor/`, other agent directories
- `security_best_practices_report.md` and other local review notes

Do not add plans, chat exports, or audit notes to the repo.

## Change rules

- Match existing style. Comments explain a non-obvious invariant, not the
  next line.
- Keep new errors free of request content.
- A behavior change needs a test next to the package that owns it.
- Do not weaken fail-closed defaults (`mode: redact`, `on_error: block`,
  `ml_assist.enabled: false`) to make a fixture pass.
- Do not retarget the module path or claim the Plugin Store id.
- Third-party provenance lives in `LICENSE`, `NOTICE`, and
  `THIRD_PARTY_LICENSES.md`. Update the license report when dependencies
  change; do not invent copyright lines.
