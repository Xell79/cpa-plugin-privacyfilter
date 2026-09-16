#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
set -euo pipefail

readonly HOST_IMAGE_REPOSITORY='eceasy/cli-proxy-api'
readonly HOST_IMAGE_DIGEST='sha256:97825da3009f98acf78b5c172fde650a5fbe7a690950a69ce6d7b535d77d4266'
readonly HOST_IMAGE="${HOST_IMAGE_REPOSITORY}@${HOST_IMAGE_DIGEST}"
readonly HOST_VERSION='v7.3.4'
readonly HOST_COMMIT='8335eac'
readonly HOST_BUILD_DATE='2026-09-15T14:07:07Z'
readonly MANAGEMENT_KEY='privacyfilter-harness-management'
readonly CLIENT_KEY='privacyfilter-harness-client'
readonly -a SENSITIVE_MARKERS=('q7z' 'replay@example.test')

library=''
version=''
revision=''
output=''
while (($# > 0)); do
  case "$1" in
    --library)
      library="${2:-}"
      shift 2
      ;;
    --version)
      version="${2:-}"
      shift 2
      ;;
    --revision)
      revision="${2:-}"
      shift 2
      ;;
    --output)
      output="${2:-}"
      shift 2
      ;;
    *)
      printf 'unknown official-Host harness argument\n' >&2
      exit 2
      ;;
  esac
done

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
if [[ -z "$library" || -z "$version" || -z "$revision" || -z "$output" ]]; then
  printf 'library, version, revision, and output are required\n' >&2
  exit 2
fi
library="$(realpath "$library")"
output="$(realpath -m "$output")"
if [[ ! -f "$library" || ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-]dev(\.[0-9a-f]{12})?)?$ || ! "$revision" =~ ^[0-9a-f]{40}$ ]]; then
  printf 'invalid official-Host harness input\n' >&2
  exit 2
fi
case "$library" in
  "$repo_root/dist/privacyfilter.so"|/home/ubuntu/workspace/cliproxyapi/*)
    printf 'refusing a forbidden plugin artifact path\n' >&2
    exit 2
    ;;
esac
if [[ -e "$output" ]]; then
  printf 'refusing to replace an existing integration report\n' >&2
  exit 2
fi
mkdir -p "$(dirname "$output")"

for command in docker go cc python3 sha256sum readelf realpath timeout; do
  command -v "$command" >/dev/null || {
    printf 'required official-Host harness command is unavailable\n' >&2
    exit 1
  }
done
if [[ "$(uname -m)" != 'x86_64' ]]; then
  printf 'official-Host harness requires Linux amd64\n' >&2
  exit 1
fi
readelf -h "$library" | grep -F 'Machine:' | grep -F 'Advanced Micro Devices X86-64' >/dev/null
readelf -d "$library" | grep -F 'Shared library: [libc.so.6]' >/dev/null

work_root="$(mktemp -d "${TMPDIR:-/tmp}/privacyfilter-official-host.XXXXXXXX")"
prefix="privacyfilter-host-${work_root##*.}"
network="${prefix}-network"
host_container="${prefix}-host"
mock_container="${prefix}-mock"
verifier_container="${prefix}-verifier"

cleanup() {
  docker rm -f "$host_container" "$mock_container" "$verifier_container" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  rm -rf "$work_root"
}
trap cleanup EXIT INT TERM

mkdir -p \
  "$work_root/bin" \
  "$work_root/no-stanza/config" \
  "$work_root/no-stanza/auth" \
  "$work_root/no-stanza/logs" \
  "$work_root/no-stanza/plugins/linux/amd64" \
  "$work_root/explicit/config" \
  "$work_root/explicit/auth" \
  "$work_root/explicit/logs" \
  "$work_root/explicit/plugins/linux/amd64" \
  "$work_root/reports"

readonly candidate_name="privacyfilter-v${version}.so"
install -m 0755 "$library" "$work_root/no-stanza/plugins/linux/amd64/$candidate_name"
install -m 0755 "$library" "$work_root/explicit/plugins/linux/amd64/$candidate_name"
go -C "$repo_root" test ./scripts/official-host/cmd/harness
CGO_ENABLED=0 go -C "$repo_root" build -trimpath \
  -o "$work_root/bin/official-host-harness" ./scripts/official-host/cmd/harness
cc -std=c11 -Wall -Wextra -Werror -fPIC -shared \
  -DPROBE_ID='"order-high"' -DPROBE_KIND=1 \
  "$repo_root/scripts/official-host/order-probe.c" \
  -o "$work_root/explicit/plugins/linux/amd64/order-high-v1.0.0.so"
cc -std=c11 -Wall -Wextra -Werror -fPIC -shared \
  -DPROBE_ID='"order-low"' -DPROBE_KIND=2 \
  "$repo_root/scripts/official-host/order-probe.c" \
  -o "$work_root/explicit/plugins/linux/amd64/order-low-v1.0.0.so"

plugin_sha256="$(sha256sum "$library" | cut -d' ' -f1)"
if ! python3 "$repo_root/.github/scripts/verify-registration.py" \
  --library "$library" --version "$version" >/dev/null 2>&1; then
  printf 'plugin ABI registration verification failed\n' >&2
  exit 1
fi

docker pull "$HOST_IMAGE" >/dev/null
repo_digests="$(docker image inspect --format '{{join .RepoDigests "\n"}}' "$HOST_IMAGE")"
grep -Fx "${HOST_IMAGE_REPOSITORY}@${HOST_IMAGE_DIGEST}" <<<"$repo_digests" >/dev/null
docker network create --internal "$network" >/dev/null

write_common_config() {
  local destination="$1"
  cat >"$destination" <<'YAML'
host: "0.0.0.0"
port: 8317
tls:
  enable: false
remote-management:
  allow-remote: true
  secret-key: "privacyfilter-harness-management"
  disable-control-panel: true
  disable-auto-update-panel: true
auth-dir: "/harness/auth"
api-keys:
  - "privacyfilter-harness-client"
debug: false
pprof:
  enable: false
logging-to-file: false
request-log: false
usage-statistics-enabled: false
error-logs-max-files: 2
request-retry: 0
YAML
}

write_common_config "$work_root/no-stanza/config/config.yaml"
cat >>"$work_root/no-stanza/config/config.yaml" <<'YAML'
plugins:
  enabled: true
  dir: "/harness/plugins"
  configs: {}
YAML

start_host() {
  local phase="$1"
  docker run -d \
    --name "$host_container" \
    --network "$network" \
    --network-alias host \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --pids-limit 256 \
    --memory 1g \
    --cpus 2 \
    --tmpfs /tmp:rw,nosuid,nodev,noexec,size=64m \
    --tmpfs /root/.cache:rw,nosuid,nodev,noexec,size=16m \
    --mount "type=bind,src=$work_root/$phase/config,dst=/harness/config" \
    --mount "type=bind,src=$work_root/$phase/auth,dst=/harness/auth" \
    --mount "type=bind,src=$work_root/$phase/logs,dst=/CLIProxyAPI/logs" \
    --mount "type=bind,src=$work_root/$phase/plugins,dst=/harness/plugins,readonly" \
    "$HOST_IMAGE" ./CLIProxyAPI --config /harness/config/config.yaml >/dev/null
}

run_verifier() {
  local mode="$1"
  local report_name="$2"
  shift 2
  if ! timeout --signal=TERM --kill-after=10s 180s docker run --rm \
    --name "$verifier_container" \
    --network "$network" \
    --user "$(id -u):$(id -g)" \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --pids-limit 64 \
    --memory 128m \
    --cpus 1 \
    --tmpfs /tmp:rw,nosuid,nodev,noexec,size=16m \
    --mount "type=bind,src=$work_root/bin/official-host-harness,dst=/harness/bin,readonly" \
    --mount "type=bind,src=$work_root/reports,dst=/harness/reports" \
    --entrypoint /harness/bin \
    "$HOST_IMAGE" \
      --mode "$mode" \
      --host-url http://host:8317 \
      --management-key "$MANAGEMENT_KEY" \
      --plugin-version "$version" \
      --plugin-sha256 "$plugin_sha256" \
      --image-reference "$HOST_IMAGE_REPOSITORY" \
      --image-digest "$HOST_IMAGE_DIGEST" \
      --host-version "$HOST_VERSION" \
      --host-commit "$HOST_COMMIT" \
      --host-build-date "$HOST_BUILD_DATE" \
      --output "/harness/reports/$report_name" \
      "$@"; then
    docker rm -f "$verifier_container" >/dev/null 2>&1 || true
    return 1
  fi
}

start_host no-stanza
if ! run_verifier verify-no-stanza no-stanza.json; then
  docker logs "$host_container" >"$work_root/no-stanza/stdout.log" 2>&1 || true
  printf 'no-stanza official Host verification failed\n' >&2
  exit 1
fi
if ! docker stop --time 10 "$host_container" >/dev/null; then
  printf 'no-stanza Host did not stop cleanly\n' >&2
  exit 1
fi
docker logs "$host_container" >"$work_root/no-stanza/stdout.log" 2>&1
docker rm "$host_container" >/dev/null

write_common_config "$work_root/explicit/config/config.yaml"
cat >>"$work_root/explicit/config/config.yaml" <<'YAML'
plugins:
  enabled: true
  dir: "/harness/plugins"
  configs:
    order-high:
      enabled: true
      priority: 50
    order-low:
      enabled: true
      priority: 1
    privacyfilter:
      enabled: true
      priority: 0
openai-compatibility:
  - name: "harness"
    base-url: "http://mock:9000/v1"
    api-key-entries:
      - api-key: "privacyfilter-harness-chat-upstream"
    models:
      - name: "mock-model"
        alias: "mock-model"
codex-api-key:
  - api-key: "privacyfilter-harness-responses-upstream"
    base-url: "http://mock:9000/v1"
    models:
      - name: "mock-model"
        alias: "mock-responses-model"
YAML

docker run -d \
  --name "$mock_container" \
  --network "$network" \
  --network-alias mock \
  --user "$(id -u):$(id -g)" \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --pids-limit 64 \
  --memory 128m \
  --cpus 1 \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,size=16m \
  --mount "type=bind,src=$work_root/bin/official-host-harness,dst=/harness/bin,readonly" \
  --entrypoint /harness/bin \
  "$HOST_IMAGE" --mode mock --listen :9000 >/dev/null
start_host explicit
if ! run_verifier verify-explicit explicit.json \
  --mock-url http://mock:9000 \
  --api-key "$CLIENT_KEY"; then
  docker logs "$host_container" >"$work_root/explicit/stdout.log" 2>&1 || true
  registered_count="$(grep -a -c -F 'pluginhost: plugin registered' "$work_root/explicit/stdout.log" || true)"
  interceptor_error_count="$(grep -a -c -F 'pluginhost: request interceptor' "$work_root/explicit/stdout.log" || true)"
  panic_count="$(grep -a -c -F 'pluginhost: plugin panic recovered' "$work_root/explicit/stdout.log" || true)"
  printf 'sanitized Host diagnostics: registered=%s interceptor_errors=%s recovered_panics=%s\n' \
    "$registered_count" "$interceptor_error_count" "$panic_count" >&2
  exit 1
fi
if ! docker stop --time 10 "$host_container" >/dev/null; then
  printf 'explicit Host did not stop cleanly\n' >&2
  exit 1
fi
docker logs "$host_container" >"$work_root/explicit/stdout.log" 2>&1
docker rm "$host_container" >/dev/null
host_container="${prefix}-removed"

log_files_scanned="$(find "$work_root/no-stanza/logs" "$work_root/explicit/logs" -type f -printf '.' | wc -c | tr -d '[:space:]')"
log_files_scanned="$((log_files_scanned + 2))"
for marker in "${SENSITIVE_MARKERS[@]}"; do
  if grep -aR -F -q -- "$marker" \
    "$work_root/no-stanza/logs" \
    "$work_root/no-stanza/stdout.log" \
    "$work_root/explicit/logs" \
    "$work_root/explicit/stdout.log"; then
    printf 'synthetic sensitive marker appeared in isolated Host logs\n' >&2
    exit 1
  fi
done

NO_STANZA_REPORT="$work_root/reports/no-stanza.json" \
EXPLICIT_REPORT="$work_root/reports/explicit.json" \
OUTPUT_REPORT="$output" \
SOURCE_REVISION="$revision" \
HARNESS_GO_SHA256="$(sha256sum "$repo_root/scripts/official-host/cmd/harness/main.go" | cut -d' ' -f1)" \
ORDER_PROBE_SHA256="$(sha256sum "$repo_root/scripts/official-host/order-probe.c" | cut -d' ' -f1)" \
RUN_SCRIPT_SHA256="$(sha256sum "$repo_root/scripts/official-host/run.sh" | cut -d' ' -f1)" \
LOG_FILES_SCANNED="$log_files_scanned" \
python3 - <<'PY'
import json
import os
from pathlib import Path

no_stanza = json.loads(Path(os.environ["NO_STANZA_REPORT"]).read_text(encoding="utf-8"))
explicit = json.loads(Path(os.environ["EXPLICIT_REPORT"]).read_text(encoding="utf-8"))
if no_stanza.get("schema_version") != 1 or explicit.get("schema_version") != 1:
    raise SystemExit("phase report schema mismatch")
if no_stanza.get("official_host") != explicit.get("official_host"):
    raise SystemExit("phase Host identity mismatch")
if no_stanza.get("plugin") != explicit.get("plugin"):
    raise SystemExit("phase plugin identity mismatch")

def require_true_booleans(value):
    if not isinstance(value, dict) or not value:
        raise SystemExit("phase assertion set is missing")
    if any(item is not True for item in value.values()):
        raise SystemExit("phase assertion failed")

require_true_booleans(no_stanza.get("no_stanza_assertions"))
require_true_booleans(explicit.get("explicit_assertions"))
report = {
    "schema_version": 1,
    "source_revision": os.environ["SOURCE_REVISION"],
    "official_host": no_stanza["official_host"],
    "plugin": no_stanza["plugin"],
    "harness": {
        "go_sha256": os.environ["HARNESS_GO_SHA256"],
        "order_probe_sha256": os.environ["ORDER_PROBE_SHA256"],
        "run_script_sha256": os.environ["RUN_SCRIPT_SHA256"],
    },
    "assertions": {
        "artifact_abi_initialized": True,
        "exact_image_digest_verified": True,
        "isolated_internal_network": True,
        "production_mounts_absent": True,
        "synthetic_marker_absent_from_host_logs": True,
    },
    "no_stanza": no_stanza["no_stanza_assertions"],
    "explicit": explicit["explicit_assertions"],
    "host_log_files_scanned": int(os.environ["LOG_FILES_SCANNED"]),
}
output = Path(os.environ["OUTPUT_REPORT"])
with output.open("xb") as stream:
    stream.write((json.dumps(report, indent=2, sort_keys=True) + "\n").encode())
PY

printf 'official Host integration passed: image=%s plugin_sha256=%s no_stanza_effective=false explicit_redaction=true active_termination=true log_marker_absent=true\n' \
  "$HOST_VERSION" "$plugin_sha256"
