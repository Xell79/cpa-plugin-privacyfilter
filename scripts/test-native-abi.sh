#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
build_dir="$(mktemp -d)"
cleanup() {
  rm -rf "${build_dir}"
}
trap cleanup EXIT

CGO_ENABLED=1 GOOS=linux GOARCH="$(go env GOARCH)" GOFLAGS=-mod=readonly \
  go -C "${repo_root}" build -trimpath -buildvcs=true -buildmode=c-shared \
  -ldflags '-s -w -X main.pluginVersion=0.3.0-native-test -X main.pluginRevision=native-test' \
  -o "${build_dir}/privacyfilter.so" .

readelf -d "${build_dir}/privacyfilter.so" | grep -F 'Shared library: [libc.so.6]' >/dev/null

"${CC:-cc}" -std=c11 -Wall -Wextra -Werror -Wno-unused-function \
  -I"${build_dir}" "${repo_root}/scripts/native-abi-harness.c" \
  -ldl -o "${build_dir}/native-abi-harness"

"${build_dir}/native-abi-harness" "${build_dir}/privacyfilter.so" "0.3.0-native-test"
printf '%s\n' 'native ABI harness passed'
