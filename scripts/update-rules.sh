#!/usr/bin/env bash
set -euo pipefail

readonly GITLEAKS_COMMIT='6eaad039603a4de39fddd1cf5f727391efe9974e'
readonly GITLEAKS_SHA256='e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf'
readonly GITLEAKS_URL="https://raw.githubusercontent.com/gitleaks/gitleaks/${GITLEAKS_COMMIT}/config/gitleaks.toml"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
target="${repo_root}/rules/gitleaks.toml"

verify_file() {
	local path="${1:?path is required}"
	local actual
	actual="$(sha256sum "${path}" | cut -d' ' -f1)"
	if [[ "${actual}" != "${GITLEAKS_SHA256}" ]]; then
		printf 'gitleaks rule SHA-256 mismatch: expected %s, got %s\n' "${GITLEAKS_SHA256}" "${actual}" >&2
		return 1
	fi
}

if [[ "${1:-}" == "--check" ]]; then
	verify_file "${target}"
	exit 0
fi
if [[ $# -ne 0 ]]; then
	printf 'usage: %s [--check]\n' "$0" >&2
	exit 2
fi

temporary="$(mktemp)"
trap 'rm -f "${temporary}"' EXIT
curl --fail --silent --show-error --location \
	--proto '=https' --tlsv1.2 \
	"${GITLEAKS_URL}" \
	--output "${temporary}"
verify_file "${temporary}"
if ! cmp --silent "${temporary}" "${target}"; then
	install -m 0644 "${temporary}" "${target}"
fi
verify_file "${target}"
