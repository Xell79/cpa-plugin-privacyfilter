#!/usr/bin/env python3
# SPDX-License-Identifier: MIT

import argparse
import hashlib
import json
import re
import zipfile
from pathlib import Path

PLUGIN_ID = "privacyfilter"
REPOSITORY = "https://github.com/ahoo/cpa-plugin-privacyfilter"
RULE_SOURCE_COMMIT = "6eaad039603a4de39fddd1cf5f727391efe9974e"
RULE_SHA256 = "e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf"
ABI_VERSION = 1
RPC_SCHEMA_VERSION = 2
EXPECTED_TARGETS = (
    ("darwin", "amd64", "dylib"),
    ("darwin", "arm64", "dylib"),
    ("linux", "amd64", "so"),
    ("linux", "arm64", "so"),
    ("windows", "amd64", "dll"),
)
DOCUMENTS = ("LICENSE", "NOTICE", "THIRD_PARTY_LICENSES.md")
SOURCE_GATES = (
    "gofmt",
    "git diff --check",
    "go mod verify",
    "go mod tidy clean-diff",
    "go test ./...",
    "go test ./.github/scripts",
    "go vet ./...",
    "go vet ./.github/scripts",
    "go test -race ./...",
    "go test ./... -count=2",
    "payload and engine bounded fuzz regressions",
    "native C ABI harness",
    "Linux RSS bound",
    "embedded rule hash and compatibility",
    "linked-license report",
    "deterministic package tests",
    "exact official Host integration",
)
INTEGRATION_SCHEMA_VERSION = 1
INTEGRATION_TOP_LEVEL_KEYS = frozenset(
    (
        "schema_version",
        "source_revision",
        "official_host",
        "plugin",
        "harness",
        "assertions",
        "no_stanza",
        "explicit",
        "host_log_files_scanned",
    )
)
OFFICIAL_HOST_KEYS = frozenset(("image_reference", "image_digest", "version", "commit", "build_date"))
INTEGRATION_PLUGIN_KEYS = frozenset(("id", "version", "library_sha256"))
HARNESS_KEYS = frozenset(("go_sha256", "order_probe_sha256", "run_script_sha256"))
INTEGRATION_ASSERTION_KEYS = frozenset(
    (
        "artifact_abi_initialized",
        "exact_image_digest_verified",
        "isolated_internal_network",
        "production_mounts_absent",
        "synthetic_marker_absent_from_host_logs",
    )
)
NO_STANZA_KEYS = frozenset(
    (
        "plugins_enabled",
        "discovered",
        "not_configured",
        "not_registered",
        "disabled",
        "not_effective",
        "metadata_absent",
        "only_candidate_id",
    )
)
EXPLICIT_KEYS = frozenset(
    (
        "all_configured",
        "all_registered",
        "all_enabled",
        "all_effective",
        "metadata_exact",
        "config_fields_exact",
        "priorities_exact",
        "successful_forward",
        "before_auth_ordered",
        "after_auth_ordered",
        "privacyfilter_last",
        "value_redacted",
        "marker_not_forwarded",
        "success_state_valid",
        "responses_lite_forward",
        "responses_lite_redacted",
        "reasoning_replay_forward",
        "reasoning_replay_preserved",
        "active_termination",
        "blocked_not_forwarded",
    )
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical_library(goos: str, extension: str) -> str:
    expected = {"linux": "so", "darwin": "dylib", "windows": "dll"}
    if expected.get(goos) != extension:
        raise SystemExit(f"invalid extension {extension!r} for {goos}")
    return f"{PLUGIN_ID}.{extension}"


def require_version(value: str) -> None:
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", value):
        raise SystemExit("release version must be exact major.minor.patch")


def require_revision(value: str) -> None:
    if not re.fullmatch(r"[0-9a-f]{40}", value):
        raise SystemExit("source revision must be a lowercase 40-character commit")


def write_json_exclusive(path: Path, value) -> None:
    data = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    try:
        with path.open("xb") as stream:
            stream.write(data)
    except FileExistsError as error:
        raise SystemExit(f"refusing to replace existing file: {path}") from error


def build_metadata(args) -> None:
    require_version(args.version)
    require_revision(args.revision)
    target = (args.goos, args.goarch, args.extension)
    if target not in EXPECTED_TARGETS:
        raise SystemExit(f"unexpected release target: {target}")
    archive = args.archive.resolve()
    library = args.library.resolve()
    if not archive.is_file() or not library.is_file():
        raise SystemExit("archive and library must be regular files")
    expected_archive = f"{PLUGIN_ID}_{args.version}_{args.goos}_{args.goarch}.zip"
    if archive.name != expected_archive:
        raise SystemExit(f"archive name mismatch: {archive.name}")
    library_name = canonical_library(args.goos, args.extension)
    metadata = {
        "schema_version": 1,
        "plugin": {
            "id": PLUGIN_ID,
            "version": args.version,
            "abi_version": ABI_VERSION,
            "rpc_schema_version": RPC_SCHEMA_VERSION,
        },
        "source": {"repository": REPOSITORY, "commit": args.revision},
        "embedded_rules": {
            "repository": "https://github.com/gitleaks/gitleaks",
            "commit": RULE_SOURCE_COMMIT,
            "path": "config/gitleaks.toml",
            "sha256": RULE_SHA256,
        },
        "target": {"goos": args.goos, "goarch": args.goarch},
        "toolchain": {
            "go_version": args.go_version,
            "runner_image": args.runner_image,
            "builder_image": args.builder_image,
        },
        "artifact": {
            "archive": {"name": archive.name, "sha256": sha256_file(archive)},
            "library": {"name": library_name, "sha256": sha256_file(library)},
        },
        "verification": {
            "registration": True,
            "source_gates_dependency": True,
        },
    }
    write_json_exclusive(args.output, metadata)


def _is_sha256_hex(value) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _is_image_digest(value) -> bool:
    return isinstance(value, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None


def _is_nonempty_token(value) -> bool:
    return isinstance(value, str) and bool(value) and not any(char.isspace() for char in value)


def _require_true_assertions(mapping, expected_keys) -> None:
    if not isinstance(mapping, dict) or set(mapping.keys()) != set(expected_keys):
        raise SystemExit("integration report assertion shape mismatch")
    for item in mapping.values():
        if item is not True:
            raise SystemExit("integration report assertion failed")


def validate_integration_report(report, version: str, revision: str, library_sha256: str):
    if not isinstance(report, dict) or set(report.keys()) != set(INTEGRATION_TOP_LEVEL_KEYS):
        raise SystemExit("integration report shape mismatch")
    if report.get("schema_version") != INTEGRATION_SCHEMA_VERSION:
        raise SystemExit("integration report schema mismatch")
    if report.get("source_revision") != revision:
        raise SystemExit("integration report source revision mismatch")

    official_host = report.get("official_host")
    if not isinstance(official_host, dict) or set(official_host.keys()) != set(OFFICIAL_HOST_KEYS):
        raise SystemExit("integration report Host identity mismatch")
    if not _is_nonempty_token(official_host.get("image_reference")):
        raise SystemExit("integration report Host identity mismatch")
    if not _is_image_digest(official_host.get("image_digest")):
        raise SystemExit("integration report Host identity mismatch")
    if re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", official_host.get("version") or "") is None:
        raise SystemExit("integration report Host identity mismatch")
    if re.fullmatch(r"[0-9a-f]{7,40}", official_host.get("commit") or "") is None:
        raise SystemExit("integration report Host identity mismatch")
    if re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", official_host.get("build_date") or "") is None:
        raise SystemExit("integration report Host identity mismatch")

    plugin = report.get("plugin")
    if not isinstance(plugin, dict) or set(plugin.keys()) != set(INTEGRATION_PLUGIN_KEYS):
        raise SystemExit("integration report plugin identity mismatch")
    if plugin.get("id") != PLUGIN_ID or plugin.get("version") != version:
        raise SystemExit("integration report plugin identity mismatch")
    if not _is_sha256_hex(plugin.get("library_sha256")):
        raise SystemExit("integration report plugin identity mismatch")
    if plugin.get("library_sha256") != library_sha256:
        raise SystemExit("integration report library checksum mismatch")

    harness = report.get("harness")
    if not isinstance(harness, dict) or set(harness.keys()) != set(HARNESS_KEYS):
        raise SystemExit("integration report harness shape mismatch")
    for item in harness.values():
        if not _is_sha256_hex(item):
            raise SystemExit("integration report harness shape mismatch")

    _require_true_assertions(report.get("assertions"), INTEGRATION_ASSERTION_KEYS)
    _require_true_assertions(report.get("no_stanza"), NO_STANZA_KEYS)
    _require_true_assertions(report.get("explicit"), EXPLICIT_KEYS)

    scanned = report.get("host_log_files_scanned")
    if isinstance(scanned, bool) or not isinstance(scanned, int) or scanned < 2:
        raise SystemExit("integration report log count mismatch")

    return {
        "schema_version": INTEGRATION_SCHEMA_VERSION,
        "source_revision": revision,
        "official_host": {
            "image_reference": official_host["image_reference"],
            "image_digest": official_host["image_digest"],
            "version": official_host["version"],
            "commit": official_host["commit"],
            "build_date": official_host["build_date"],
        },
        "plugin": {
            "id": PLUGIN_ID,
            "version": version,
            "library_sha256": library_sha256,
        },
        "harness": {
            "go_sha256": harness["go_sha256"],
            "order_probe_sha256": harness["order_probe_sha256"],
            "run_script_sha256": harness["run_script_sha256"],
        },
        "assertions": {key: True for key in sorted(INTEGRATION_ASSERTION_KEYS)},
        "no_stanza": {key: True for key in sorted(NO_STANZA_KEYS)},
        "explicit": {key: True for key in sorted(EXPLICIT_KEYS)},
        "host_log_files_scanned": scanned,
    }


def load_integration_report(path: Path, version: str, revision: str, library_sha256: str):
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise SystemExit("integration report is missing") from error
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as error:
        raise SystemExit("integration report is malformed") from error
    return validate_integration_report(report, version, revision, library_sha256)


def validate_archive(input_dir: Path, build) -> None:
    artifact = build["artifact"]
    archive_info = artifact["archive"]
    library_info = artifact["library"]
    archive = input_dir / archive_info["name"]
    if not archive.is_file() or sha256_file(archive) != archive_info["sha256"]:
        raise SystemExit(f"archive checksum mismatch: {archive.name}")
    with zipfile.ZipFile(archive) as bundle:
        entries = bundle.infolist()
        if len(entries) != 1 or entries[0].filename != library_info["name"]:
            raise SystemExit(f"archive layout mismatch: {archive.name}")
        entry = entries[0]
        if entry.date_time != (1980, 1, 1, 0, 0, 0):
            raise SystemExit(f"archive timestamp mismatch: {archive.name}")
        if (entry.external_attr >> 16) & 0o777 != 0o755:
            raise SystemExit(f"archive mode mismatch: {archive.name}")
        data = bundle.read(entry)
        if hashlib.sha256(data).hexdigest() != library_info["sha256"]:
            raise SystemExit(f"library checksum mismatch: {archive.name}")


def assemble_manifest(args) -> None:
    require_version(args.version)
    require_revision(args.revision)
    input_dir = args.input_dir.resolve()
    paths = sorted(input_dir.glob("build-metadata_*.json"))
    if len(paths) != len(EXPECTED_TARGETS):
        raise SystemExit(f"expected {len(EXPECTED_TARGETS)} build metadata files, found {len(paths)}")
    builds = [json.loads(path.read_text(encoding="utf-8")) for path in paths]
    expected_pairs = {(goos, goarch) for goos, goarch, _extension in EXPECTED_TARGETS}
    actual_pairs = {(item["target"]["goos"], item["target"]["goarch"]) for item in builds}
    if actual_pairs != expected_pairs or len(actual_pairs) != len(builds):
        raise SystemExit("release target set mismatch")

    for build in builds:
        if build.get("schema_version") != 1:
            raise SystemExit("build metadata schema mismatch")
        if build.get("plugin") != {
            "id": PLUGIN_ID,
            "version": args.version,
            "abi_version": ABI_VERSION,
            "rpc_schema_version": RPC_SCHEMA_VERSION,
        }:
            raise SystemExit("plugin identity mismatch across build metadata")
        if build.get("source") != {"repository": REPOSITORY, "commit": args.revision}:
            raise SystemExit("source identity mismatch across build metadata")
        rules = build.get("embedded_rules", {})
        if rules.get("commit") != RULE_SOURCE_COMMIT or rules.get("sha256") != RULE_SHA256:
            raise SystemExit("embedded rule provenance mismatch")
        if build.get("verification") != {"registration": True, "source_gates_dependency": True}:
            raise SystemExit("build verification declaration mismatch")
        validate_archive(input_dir, build)

    documents = []
    for name in DOCUMENTS:
        path = input_dir / name
        if not path.is_file():
            raise SystemExit(f"missing release document: {name}")
        documents.append({"name": name, "sha256": sha256_file(path)})

    linux_builds = [
        build
        for build in builds
        if build.get("target") == {"goos": "linux", "goarch": "amd64"}
    ]
    if len(linux_builds) != 1:
        raise SystemExit("linux-amd64 build metadata is missing")
    linux_library_sha256 = linux_builds[0]["artifact"]["library"]["sha256"]
    if not _is_sha256_hex(linux_library_sha256):
        raise SystemExit("linux-amd64 library checksum mismatch")
    integration_path = getattr(args, "integration_report", None)
    if integration_path is None:
        raise SystemExit("integration report is missing")
    integration = load_integration_report(
        Path(integration_path), args.version, args.revision, linux_library_sha256
    )

    builds.sort(key=lambda item: (item["target"]["goos"], item["target"]["goarch"]))
    manifest = {
        "schema_version": 1,
        "plugin": {
            "id": PLUGIN_ID,
            "version": args.version,
            "abi_version": ABI_VERSION,
            "rpc_schema_version": RPC_SCHEMA_VERSION,
        },
        "source": {"repository": REPOSITORY, "commit": args.revision},
        "embedded_rules": builds[0]["embedded_rules"],
        "builds": [
            {
                "target": build["target"],
                "toolchain": build["toolchain"],
                "artifact": build["artifact"],
                "verification": build["verification"],
            }
            for build in builds
        ],
        "documents": sorted(documents, key=lambda item: item["name"]),
        "source_gates": list(SOURCE_GATES),
        "official_host_integration": integration,
    }
    write_json_exclusive(args.output, manifest)


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    commands = root.add_subparsers(dest="command", required=True)

    build = commands.add_parser("build")
    build.add_argument("--version", required=True)
    build.add_argument("--revision", required=True)
    build.add_argument("--goos", required=True)
    build.add_argument("--goarch", required=True)
    build.add_argument("--extension", required=True)
    build.add_argument("--archive", required=True, type=Path)
    build.add_argument("--library", required=True, type=Path)
    build.add_argument("--go-version", required=True)
    build.add_argument("--runner-image", required=True)
    build.add_argument("--builder-image", required=True)
    build.add_argument("--output", required=True, type=Path)
    build.set_defaults(handler=build_metadata)

    assemble = commands.add_parser("assemble")
    assemble.add_argument("--version", required=True)
    assemble.add_argument("--revision", required=True)
    assemble.add_argument("--input-dir", required=True, type=Path)
    assemble.add_argument("--integration-report", required=True, type=Path)
    assemble.add_argument("--output", required=True, type=Path)
    assemble.set_defaults(handler=assemble_manifest)
    return root


def main() -> None:
    args = parser().parse_args()
    args.handler(args)


if __name__ == "__main__":
    main()
