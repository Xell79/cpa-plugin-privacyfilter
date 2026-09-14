# SPDX-License-Identifier: MIT

import hashlib
import importlib.util
import json
import shutil
import tempfile
import types
import unittest
import zipfile
from pathlib import Path

SCRIPT = Path(__file__).with_name("release-manifest.py")
SPEC = importlib.util.spec_from_file_location("release_manifest", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class ReleaseManifestTest(unittest.TestCase):
    def create_input(self, root: Path):
        version = "0.3.0"
        revision = "1" * 40
        for goos, goarch, extension in MODULE.EXPECTED_TARGETS:
            library_name = f"privacyfilter.{extension}"
            library = root / f"library_{goos}_{goarch}.{extension}"
            library.write_bytes(f"{goos}/{goarch}".encode())
            archive = root / f"privacyfilter_{version}_{goos}_{goarch}.zip"
            info = zipfile.ZipInfo(library_name, (1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100755 << 16
            with zipfile.ZipFile(archive, "w") as bundle:
                bundle.writestr(info, library.read_bytes())
            args = types.SimpleNamespace(
                version=version,
                revision=revision,
                goos=goos,
                goarch=goarch,
                extension=extension,
                archive=archive,
                library=library,
                go_version="go version go1.26.0 test/test",
                runner_image="test-runner",
                builder_image="test-builder",
                output=root / f"build-metadata_{goos}_{goarch}.json",
            )
            MODULE.build_metadata(args)
        for document in MODULE.DOCUMENTS:
            (root / document).write_text(f"{document}\n", encoding="utf-8")
        return version, revision

    def create_integration_report(self, root: Path, version: str, revision: str, name="official-host-integration.json"):
        library_sha256 = hashlib.sha256(b"linux/amd64").hexdigest()
        report = {
            "schema_version": 1,
            "source_revision": revision,
            "official_host": {
                "image_reference": "test-registry/official-host",
                "image_digest": "sha256:" + "a" * 64,
                "version": "v7.3.3",
                "commit": "abc1234",
                "build_date": "2026-09-14T19:44:01Z",
            },
            "plugin": {
                "id": "privacyfilter",
                "version": version,
                "library_sha256": library_sha256,
            },
            "harness": {
                "go_sha256": "b" * 64,
                "order_probe_sha256": "c" * 64,
                "run_script_sha256": "d" * 64,
            },
            "assertions": {
                "artifact_abi_initialized": True,
                "exact_image_digest_verified": True,
                "isolated_internal_network": True,
                "production_mounts_absent": True,
                "synthetic_marker_absent_from_host_logs": True,
            },
            "no_stanza": {
                "plugins_enabled": True,
                "discovered": True,
                "not_configured": True,
                "not_registered": True,
                "disabled": True,
                "not_effective": True,
                "metadata_absent": True,
                "only_candidate_id": True,
            },
            "explicit": {
                "all_configured": True,
                "all_registered": True,
                "all_enabled": True,
                "all_effective": True,
                "metadata_exact": True,
                "config_fields_exact": True,
                "priorities_exact": True,
                "successful_forward": True,
                "before_auth_ordered": True,
                "after_auth_ordered": True,
                "privacyfilter_last": True,
                "value_redacted": True,
                "marker_not_forwarded": True,
                "success_state_valid": True,
                "active_termination": True,
                "blocked_not_forwarded": True,
            },
            "host_log_files_scanned": 2,
        }
        path = root / name
        path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return path

    def assemble(self, root: Path, output_name, integration=None):
        version = "0.3.0"
        revision = "1" * 40
        if integration is None:
            integration = self.create_integration_report(root, version, revision)
        MODULE.assemble_manifest(
            types.SimpleNamespace(
                version=version,
                revision=revision,
                input_dir=root,
                integration_report=integration,
                output=root / output_name,
            )
        )
        return root / output_name

    def mutate_integration_report(self, root: Path, version: str, revision: str, mutate, name="official-host-integration.json"):
        path = self.create_integration_report(root, version, revision, name=name)
        report = json.loads(path.read_text(encoding="utf-8"))
        mutate(report)
        path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return path

    def test_assemble_manifest_is_deterministic_and_complete(self):
        with tempfile.TemporaryDirectory() as first_name, tempfile.TemporaryDirectory() as second_name:
            first = Path(first_name)
            second = Path(second_name)
            version, revision = self.create_input(first)
            shutil.copytree(first, second, dirs_exist_ok=True)

            first_output = self.assemble(first, "release-manifest.json")
            second_output = self.assemble(second, "release-manifest.json")
            self.assertEqual(first_output.read_bytes(), second_output.read_bytes())
            manifest = json.loads(first_output.read_text(encoding="utf-8"))
            self.assertEqual(manifest["plugin"]["version"], version)
            self.assertEqual(manifest["source"]["commit"], revision)
            self.assertEqual(len(manifest["builds"]), 5)
            self.assertEqual(len(manifest["documents"]), 3)
            self.assertEqual(manifest["embedded_rules"]["sha256"], MODULE.RULE_SHA256)

    def test_assemble_records_official_host_integration(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            version, revision = self.create_input(root)
            output = self.assemble(root, "release-manifest.json")
            manifest = json.loads(output.read_text(encoding="utf-8"))
            integration = manifest["official_host_integration"]
            self.assertEqual(integration["schema_version"], 1)
            self.assertEqual(integration["source_revision"], revision)
            self.assertTrue(integration["official_host"]["image_digest"].startswith("sha256:"))
            self.assertEqual(integration["official_host"]["version"], "v7.3.3")
            self.assertEqual(integration["official_host"]["commit"], "abc1234")
            self.assertEqual(integration["official_host"]["build_date"], "2026-09-14T19:44:01Z")
            self.assertEqual(
                integration["plugin"]["library_sha256"], hashlib.sha256(b"linux/amd64").hexdigest()
            )
            self.assertEqual(integration["plugin"]["version"], version)
            self.assertTrue(all(integration["assertions"].values()))
            self.assertTrue(integration["no_stanza"]["disabled"])
            self.assertTrue(integration["no_stanza"]["not_registered"])
            for key in (
                "all_configured",
                "all_registered",
                "priorities_exact",
                "before_auth_ordered",
                "after_auth_ordered",
                "privacyfilter_last",
                "value_redacted",
                "marker_not_forwarded",
                "successful_forward",
                "success_state_valid",
                "active_termination",
                "blocked_not_forwarded",
            ):
                self.assertTrue(integration["explicit"][key])
            self.assertEqual(len(integration["harness"]), 3)
            self.assertGreaterEqual(integration["host_log_files_scanned"], 2)

    def test_assemble_rejects_missing_integration_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.create_input(root)
            with self.assertRaises(SystemExit):
                MODULE.assemble_manifest(
                    types.SimpleNamespace(
                        version="0.3.0",
                        revision="1" * 40,
                        input_dir=root,
                        integration_report=root / "does-not-exist.json",
                        output=root / "release-manifest.json",
                    )
                )

    def test_assemble_rejects_malformed_integration_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.create_input(root)
            path = root / "official-host-integration.json"
            path.write_text("{not-json", encoding="utf-8")
            with self.assertRaises(SystemExit) as context:
                self.assemble(root, "release-manifest.json", integration=path)
            self.assertNotIn("not-json", str(context.exception))

    def test_assemble_rejects_false_assertion(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            version, revision = self.create_input(root)
            path = self.mutate_integration_report(
                root, version, revision, lambda report: report["explicit"].__setitem__("active_termination", False)
            )
            with self.assertRaises(SystemExit):
                self.assemble(root, "release-manifest.json", integration=path)

    def test_assemble_rejects_false_no_stanza_assertion(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            version, revision = self.create_input(root)
            path = self.mutate_integration_report(
                root, version, revision, lambda report: report["no_stanza"].__setitem__("disabled", False)
            )
            with self.assertRaises(SystemExit):
                self.assemble(root, "release-manifest.json", integration=path)

    def test_assemble_rejects_library_checksum_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            version, revision = self.create_input(root)
            path = self.mutate_integration_report(
                root,
                version,
                revision,
                lambda report: report["plugin"].__setitem__("library_sha256", "e" * 64),
            )
            with self.assertRaises(SystemExit):
                self.assemble(root, "release-manifest.json", integration=path)

    def test_assemble_rejects_source_revision_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            version, _revision = self.create_input(root)
            path = self.mutate_integration_report(
                root,
                version,
                "2" * 40,
                lambda report: None,
            )
            with self.assertRaises(SystemExit):
                self.assemble(root, "release-manifest.json", integration=path)

    def test_assemble_rejects_plugin_version_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _version, revision = self.create_input(root)
            path = self.mutate_integration_report(
                root,
                "9.9.9",
                revision,
                lambda report: None,
            )
            with self.assertRaises(SystemExit):
                self.assemble(root, "release-manifest.json", integration=path)

    def test_assemble_rejects_host_identity_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            version, revision = self.create_input(root)
            path = self.mutate_integration_report(
                root,
                version,
                revision,
                lambda report: report["official_host"].__setitem__("image_digest", "sha256:" + "f" * 63),
            )
            with self.assertRaises(SystemExit):
                self.assemble(root, "release-manifest.json", integration=path)

    def test_assemble_rejects_extra_untrusted_shape(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            version, revision = self.create_input(root)
            marker = "untrusted-shape-marker"
            path = self.mutate_integration_report(
                root,
                version,
                revision,
                lambda report: report.__setitem__(marker, True),
            )
            with self.assertRaises(SystemExit) as context:
                self.assemble(root, "release-manifest.json", integration=path)
            self.assertNotIn(marker, str(context.exception))

    def test_assemble_rejects_small_log_count(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            version, revision = self.create_input(root)
            path = self.mutate_integration_report(
                root,
                version,
                revision,
                lambda report: report.__setitem__("host_log_files_scanned", 1),
            )
            with self.assertRaises(SystemExit):
                self.assemble(root, "release-manifest.json", integration=path)

    def test_validate_archive_rejects_wrong_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "privacyfilter_0.3.0_linux_amd64.zip"
            info = zipfile.ZipInfo("privacyfilter.so", (1980, 1, 1, 0, 0, 0))
            info.external_attr = 0o100644 << 16
            data = b"library"
            with zipfile.ZipFile(archive, "w") as bundle:
                bundle.writestr(info, data)
            build = {
                "artifact": {
                    "archive": {"name": archive.name, "sha256": MODULE.sha256_file(archive)},
                    "library": {
                        "name": "privacyfilter.so",
                        "sha256": hashlib.sha256(data).hexdigest(),
                    },
                }
            }
            with self.assertRaises(SystemExit):
                MODULE.validate_archive(root, build)


if __name__ == "__main__":
    unittest.main()
