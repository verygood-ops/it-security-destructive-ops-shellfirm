"""Exercise upload safety with a fake API. These tests never contact Jamf."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import upload


class FakeJamf:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.calls = []

    def request(self, method, path, data=None, content_type=None):
        self.calls.append((method, path, data, content_type))
        return next(self.responses)


class UploadTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name)
        self.commit = "a" * 40
        self.manifest = {
            "kind": "policy", "package_version": "2026.10.6.1",
            "file_name": "VGS-ShellFirm-Policy-2026.10.6.1-unsigned.pkg",
            "source_commit": self.commit, "policy_sha256": "b" * 64,
            "package_sha256": hashlib.sha256(b"fixture").hexdigest(),
        }
        self.package = self.directory / self.manifest["file_name"]
        self.package.write_bytes(b"fixture")
        self.write_manifest()
        self.record = {"id": "1400", "fileName": self.package.name,
                       "sha256": self.manifest["package_sha256"], "cloudTransferStatus": "READY"}

    def write_manifest(self):
        (self.directory / "manifest.json").write_text(json.dumps(self.manifest))

    def test_tampered_package_is_rejected_before_authentication(self):
        self.package.write_bytes(b"tampered")
        with self.assertRaisesRegex(ValueError, "checksum"):
            upload.load_artifact(self.directory, self.commit)

    def test_wrong_commit_and_path_traversal_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "commit"):
            upload.load_artifact(self.directory, "c" * 40)
        self.manifest["file_name"] = "../outside.pkg"
        self.write_manifest()
        with self.assertRaisesRegex(ValueError, "filename"):
            upload.load_artifact(self.directory, self.commit)

    def test_symlink_package_is_rejected(self):
        destination = self.directory / "actual.pkg"
        self.package.rename(destination)
        self.package.symlink_to(destination)
        with self.assertRaisesRegex(ValueError, "regular file"):
            upload.load_artifact(self.directory, self.commit)

    def test_identical_ready_package_does_not_write(self):
        api = FakeJamf([{"totalCount": 1, "results": [self.record]}])
        result = upload.upload(api, self.manifest, self.package)
        self.assertEqual(result[0], "1400")
        self.assertEqual([call[0] for call in api.calls], ["GET"])

    def test_conflicting_or_incomplete_package_never_overwrites(self):
        for change in ({"sha256": "c" * 64}, {"cloudTransferStatus": "PENDING"}):
            api = FakeJamf([{"totalCount": 1, "results": [{**self.record, **change}]}])
            with self.assertRaisesRegex(RuntimeError, "Nothing was overwritten"):
                upload.upload(api, self.manifest, self.package)
            self.assertEqual([call[0] for call in api.calls], ["GET"])

    def test_new_package_requires_ready_and_server_checksum(self):
        api = FakeJamf([{"totalCount": 0, "results": []}, {"id": "1400"}, {},
                        {**self.record, "cloudTransferStatus": "PENDING"}, self.record])
        result = upload.upload(api, self.manifest, self.package, wait=lambda _: None)
        self.assertEqual(result[0], "1400")
        self.assertEqual([call[0] for call in api.calls], ["GET", "POST", "POST", "GET", "GET"])
        metadata = api.calls[1][2]
        self.assertNotIn("sha256", metadata)  # Must be computed by Jamf after receiving bytes.
        self.assertFalse(metadata["rebootRequired"])
        self.assertIn(b'name="file"', api.calls[2][2])
        self.assertIn(b"fixture", api.calls[2][2])
        self.assertTrue(all("/packages" in call[1] for call in api.calls))

    def test_invalid_later_package_priority_stops_before_first_api_call(self):
        for priority in (0, -1, 21, 30, True, "20", 1.5):
            with self.subTest(priority=priority):
                api = FakeJamf([])
                with patch.dict(upload.PACKAGE_PRIORITIES, {"policy": priority}):
                    with self.assertRaisesRegex(ValueError, "integers from 1 to 20"):
                        upload.upload(api, {**self.manifest, "kind": "checks"}, self.package)
                self.assertEqual(api.calls, [])

    def test_equal_or_reversed_priorities_stop_before_first_api_call(self):
        for priorities in ({"checks": 10, "binary": 5, "policy": 20},
                           {"checks": 5, "binary": 20, "policy": 10},
                           {"checks": 5, "binary": 5, "policy": 20}):
            with self.subTest(priorities=priorities):
                api = FakeJamf([])
                with patch.dict(upload.PACKAGE_PRIORITIES, priorities):
                    with self.assertRaisesRegex(ValueError, "checks before binary before policy"):
                        upload.upload(api, {**self.manifest, "kind": "checks"}, self.package)
                self.assertEqual(api.calls, [])

    def test_server_checksum_mismatch_is_failure(self):
        api = FakeJamf([{"totalCount": 0, "results": []}, {"id": "1400"}, {},
                        {**self.record, "sha256": "c" * 64}])
        with self.assertRaisesRegex(RuntimeError, "mismatch"):
            upload.upload(api, self.manifest, self.package)

    def test_unready_upload_is_failure(self):
        pending = {**self.record, "cloudTransferStatus": "PENDING", "sha256": ""}
        api = FakeJamf([{"totalCount": 0, "results": []}, {"id": "1400"}, {}] + [pending] * 24)
        with self.assertRaisesRegex(RuntimeError, "did not become READY"):
            upload.upload(api, self.manifest, self.package, wait=lambda _: None)

    def test_untrusted_origin_is_rejected_before_network(self):
        for url in ("http://example.com", "https://user:pass@example.com", "https://example.com/path"):
            with self.assertRaisesRegex(ValueError, "HTTPS origin"):
                upload.Jamf(url, "fixture", "fixture")

    def test_redirects_do_not_forward_credentials(self):
        self.assertIsNone(upload.NoRedirect().redirect_request(None, None, 302, "", {}, "https://other.example"))


if __name__ == "__main__":
    unittest.main()
