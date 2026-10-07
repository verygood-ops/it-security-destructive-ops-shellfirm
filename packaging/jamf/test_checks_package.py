"""Guard the three-package contract without contacting Jamf."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import build
import release
import upload


class ChecksPackageTests(unittest.TestCase):
    def test_complete_catalog_is_sorted_and_preserves_all_sources(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            checks = root / 'shellfirm/checks'
            checks.mkdir(parents=True)
            (checks / 'z.yaml').write_text('- id: z\n')
            (checks / 'a.yaml').write_text('- id: a\n')
            with patch.object(build, 'ROOT', root):
                self.assertEqual(build.catalog(), b'- id: a\n- id: z\n')
                (checks / 'a.yaml').unlink()
                (checks / 'a.yaml').symlink_to(checks / 'z.yaml')
                with self.assertRaises(ValueError): build.catalog()

    def test_checks_install_before_binary_and_vgs_policy(self):
        priorities = []
        for kind in ('checks', 'binary', 'policy'):
            metadata = upload.package_metadata({'kind':kind, 'package_version':'1.0.0',
                'file_name':'fixture.pkg', 'source_commit':'a'*40, 'package_sha256':'b'*64,
                'policy_sha256':'c'*64}, '-1')
            priorities.append(metadata['priority'])
        for priority in priorities:
            self.assertIs(type(priority), int)
            self.assertGreaterEqual(priority, 1)
            self.assertLessEqual(priority, 20)
        self.assertLess(priorities[0], priorities[1])
        self.assertLess(priorities[1], priorities[2])

    def test_catalog_mismatch_stops_promotion_preparation(self):
        binary = {'application_version':'0.3.10', 'policy_sha256':'a'*64,
                  'checks_source':build.MANAGED_CHECKS, 'checks_sha256':'b'*64}
        policy = {'application_version':'0.3.10', 'payload_sha256':'a'*64}
        checks = {'application_version':'0.3.10', 'checks_source':build.MANAGED_CHECKS,
                  'payload_sha256':'c'*64}
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(release, 'load_artifact', side_effect=[(binary,None),(policy,None),(checks,None)]):
                with self.assertRaisesRegex(ValueError, 'compatible release catalog'):
                    release.prepare_release(Path(tmp), 'a'*40, 1, 1)


if __name__ == '__main__':
    unittest.main()
