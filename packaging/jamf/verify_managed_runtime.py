#!/usr/bin/env python3
"""Exercise the real managed binary on an ephemeral GitHub macOS runner only."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

import build


def main(binary):
    if os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('RUNNER_OS') != 'macOS':
        raise RuntimeError('This integration test is restricted to an ephemeral macOS CI runner')
    target = Path(build.MANAGED_CHECKS)
    if target.exists() or target.is_symlink():
        raise RuntimeError('Refusing to replace an existing managed catalog during CI')
    binary = binary.resolve(strict=True)
    before = hashlib.sha256(binary.read_bytes()).hexdigest()
    assert b'aws:s3_remove_bucket' not in binary.read_bytes(), 'Default checks were embedded'
    with tempfile.TemporaryDirectory(prefix='vgs-runtime-') as tmp:
        home = Path(tmp)
        candidate = home / 'candidate.yaml'
        environment = {**os.environ, 'HOME': str(home)}
        # Setting this at runtime must not override the path compiled into the binary.
        environment['SHELLFIRM_MANAGED_CHECKS_PATH'] = str(candidate)
        def command(*args, succeeds=True):
            result = subprocess.run([str(binary), *args], env=environment, cwd=home,
                                    capture_output=True, text=True, timeout=30)
            output = result.stdout + result.stderr
            assert (result.returncode == 0) == succeeds, output
            return output
        def publish(content):
            candidate.write_bytes(content)
            subprocess.run(['sudo', 'install', '-m', '644', '-o', 'root', '-g', 'wheel',
                            str(candidate), str(target)], check=True)
        # Make only the three managed directories; never change /Library itself.
        for directory in (target.parent.parent.parent, target.parent.parent, target.parent):
            subprocess.run(['sudo', 'install', '-d', '-m', '755', '-o', 'root', '-g', 'wheel', str(directory)], check=True)
        original = build.catalog()
        try:
            command('default-checks', 'status', succeeds=False)
            publish(original)
            assert command('default-checks', 'source').strip() == str(target)
            command('default-checks', 'status')
            probe = ('pre-command', '--test', '-c', 'aws s3 rb s3://ci-fixture --force')
            assert 'aws:s3_remove_bucket' in command(*probe)
            publish(original.replace(b'aws:s3_remove_bucket', b'aws:vgs_runtime_fixture'))
            assert 'aws:vgs_runtime_fixture' in command(*probe)
            assert 'aws:s3_remove_bucket' not in command(*probe)
            # VGS policy is still loaded separately, alongside managed defaults.
            shutil.copyfile(build.ROOT / '.shellfirm.yaml', home / '.shellfirm.yaml')
            assert 'vgs:terraform_apply_replace' in command('pre-command', '--test', '-c',
                                                          'terragrunt apply -replace=helm_release.flux')
            for invalid in (b'[]\n', b'[invalid', original + original,
                            b'- id: bad\n  from: aws\n  description: invalid\n  test: "["\n'):
                publish(invalid)
                command('default-checks', 'status', succeeds=False)
                command(*probe, succeeds=False)
            publish(original)
            subprocess.run(['sudo', 'chmod', '666', str(target)], check=True)
            command(*probe, succeeds=False)
            subprocess.run(['sudo', 'chmod', '644', str(target)], check=True)
            subprocess.run(['sudo', 'chmod', '777', str(target.parent)], check=True)
            command(*probe, succeeds=False)
            subprocess.run(['sudo', 'chmod', '755', str(target.parent)], check=True)
            subprocess.run(['sudo', 'rm', str(target)], check=True)
            subprocess.run(['sudo', 'ln', '-s', str(candidate), str(target)], check=True)
            command(*probe, succeeds=False)
            subprocess.run(['sudo', 'rm', str(target)], check=True)
            command(*probe, succeeds=False)
        finally:
            subprocess.run(['sudo', 'rm', '-f', str(target)], check=True)
        assert hashlib.sha256(binary.read_bytes()).hexdigest() == before
    print('Managed runtime verified: changed rules apply without changing the binary; invalid catalogs fail closed.')


if __name__ == '__main__':
    main(Path(sys.argv[1]))
