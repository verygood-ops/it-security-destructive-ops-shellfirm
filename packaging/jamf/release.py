#!/usr/bin/env python3
"""Build a reviewed release; publish and promote only after environment approval."""
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import sys
import tomllib
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

import build as builder
from classic import ClassicJamf
from upload import load_artifact, upload

TEMPLATES = Path(__file__).with_name('release')
CONFIG = json.loads((TEMPLATES / 'deployment.json').read_text())
PREFIX = 'VGS ShellFirm CI '
OWNED_NAME = re.compile(r'^VGS ShellFirm CI r\d+\.\d+ [0-9a-f]{12} - (Install|Weekly Health) - IT Security$')


def digest(text):
    return hashlib.sha256(text.encode()).hexdigest()


def field(parent, name, value):
    ET.SubElement(parent, name).text = str(value).lower() if isinstance(value, bool) else str(value)


def identifier(document, path='id'):
    value = document.findtext(path, '')
    if not re.fullmatch(r'[1-9]\d*', value):
        raise ValueError('API returned an invalid resource ID')
    return value


def secure_scope(policy):
    scope = policy.find('scope')
    if scope is None or scope.findtext('all_computers') != 'false':
        raise ValueError('Policy is not restricted to specific computers')
    if scope.findall('computer_groups/computer_group/id') == []:
        raise ValueError('Policy has no pilot scope')
    groups = [v.text for v in scope.findall('computer_groups/computer_group/id')]
    if groups != [CONFIG['pilot_group_id']]:
        raise ValueError('Policy scope differs from the approved IT Security group')
    for collection in ('computers', 'buildings', 'departments', 'users', 'user_groups', 'jss_users', 'jss_user_groups'):
        node = scope.find(collection)
        if node is not None and any(c.tag != 'size' for c in node):
            raise ValueError('Policy has additional targets outside the approved group')
    if scope.findtext('all_jss_users', 'false') != 'false':
        raise ValueError('Policy has an unexpected user scope')


def policy_document(name, package_ids, script_id, health=False):
    policy = ET.Element('policy')
    general = ET.SubElement(policy, 'general')
    values = {'name': name, 'enabled': False, 'trigger': 'EVENT',
              'trigger_checkin': True, 'trigger_login': not health,
              'trigger_startup': False, 'trigger_network_state_changed': False,
              'trigger_enrollment_complete': False,
              'trigger_other': '', 'frequency': 'Once every week' if health else 'Once per computer',
              'retry_event': 'none' if health else 'check-in',
              'retry_attempts': -1 if health else 3,
              'notify_on_each_failed_retry': False, 'target_drive': '/', 'offline': False}
    for key, value in values.items():
        field(general, key, value)
    scope = ET.SubElement(policy, 'scope')
    field(scope, 'all_computers', False)
    field(scope, 'all_jss_users', False)
    group = ET.SubElement(ET.SubElement(scope, 'computer_groups'), 'computer_group')
    field(group, 'id', CONFIG['pilot_group_id'])
    packages = ET.SubElement(ET.SubElement(policy, 'package_configuration'), 'packages')
    for package_id in package_ids:
        package = ET.SubElement(packages, 'package')
        field(package, 'id', package_id)
        field(package, 'action', 'Install')
    script = ET.SubElement(ET.SubElement(policy, 'scripts'), 'script')
    field(script, 'id', script_id)
    field(script, 'priority', 'After')
    field(ET.SubElement(policy, 'self_service'), 'use_for_self_service', False)
    field(ET.SubElement(policy, 'maintenance'), 'recon', not health)
    return policy


def verify_policy(actual, expected, enabled=None):
    secure_scope(actual)
    for path in ('general/name', 'general/frequency', 'general/trigger_checkin',
                 'general/trigger_login', 'general/trigger_startup',
                 'general/trigger_network_state_changed', 'general/trigger_enrollment_complete',
                 'general/retry_event', 'general/retry_attempts', 'self_service/use_for_self_service'):
        if actual.findtext(path) != expected.findtext(path):
            raise ValueError(f'Policy read-back differs at {path}')
    for path, fields in [('package_configuration/packages/package', ('id', 'action')),
                         ('scripts/script', ('id', 'priority'))]:
        a = sorted(tuple(x.findtext(k) for k in fields) for x in actual.findall(path))
        b = sorted(tuple(x.findtext(k) for k in fields) for x in expected.findall(path))
        if a != b:
            raise ValueError('Policy read-back has unexpected package or script actions')
    if enabled is not None and actual.findtext('general/enabled') != str(enabled).lower():
        raise ValueError('Policy enabled state did not match')


def get_named(jamf, resource, name):
    return jamf.classic('GET', resource + '/name/' + urllib.parse.quote(name, safe=''), missing_ok=True)


def ensure_script(jamf, name, contents):
    existing = get_named(jamf, 'scripts', name)
    if existing is None:
        document = ET.Element('script')
        field(document, 'name', name)
        field(document, 'priority', 'After')
        field(document, 'script_contents_encoded', base64.b64encode(contents.encode()).decode())
        created = jamf.classic('POST', 'scripts/id/0', document)
        script_id = identifier(created)
        existing = jamf.classic('GET', 'scripts/id/' + script_id)
    encoded = existing.findtext('script_contents_encoded')
    text = base64.b64decode(encoded).decode() if encoded else existing.findtext('script_contents', '')
    if text.rstrip('\n') != contents.rstrip('\n') or existing.findtext('name') != name:
        raise ValueError('Existing release script content differs; no script was overwritten')
    return identifier(existing)


def ensure_policy(jamf, expected):
    name = expected.findtext('general/name')
    existing = get_named(jamf, 'policies', name)
    if existing is None:
        created = jamf.classic('POST', 'policies/id/0', expected)
        policy_id = identifier(created)
        existing = jamf.classic('GET', 'policies/id/' + policy_id)
        verify_policy(existing, expected, enabled=False)
    else:
        verify_policy(existing, expected)
    return identifier(existing, 'general/id')


def set_enabled(jamf, policy_id, enabled):
    change = ET.Element('policy')
    field(ET.SubElement(change, 'general'), 'enabled', enabled)
    jamf.classic('PUT', 'policies/id/' + policy_id, change)
    result = jamf.classic('GET', 'policies/id/' + policy_id)
    if result.findtext('general/enabled') != str(enabled).lower():
        raise ValueError('Policy enabled state failed read-back verification')
    return result


def preflight(jamf):
    if jamf.url != CONFIG['jamf_url']:
        raise ValueError('Refusing a Jamf tenant other than the reviewed VGS tenant')
    group = jamf.classic('GET', 'computergroups/id/' + CONFIG['pilot_group_id'])
    if group.findtext('name') != CONFIG['pilot_group_name'] or group.findtext('is_smart') != 'false':
        raise ValueError('Pilot group identity changed')
    old = []
    for kind in ('install', 'health'):
        policy_id = CONFIG[f'baseline_{kind}_policy_id']
        policy = jamf.classic('GET', 'policies/id/' + policy_id)
        if policy.findtext('general/name') != CONFIG[f'baseline_{kind}_policy_name']:
            raise ValueError('Baseline policy identity changed')
        secure_scope(policy)
        old.append(policy)
    listing = jamf.classic('GET', 'policies')
    for item in listing.findall('policy'):
        if OWNED_NAME.fullmatch(item.findtext('name', '')):
            policy = jamf.classic('GET', 'policies/id/' + identifier(item))
            secure_scope(policy)
            old.append(policy)
    return old


def promote(jamf, release, package_ids, activation, health, freshness=lambda: None):
    """Stage and verify first. Enable installation last. Never delete resources."""
    previous = preflight(jamf)
    activation_id = ensure_script(jamf, PREFIX + release['release_id'] + ' - Activate', activation)
    health_id = ensure_script(jamf, PREFIX + 'Health ' + digest(health)[:16], health)
    install_name = PREFIX + release['release_id'] + ' - Install - IT Security'
    health_name = PREFIX + release['release_id'] + ' - Weekly Health - IT Security'
    install = policy_document(install_name, package_ids, activation_id)
    weekly = policy_document(health_name, [], health_id, health=True)
    install_id = ensure_policy(jamf, install)
    weekly_id = ensure_policy(jamf, weekly)
    freshness()
    # Health can evaluate both the baseline and successfully activated CI releases.
    verify_policy(set_enabled(jamf, weekly_id, True), weekly, enabled=True)
    for policy in previous:
        old_id = identifier(policy, 'general/id')
        if old_id not in (install_id, weekly_id) and policy.findtext('general/enabled') == 'true':
            # Recheck scope immediately before retiring a policy in case an admin changed it.
            secure_scope(jamf.classic('GET', 'policies/id/' + old_id))
            set_enabled(jamf, old_id, False)
    freshness()
    verify_policy(set_enabled(jamf, install_id, True), install, enabled=True)
    return {'install_policy_id': install_id, 'weekly_health_policy_id': weekly_id,
            'activation_script_id': activation_id, 'health_script_id': health_id,
            'package_ids': package_ids, 'pilot_group_id': CONFIG['pilot_group_id']}


def release_versions(app, run_number, attempt, date):
    if not re.fullmatch(r'\d+\.\d+\.\d+', app) or not (1 <= run_number <= 999999 and 1 <= attempt <= 99):
        raise ValueError('Invalid application version or workflow run/attempt')
    sequence = 1000 + run_number * 100 + attempt
    return {'binary': f'{app}.{sequence}', 'checks': f'{date.year}.{date.month}.{date.day}.{sequence}',
            'policy': f'{date.year}.{date.month}.{date.day}.{sequence}'}


def prepare_release(directory, commit, run_number, attempt):
    binary, _ = load_artifact(directory / 'binary', commit)
    policy, _ = load_artifact(directory / 'policy', commit)
    checks, _ = load_artifact(directory / 'checks', commit)
    if binary['application_version'] != policy['application_version'] or binary['policy_sha256'] != policy['payload_sha256']:
        raise ValueError('Binary and policy are not a compatible release pair')
    if (checks['checks_source'] != builder.MANAGED_CHECKS
            or binary['checks_source'] != builder.MANAGED_CHECKS
            or binary['checks_sha256'] != checks['payload_sha256']
            or checks['application_version'] != binary['application_version']):
        raise ValueError('Default checks are not a compatible release catalog')
    for manifest, kind in ((binary, 'binary'), (checks, 'checks'), (policy, 'policy')):
        if manifest['kind'] != kind:
            raise ValueError('Package kind differs from its release directory')
    for value in (binary['payload_sha256'], policy['payload_sha256'], checks['payload_sha256']):
        if not re.fullmatch(r'[0-9a-f]{64}', value):
            raise ValueError('Invalid payload digest')
    release = {'schema': 2, 'source_commit': commit,
               'release_id': f'r{run_number}.{attempt} {commit[:12]}',
               'application_version': binary['application_version'],
               'binary_version': binary['package_version'], 'policy_version': policy['package_version'],
               'binary_sha256': binary['payload_sha256'], 'policy_sha256': policy['payload_sha256'],
               'checks_version': checks['package_version'], 'checks_sha256': checks['payload_sha256']}
    health = (TEMPLATES / 'health-check.sh').read_text()
    activation = (TEMPLATES / 'activation.zsh').read_text()
    replacements = {'@APP_VERSION@': release['application_version'], '@POLICY_SHA256@': release['policy_sha256'],
                    '@CHECKS_SHA256@': release['checks_sha256'], '@CHECKS_VERSION@': release['checks_version'],
                    '@BINARY_SHA256@': release['binary_sha256'], '@RELEASE_ID@': release['release_id'],
                    '@HEALTHCHECK@': health,
                    '@RELEASE_PLIST@': plistlib.dumps(release).decode().rstrip()}
    for key, value in replacements.items():
        activation = activation.replace(key, value)
    if re.search(r'@[A-Z_]+@', activation):
        raise ValueError('Unrendered activation template')
    health = (TEMPLATES / 'health-check.sh').read_text()
    (directory / 'activation.zsh').write_text(activation)
    (directory / 'health-check.sh').write_text(health)
    release['activation_sha256'] = digest(activation)
    release['health_sha256'] = digest(health)
    (directory / 'release.json').write_text(json.dumps(release, indent=2) + '\n')
    return release


def assert_current_main(commit):
    if os.environ.get('GITHUB_REPOSITORY') != CONFIG['repository'] or os.environ.get('GITHUB_REF') != 'refs/heads/main':
        raise ValueError('Deployment is restricted to this repository main branch')
    request = urllib.request.Request('https://api.github.com/repos/' + CONFIG['repository'] + '/commits/main',
                                     headers={'Authorization': 'Bearer ' + os.environ['GH_TOKEN'],
                                              'Accept': 'application/vnd.github+json'})
    with urllib.request.urlopen(request, timeout=30) as response:
        head = json.load(response)['sha']
    if head != commit:
        raise ValueError('main advanced while this release was queued; approve the newest release instead')


def deploy(directory, commit):
    assert_current_main(commit)
    release = json.loads((directory / 'release.json').read_text())
    activation = (directory / 'activation.zsh').read_text()
    health = (directory / 'health-check.sh').read_text()
    if (release['source_commit'] != commit or digest(activation) != release['activation_sha256']
            or digest(health) != release['health_sha256']):
        raise ValueError('Release scripts or source commit do not match the build manifest')
    manifests = [load_artifact(directory / kind, commit) for kind in ('checks', 'binary', 'policy')]
    for (manifest, _), kind in zip(manifests, ('checks', 'binary', 'policy')):
        if manifest['kind'] != kind:
            raise ValueError('Package kind differs from its release directory')
        if release[kind + '_version'] != manifest['package_version'] or release[kind + '_sha256'] != manifest['payload_sha256']:
            raise ValueError('Package differs from the release descriptor')
    if os.environ['JAMF_URL'].rstrip('/') != CONFIG['jamf_url']:
        raise ValueError('JAMF_URL does not match the approved tenant')
    jamf = ClassicJamf(*(os.environ[key] for key in ('JAMF_URL', 'JAMF_CLIENT_ID', 'JAMF_CLIENT_SECRET')))
    try:
        preflight(jamf)
        ids = [upload(jamf, manifest, package, os.environ.get('JAMF_CATEGORY_ID') or '-1')[0]
               for manifest, package in manifests]
        result = promote(jamf, release, ids, activation, health, lambda: assert_current_main(commit))
        (directory / 'deployment-result.json').write_text(json.dumps(result, indent=2) + '\n')
        message = ('Release ' + release['release_id'] + ' enabled for IT Security group 259. '
                   'Install policy ' + result['install_policy_id'] + '; weekly health policy '
                   + result['weekly_health_policy_id'] + '. Endpoint execution is pending Jamf check-in; '
                   'this is not confirmation of successful workstation installation.')
        print(message)
        if os.environ.get('GITHUB_STEP_SUMMARY'):
            with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as summary:
                summary.write(message + '\n')
    finally:
        try:
            jamf.request('POST', '/api/v1/auth/invalidate-token')
        except RuntimeError:
            print('Token invalidation unavailable; the short-lived token will expire.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('build', 'deploy'))
    parser.add_argument('--directory', type=Path, default=Path('dist/release'))
    parser.add_argument('--commit', required=True)
    parser.add_argument('--binary', type=Path)
    parser.add_argument('--run-number', type=int)
    parser.add_argument('--attempt', type=int)
    args = parser.parse_args()
    if args.action == 'deploy':
        deploy(args.directory, args.commit)
    else:
        app = tomllib.loads((builder.ROOT / 'shellfirm/Cargo.toml').read_text())['package']['version']
        versions = release_versions(app, args.run_number, args.attempt, datetime.now(timezone.utc))
        version_path = builder.CONFIG / 'versions.json'
        original = version_path.read_bytes()
        try:
            version_path.write_text(json.dumps(versions) + '\n')
            for kind in ('checks', 'binary', 'policy'):
                builder.build(kind, args.binary, args.directory / kind, args.commit)
        finally:
            version_path.write_bytes(original)
        release = prepare_release(args.directory, args.commit, args.run_number, args.attempt)
        builder.run('/bin/zsh', '-n', args.directory / 'activation.zsh')
        builder.run('/bin/bash', '-n', args.directory / 'health-check.sh')
        print(json.dumps(release, indent=2))
        if os.environ.get('GITHUB_STEP_SUMMARY'):
            with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as summary:
                summary.write(f"Candidate {release['release_id']}: binary {release['binary_version']}, "
                              f"checks {release['checks_version']}, policy {release['policy_version']}. After jamf approval: new install and weekly health "
                              "policies for IT Security group 259, retiring policies 409/410 and earlier CI releases.\n")


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, OSError, RuntimeError, ET.ParseError) as exc:
        print(f'Release stopped: {exc}', file=sys.stderr)
        sys.exit(1)
