import copy
from datetime import datetime, timezone
from pathlib import Path
import plistlib
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import urllib.parse
import xml.etree.ElementTree as ET
import release

class FakeJamf:
    url = release.CONFIG['jamf_url']
    def __init__(self):
        self.calls, self.scripts, self.policies = [], {}, {}
        self.next_id = 500
        self.fail_enable_install = self.widen_created_policy = False
        for kind in ('install', 'health'):
            pid = release.CONFIG[f'baseline_{kind}_policy_id']
            policy = release.policy_document(release.CONFIG[f'baseline_{kind}_policy_name'], [], '95', health=kind == 'health')
            release.field(policy.find('general'), 'id', pid)
            policy.find('general/enabled').text = 'true'
            self.policies[pid] = policy
    def classic(self, method, resource, body=None, missing_ok=False):
        self.calls.append((method, resource, copy.deepcopy(body)))
        if resource == 'computergroups/id/259':
            return ET.fromstring('<computer_group><id>259</id><name>IT Security</name><is_smart>false</is_smart></computer_group>')
        if resource == 'policies':
            result = ET.Element('policies')
            for pid, policy in self.policies.items():
                entry = ET.SubElement(result, 'policy')
                release.field(entry, 'id', pid)
                release.field(entry, 'name', policy.findtext('general/name'))
            return result
        collection, lookup, key = resource.split('/', 2)
        records = self.policies if collection == 'policies' else self.scripts
        path = 'general/name' if collection == 'policies' else 'name'
        if lookup == 'name':
            matches = [v for v in records.values() if v.findtext(path) == urllib.parse.unquote(key)]
            return copy.deepcopy(matches[0]) if matches else None
        if method == 'GET':
            return copy.deepcopy(records[key])
        if method == 'POST':
            self.next_id += 1
            key, record = str(self.next_id), copy.deepcopy(body)
            release.field(record.find('general') if collection == 'policies' else record, 'id', key)
            if collection == 'policies' and self.widen_created_policy:
                record.find('scope/all_computers').text = 'true'
            records[key] = record
            return ET.fromstring(f'<{record.tag}><id>{key}</id></{record.tag}>')
        if method == 'PUT':
            enabled = body.findtext('general/enabled')
            if self.fail_enable_install and enabled == 'true' and ' - Install - ' in records[key].findtext(path):
                raise RuntimeError('Simulated enable failure')
            records[key].find('general/enabled').text = enabled
            return ET.Element('response')
        raise AssertionError('Unexpected operation')

class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.api = FakeJamf()
        self.release = {'release_id': 'r10.1 ' + 'a'*12}
    def promote(self, **kwargs):
        return release.promote(self.api, self.release, ['1400','1401'], '#!/bin/zsh\necho activate\n', '#!/bin/bash\necho health\n', **kwargs)
    def assert_no_writes(self):
        self.assertFalse(any(m in ('POST','PUT','DELETE') for m,_,_ in self.api.calls))
    def test_success_enables_install_last_and_retains_recoverable_history(self):
        result = self.promote()
        writes = [(p,b.findtext('general/enabled')) for m,p,b in self.api.calls if m == 'PUT']
        self.assertEqual(writes[-1], ('policies/id/'+result['install_policy_id'],'true'))
        self.assertEqual(writes[0], ('policies/id/'+result['weekly_health_policy_id'],'true'))
        for pid in ('409','410'):
            self.assertEqual(self.api.policies[pid].findtext('general/enabled'),'false')
        self.assertFalse(any(m == 'DELETE' for m,_,_ in self.api.calls))
    def test_retry_reuses_verified_objects(self):
        first = self.promote()
        count = len(self.api.policies),len(self.api.scripts)
        self.assertEqual(first,self.promote())
        self.assertEqual(count,(len(self.api.policies),len(self.api.scripts)))
    def test_changed_script_is_not_overwritten(self):
        result = self.promote()
        self.api.scripts[result['activation_script_id']].find('script_contents_encoded').text = 'YWx0ZXJlZA=='
        self.api.calls.clear()
        with self.assertRaisesRegex(ValueError,'script content differs'): self.promote()
        self.assert_no_writes()
    def test_stale_approval_never_enables_or_retires(self):
        def stale(): raise ValueError('main advanced')
        with self.assertRaisesRegex(ValueError,'main advanced'): self.promote(freshness=stale)
        self.assertFalse(any(m == 'PUT' for m,_,_ in self.api.calls))
    def test_wrong_tenant_prevents_writes(self):
        self.api.url = 'https://another.jamfcloud.com'
        with self.assertRaisesRegex(ValueError,'tenant'): self.promote()
        self.assert_no_writes()
    def test_expanded_scope_prevents_writes(self):
        self.api.policies['409'].find('scope/all_computers').text = 'true'
        with self.assertRaises(ValueError): self.promote()
        self.assert_no_writes()
    def test_extra_computer_prevents_writes(self):
        ET.SubElement(ET.SubElement(self.api.policies['409'].find('scope'),'computers'),'computer')
        with self.assertRaisesRegex(ValueError,'additional targets'): self.promote()
        self.assert_no_writes()
    def test_server_widened_candidate_is_never_enabled(self):
        self.api.widen_created_policy = True
        with self.assertRaises(ValueError): self.promote()
        self.assertFalse(any(m == 'PUT' for m,_,_ in self.api.calls))
    def test_unrelated_policy_is_not_retired(self):
        other = release.policy_document('Another application',[],'88')
        release.field(other.find('general'),'id','88')
        other.find('general/enabled').text = 'true'
        self.api.policies['88'] = other
        self.promote()
        self.assertEqual(other.findtext('general/enabled'),'true')
    def test_previous_ci_release_is_retired(self):
        first = self.promote()
        self.release['release_id'] = 'r11.1 '+'b'*12
        second = self.promote()
        self.assertNotEqual(first['install_policy_id'],second['install_policy_id'])
        for key in ('install_policy_id','weekly_health_policy_id'):
            self.assertEqual(self.api.policies[first[key]].findtext('general/enabled'),'false')
    def test_enable_failure_leaves_candidate_disabled_and_retry_completes(self):
        self.api.fail_enable_install = True
        with self.assertRaises(RuntimeError): self.promote()
        candidate = [p for p in self.api.policies.values() if ' - Install - ' in p.findtext('general/name')][0]
        self.assertEqual(candidate.findtext('general/enabled'),'false')
        self.api.fail_enable_install = False
        result = self.promote()
        self.assertEqual(self.api.policies[result['install_policy_id']].findtext('general/enabled'),'true')
    def test_payload_mismatch_prevents_reuse(self):
        result = self.promote()
        self.api.policies[result['install_policy_id']].find('package_configuration/packages/package/id').text = '9999'
        self.api.calls.clear()
        with self.assertRaisesRegex(ValueError,'unexpected package'): self.promote()
        self.assertFalse(any(m == 'PUT' for m,_,_ in self.api.calls))
    def test_versions_are_unique_and_increasing(self):
        date = datetime(2026,10,6,tzinfo=timezone.utc)
        versions = [release.release_versions('0.3.10',r,a,date) for r,a in [(1,1),(1,2),(2,1)]]
        self.assertEqual(versions[0],{'binary':'0.3.10.1101','policy':'2026.10.6.1101'})
        suffixes = [int(v['binary'].split('.')[-1]) for v in versions]
        self.assertEqual(suffixes,sorted(set(suffixes)))
        with self.assertRaises(ValueError): release.release_versions('0.3.10',1,100,date)
    def test_pair_renders_exact_payload_expectations_and_valid_shell(self):
        binary = {'application_version':'0.3.10','policy_sha256':'b'*64,'payload_sha256':'c'*64,'package_version':'0.3.10.1101'}
        policy = {'application_version':'0.3.10','payload_sha256':'b'*64,'package_version':'2026.10.6.1101'}
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            with patch.object(release,'load_artifact',side_effect=[(binary,None),(policy,None)]):
                manifest = release.prepare_release(directory,'a'*40,1,1)
            activation = (directory/'activation.zsh').read_text()
            self.assertNotIn('@APP_VERSION@',activation)
            self.assertEqual(manifest['activation_sha256'],release.digest(activation))
            xml = activation.split("<<'VGS_APPROVED_RELEASE'\n",1)[1].split('\nVGS_APPROVED_RELEASE',1)[0]
            state = plistlib.loads(xml.encode())
            self.assertEqual(state['binary_sha256'],'c'*64)
            self.assertEqual(state['policy_version'],'2026.10.6.1101')
            self.assertIn('CHECK_3_USER_HOOKS',activation)
            subprocess.run(['/bin/bash','-n',str(directory/'health-check.sh')],check=True)
            if Path('/bin/zsh').exists(): subprocess.run(['/bin/zsh','-n',str(directory/'activation.zsh')],check=True)
    def test_incompatible_pair_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(release,'load_artifact',side_effect=[({'application_version':'0.3.10','policy_sha256':'a'*64},None),({'application_version':'0.3.10','payload_sha256':'b'*64},None)]):
                with self.assertRaisesRegex(ValueError,'compatible release'): release.prepare_release(Path(tmp),'a'*40,1,1)

if __name__ == '__main__': unittest.main()
