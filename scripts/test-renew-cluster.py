#!/usr/bin/env python3
"""公開証明書のSFTP経路と一時データのcleanupを、実機変更なしで検査する。"""
import base64
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    'renew_cluster', Path(__file__).with_name('renew-cluster.py'))
RENEW = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RENEW)


class WindowsRenewTests(unittest.TestCase):
    def setUp(self):
        self.node = {'ssh': 'fixture-host', 'platform': 'windows',
                     'home': 'C:/ProgramData/idobata',
                     'binary': 'C:/Program Files/idobata/idobata.exe'}

    def test_large_certificate_uses_private_sftp_not_encoded_payload(self):
        certificate = {'signed': {'fixture': 'sftp-body-sentinel' * 2048}}
        calls, temporary = [], []

        def run(args, *_data, **_options):
            calls.append(args)
            if args[0] == 'scp':
                path = Path(args[-2])
                temporary.append(path)
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                self.assertEqual(json.loads(path.read_text()), certificate)
                self.assertTrue(args[-1].startswith(
                    'fixture-host:C:/ProgramData/idobata/engineering-invite-'))
            else:
                self.assertLess(len(args[-1]), 8191)
                script = base64.b64decode(args[-1].split()[-1]).decode('utf-16le')
                self.assertNotIn('sftp-body-sentinel', script)
                self.assertNotIn('FromBase64String', script)
                self.assertIn('Remove-Item', script)
                self.assertIn('Unregister-ScheduledTask', script)
            return ''

        with patch.object(RENEW, 'run', side_effect=run):
            RENEW.windows_join(self.node, 'engineering', certificate, '1' * 52)
        self.assertEqual([call[0] for call in calls], ['scp', 'ssh', 'ssh'])
        self.assertFalse(temporary[0].exists())
        joined = base64.b64decode(calls[1][-1].split()[-1]).decode('utf-16le')
        self.assertIn('FileSecurity', joined)
        self.assertIn("'S-1-5-19'", joined)
        self.assertIn('finally', joined)

    def test_upload_or_join_failure_still_cleans_private_files(self):
        for failed_tool in ['scp', 'ssh']:
            calls, temporary = [], []
            failed = False

            def run(args, *_data, **_options):
                nonlocal failed
                calls.append(args)
                if args[0] == 'scp':
                    temporary.append(Path(args[-2]))
                if args[0] == failed_tool and not failed:
                    failed = True
                    raise RuntimeError('fixture_failure')
                return ''

            with patch.object(RENEW, 'run', side_effect=run):
                with self.assertRaises(RuntimeError):
                    RENEW.windows_join(self.node, 'engineering', {'signed': {}}, '1' * 52)
            self.assertFalse(temporary[0].exists())
            cleanup = base64.b64decode(calls[-1][-1].split()[-1]).decode('utf-16le')
            self.assertIn('Stop-ScheduledTask', cleanup)
            self.assertIn('Unregister-ScheduledTask', cleanup)
            self.assertIn('Remove-Item', cleanup)

    def test_alias_and_windows_path_traversal_are_rejected_before_commands(self):
        for room, home, binary in [
            ('../other', self.node['home'], self.node['binary']),
            ('engineering', 'C:/ProgramData/idobata/../other', self.node['binary']),
            ('engineering', 'C:/ProgramData/idobata\n', self.node['binary']),
            ('engineering', self.node['home'], 'idobata.exe'),
        ]:
            node = {**self.node, 'home': home, 'binary': binary}
            with patch.object(RENEW, 'run') as run:
                with self.assertRaises(ValueError):
                    RENEW.windows_join(node, room, {}, '1' * 52)
                run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
