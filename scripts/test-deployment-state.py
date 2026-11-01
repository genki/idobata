#!/usr/bin/env python3
"""既存service/状態の保全を実機変更なしで確認する。"""
import importlib.util
import base64
import hashlib
import re
import shlex
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))
import deployment_state as STATE


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), SCRIPTS / name)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class DeploymentStateTests(unittest.TestCase):
    def test_exact_v04_mutable_inventory_keeps_keys_and_locks_separate(self):
        self.assertTrue({'config.json', 'state.enc', 'knowledge.enc',
                         'automation-nonces.json', 'public-projection.enc',
                         'ledger-settings.json', 'ledger-consensus.enc',
                         'ledger-minimum.enc', 'ledger-application.enc',
                         'ledger-consensus.initialized'}
                        <= set(STATE.MUTABLE_FILES))
        self.assertFalse(set(STATE.MUTABLE_FILES) & set(STATE.IMMUTABLE_FILES))
        self.assertFalse(set(STATE.MUTABLE_FILES) & set(STATE.LOCK_FILES))
        self.assertNotIn('ledger-runtime.enc', STATE.MUTABLE_FILES)

    def test_existing_home_service_binary_and_symlink_fail_before_reading_values(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home, binary, service = root / 'home', root / 'sdk', root / 'service'
            STATE.assert_bootstrap_fresh(home, binary, [service])
            home.mkdir()
            key = home / 'identity.key'
            key.write_text('private-key-sentinel')
            with patch.object(Path, 'read_bytes', side_effect=AssertionError('key content read')):
                with self.assertRaisesRegex(RuntimeError, 'existing_installation'):
                    STATE.assert_bootstrap_fresh(home, binary, [service])
            key.unlink(); home.rmdir()
            for path in [binary, service]:
                path.write_text('existing-state')
                with self.assertRaises(RuntimeError):
                    STATE.assert_bootstrap_fresh(home, binary, [service])
                self.assertEqual(path.read_text(), 'existing-state')
                path.unlink()
            home.symlink_to(root / 'missing')
            with self.assertRaises(RuntimeError):
                STATE.assert_bootstrap_fresh(home, binary, [service])
            home.unlink()
            with self.assertRaises(RuntimeError):
                STATE.assert_bootstrap_fresh(home, binary, [service], True)

    def test_mutated_nonce_wal_minimum_or_tracking_prohibits_binary_rollback(self):
        before = {name: {'present': False} for name in STATE.MUTABLE_FILES}
        self.assertTrue(STATE.unchanged_for_binary_rollback(before, before.copy()))
        for name in STATE.MUTABLE_FILES:
            after = before.copy()
            after[name] = {'present': True, 'private_manifest': 'changed'}
            self.assertFalse(STATE.unchanged_for_binary_rollback(before, after))
        incomplete = before.copy(); incomplete.pop('ledger-minimum.enc')
        self.assertFalse(STATE.unchanged_for_binary_rollback(incomplete, incomplete))

    def test_cli_scope_cannot_target_sdk_keys_or_data(self):
        self.assertTrue(STATE.assert_cli_targets('macos', ['/usr/local/bin/idobata']))
        self.assertTrue(STATE.assert_cli_targets('windows',
                        ['C:\\Program Files\\idobata\\bin\\idobata.exe',
                         'C:/Program Files/idobata/agent.socket']))
        for platform, path in [('linux', '/usr/local/lib/idobata/idobata'),
                               ('linux', '/var/lib/idobata/identity.key'),
                               ('macos', '/usr/local/bin/../lib/idobata/idobata'),
                               ('windows', 'C:/Program Files/idobata/idobata.exe'),
                               ('windows', 'C:/ProgramData/idobata/ledger-consensus.enc')]:
            with self.assertRaises(ValueError):
                STATE.assert_cli_targets(platform, [path])

    def test_mac_bootstrap_preflight_is_first_operation_and_remote_python_is_valid(self):
        module = load('install-peers.py')
        calls = []

        def guarded(args, *_args, **_kwargs):
            calls.append(args)
            raise RuntimeError('fixture_guard_refused')

        with patch.object(module, 'run', side_effect=guarded):
            with self.assertRaisesRegex(RuntimeError, 'fixture_guard_refused'):
                module.mac('fixture', 39111)
        self.assertEqual(len(calls), 1)
        self.assertIn('existing_installation_requires_guarded_upgrade', calls[0][-1])
        self.assertNotIn('install -m', calls[0][-1])
        compile(shlex.split(calls[0][-1])[-1], '<mac-bootstrap-preflight>', 'exec')
        self.assertIn('GUARDED_MUTABLE_FILES', module.__dict__)
        cli = load('install-agent-cli.py')
        compile(cli.UNIX_REMOTE, '<public-cli-remote>', 'exec')
        self.assertIn("payload['allowed_targets']", cli.UNIX_REMOTE)

    def test_linux_preflight_refuses_before_user_or_sdk_mutation(self):
        module = load('install-peers.py')
        with tempfile.TemporaryDirectory() as temporary:
            candidate = Path(temporary) / 'candidate'
            candidate.write_bytes(b'public-sdk-fixture')
            calls = []

            def invoke(args, *_args, **_kwargs):
                calls.append(args)
                if args[-1] == '--version':
                    return 'idobata ' + module.VERSION
                compile(args[-1], '<linux-bootstrap-preflight>', 'exec')
                raise RuntimeError('fixture_guard_refused')

            with patch.object(module, 'run', side_effect=invoke), patch.object(
                    module.subprocess, 'run', side_effect=AssertionError('mutation attempted')):
                with self.assertRaisesRegex(RuntimeError, 'fixture_guard_refused'):
                    module.linux(candidate, hashlib.sha256(candidate.read_bytes()).hexdigest())
            self.assertEqual(len(calls), 2)
            self.assertIn('existing_installation_requires_guarded_upgrade', calls[-1][-1])

    def test_windows_preflight_precedes_copy_acl_and_task_replacement(self):
        module = load('install-peers.py')
        commands = []

        def refuse(args, *_args, **_kwargs):
            commands.append(args)
            raise RuntimeError('fixture_no_remote_execution')

        with patch.object(module, 'run', side_effect=refuse):
            with self.assertRaisesRegex(RuntimeError, 'fixture_no_remote_execution'):
                module.windows()
        script = base64.b64decode(commands[0][-1].split()[-1]).decode('utf-16le')
        self.assertNotIn('Stop-ScheduledTask', script)
        self.assertLess(script.index('existing_installation_requires_guarded_upgrade'),
                        script.index('Copy-Item'))
        self.assertLess(script.index('existing_installation_requires_guarded_upgrade'),
                        script.index('Set-IdobataAcl $homeDir'))

    def test_production_ledger_file_literals_are_all_guarded(self):
        source = SCRIPTS.parent / 'crates/idobata/src'
        names = set()
        for path in source.glob('ledger*.rs'):
            if 'tests' not in path.name:
                names.update(re.findall(r'"(ledger-[a-z-]+\.(?:enc|json|initialized))"',
                                        path.read_text()))
        self.assertTrue(names <= set(STATE.MUTABLE_FILES),
                        'new persistent ledger filename requires inventory update')


if __name__ == '__main__':
    unittest.main()
