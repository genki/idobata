#!/usr/bin/env python3
"""補助監視の状態区別・情報境界・既存4peerからの分離を検証する。"""
import importlib.util
import base64
import json
from pathlib import Path
import stat
import shlex
import sys
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location(
    'watch_delegation', Path(__file__).with_name('watch-delegation.py'))
WATCH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(WATCH)
SETUP_SPEC = importlib.util.spec_from_file_location(
    'setup_delegation', Path(__file__).with_name('setup-delegation-monitor.py'))
SETUP = importlib.util.module_from_spec(SETUP_SPEC)
SETUP_SPEC.loader.exec_module(SETUP)


def runner(state='success', reason='dry_run_complete'):
    return {'version': 1, 'checked_at': 100, 'state': state, 'reason': reason,
            'started_at': 90, 'completed_at': 100, 'deadline_at': 270,
            'last_success_at': 100,
            'counts': {'attempts': 1, 'successes': int(state == 'success'),
                       'failures': int(state == 'failure'),
                       'holds': int(state == 'hold')}}


def config():
    return {'version': 1, 'enabled': True, **WATCH.METADATA,
            'runner_stale_seconds': 120,
            'doctor_argv': ['fixed-ssh', 'doctor'],
            'runner_argv': ['fixed-ssh', 'runner-status']}


class DelegationWatchTests(unittest.TestCase):
    def test_setup_uses_fixed_dsh_scope_without_vm_autostart_or_sdk_mutation(self):
        value = SETUP.configuration()
        self.assertTrue(WATCH.config_valid(value))
        commands = []
        for key in ['doctor_argv', 'runner_argv']:
            argv = value[key]
            self.assertIn('-oForwardAgent=no', argv)
            nested = shlex.split(argv[-1])
            self.assertEqual(nested[0], '/usr/bin/ssh')
            self.assertIn('lima-dsh', nested)
            wrapper = shlex.split(nested[-1])
            self.assertEqual(wrapper[:3], ['sudo', '-n',
                                          '/usr/local/sbin/dsh-websh-exec'])
            commands.append(base64.b64decode(wrapper[3]).decode())
        self.assertEqual(commands, [
            '/usr/local/bin/idobata --socket /run/idobata/ipc.sock doctor',
            'cat /home/dsh/.local/state/idobata-judge/status.json'])
        self.assertNotIn('watch-cluster', SETUP.UNIT)
        self.assertNotIn('ledger-settings', json.dumps(value))

    def test_peer_drops_identity_rooms_and_free_text(self):
        value = {'status': 'healthy', 'daemon': {
            'status': 'ready', 'version': '0.4.0', 'uptime_seconds': 42,
            'connected_peers': 0, 'peer_id': 'private-peer-sentinel',
            'rooms': [{'name': 'private-room-sentinel', 'authorized': True,
                       'expires_at': 1000}], 'body': 'private-body-sentinel'}}
        result = WATCH.summarize_peer(value, 100)
        self.assertEqual(result['state'], 'up')
        self.assertEqual(result['authorized_rooms'], 1)
        self.assertNotIn('sentinel', json.dumps(result))
        value['daemon']['rooms'][0]['authorized'] = False
        self.assertEqual(WATCH.summarize_peer(value, 100)['state'], 'unavailable')

    def test_success_hold_failure_are_not_interchangeable(self):
        for state, reason in [('success', 'evaluation_applied'),
                              ('hold', 'model_abstained'),
                              ('failure', 'model_failed')]:
            value = runner(state, reason)
            value.update(prompt='private-prompt-sentinel',
                         question_id='private-id-sentinel')
            result = WATCH.summarize_runner(value, 100)
            self.assertEqual(result['state'], state)
            self.assertEqual(result['reason'], reason)
            self.assertNotIn('sentinel', json.dumps(result))
        self.assertEqual(WATCH.summarize_runner(
            runner('hold', 'dry_run_complete'), 100)['state'], 'unavailable')

    def test_success_requires_actual_success_count(self):
        value = runner()
        value['counts']['successes'] = 0
        self.assertEqual(WATCH.summarize_runner(value, 100)['state'], 'unavailable')

    def test_empty_and_completed_queue_idle_do_not_invent_attempts(self):
        for reason in ['no_open_questions', 'no_eligible_answer']:
            for successes in [0, 1]:
                value = runner('hold', reason)
                value.update(started_at=None, completed_at=None, deadline_at=None)
                value['counts'] = {'attempts': successes, 'successes': successes,
                                   'failures': 0, 'holds': 0}
                result = WATCH.summarize_runner(value, 100)
                self.assertEqual(result['state'], 'hold')
                self.assertEqual(result['counts'], value['counts'])

    def test_running_deadline_is_not_a_success(self):
        value = runner('running', 'running')
        value.update(completed_at=None, last_success_at=None)
        self.assertEqual(WATCH.summarize_runner(value, 269)['state'], 'running')
        expired = WATCH.summarize_runner(value, 270)
        self.assertEqual((expired['state'], expired['reason']),
                         ('running', 'running'))
        self.assertEqual(expired['counts']['failures'], 0)
        value['deadline_at'] = 391
        self.assertEqual(WATCH.summarize_runner(value, 100)['state'], 'unavailable')

    def test_not_run_is_explicit_without_success(self):
        value = runner('not_run', 'not_run')
        value.update(started_at=None, completed_at=None, deadline_at=None,
                     last_success_at=None)
        value['counts']['attempts'] = 0
        result = WATCH.summarize_runner(value, 100)
        self.assertEqual(result['state'], 'not_run')
        self.assertEqual(result['counts']['successes'], 0)

    def test_malformed_unknown_and_future_status_are_unavailable(self):
        for key, invalid in [('version', True), ('reason', 'private-error-sentinel'),
                             ('checked_at', 161), ('counts', None)]:
            value = runner(); value[key] = invalid
            result = WATCH.summarize_runner(value, 100)
            self.assertEqual(result['state'], 'unavailable')
            self.assertNotIn('sentinel', json.dumps(result))
        for invalid in [True, -1, 1.5, 2**53]:
            value = runner(); value['counts']['attempts'] = invalid
            self.assertEqual(WATCH.summarize_runner(value, 100)['state'], 'unavailable')

    def test_actual_operator_credit_cannot_be_enabled_by_inventory(self):
        self.assertTrue(WATCH.config_valid(config()))
        for key, invalid in [('synthetic', False), ('model_tools', True),
                             ('actual_operator_contribution', 1),
                             ('common_controller', 'independent'),
                             ('operator', 'private-label-sentinel')]:
            value = config(); value[key] = invalid
            self.assertFalse(WATCH.config_valid(value))

    def test_missing_runner_does_not_hide_peer(self):
        def invoke(argv, **_kwargs):
            if argv[-1] == 'runner-status':
                raise RuntimeError('private-error-sentinel')
            return {'status': 'healthy', 'daemon': {
                'status': 'ready', 'version': '0.4.0', 'uptime_seconds': 1,
                'connected_peers': 0,
                'rooms': [{'authorized': True, 'expires_at': 1000}]}}
        result = WATCH.collect(config(), 100, invoke)
        self.assertEqual(result['peer']['state'], 'up')
        self.assertEqual(result['runner']['state'], 'unavailable')
        self.assertEqual(result['actual_operator_contribution'], 0)
        self.assertNotIn('sentinel', json.dumps(result))

    def test_subprocess_output_and_timeout_are_bounded(self):
        for command, options in [
            ([sys.executable, '-c', 'print("x"*100)'], {'limit': 16}),
            ([sys.executable, '-c', 'import time; time.sleep(1)'],
             {'timeout': 0.02}),
        ]:
            with self.assertRaises(RuntimeError):
                WATCH.bounded_call(command, **options)
        self.assertEqual(WATCH.bounded_call(
            [sys.executable, '-c', 'print("{}")']), {})

    def test_atomic_metadata_files_are_private_and_leave_no_temp_files(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)/'delegation-status.json'
            WATCH.save(path, {'state': 'hold'})
            WATCH.save(path, {'state': 'success'})
            self.assertEqual(json.loads(path.read_text())['state'], 'success')
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(len(list(Path(d).iterdir())), 1)


if __name__ == '__main__':
    unittest.main()
