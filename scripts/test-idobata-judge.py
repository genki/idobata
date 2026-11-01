#!/usr/bin/env python3
"""推論を行わず、境界・typed判断・durable再実行防止を検証する。"""
import copy
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import time
import sys
import unittest
from unittest.mock import patch

import idobata_judge as J
from idobata_judge_automation import public_task_cases, solve_automation_challenge


def cfg(directory):
    return {'version': 1, 'room_alias': 'dsh-lab', 'deadline_seconds': 180,
            'room': {'authority_peer_id': 'authority', 'certificate': {'signed': {
                'room_id': 'r' * 64, 'public': False, 'knowledge_automation_required': True,
                'policy_id': 'p' * 64, 'members': [
                    {'peer_id': 'subject', 'public_key': 'subject-key'},
                    {'peer_id': 'issuer', 'public_key': 'issuer-key'}]}}},
            'state': str(directory), 'sdk': '/trusted/sdk', 'socket': '/fixed/ipc'}


TASK = {'version': 1, 'query': '明示対象', 'question_id': 'a' * 64, 'answer_id': 'b' * 64}
RECORDS = [{'problem': '2と2の和は何ですか。', 'solution': '整数の和を答えてください。',
            'context': '算術の確認。'},
           {'problem': '2と2の和', 'solution': '4です。', 'context': '同じ前提です。'}]


class FakeBroker:
    inferences = 0
    evaluations = 0
    judgment = 'useful'
    fail_apply = False
    records_value = RECORDS

    def __init__(self, _cfg, _deadline):
        pass

    def records(self, _task):
        return 'subject', copy.deepcopy(self.records_value)

    def infer(self, prompt):
        type(self).inferences += 1
        return {'version': 1, **{key: prompt[key] for key in [
            'job_digest', 'question_id', 'answer_id']},
            'judgment': self.judgment, 'reason': '整数の和が四であり条件を満たします。'}

    def evaluate(self, _task, _decision, _subject, _directory):
        type(self).evaluations += 1
        if self.fail_apply:
            raise J.Failure('apply_outcome_unknown')


class JudgeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name) / 'state'
        self.store = J.Store(self.directory)
        self.cfg = cfg(self.directory)
        FakeBroker.inferences = FakeBroker.evaluations = 0
        FakeBroker.judgment = 'useful'; FakeBroker.fail_apply = False
        FakeBroker.records_value = RECORDS

    def tearDown(self):
        self.store.close(); self.temporary.cleanup()

    def run_job(self, apply=False):
        return J.execute(self.cfg, TASK, self.store, apply, FakeBroker)

    def test_duplicate_keys_trailing_json_and_nonfinite_numbers_rejected(self):
        for raw in ['{"x":1,"x":2}', '{} {}', '{"x":NaN}', '{"x":1e999}']:
            with self.subTest(raw=raw), self.assertRaises(J.Failure):
                J.strict_json(raw)

    def test_sdk_quality_floats_and_private_timestamp_journal_survive_reopen(self):
        self.assertEqual(J.strict_json('{"quality":{"value":0.5}}')['quality']['value'], 0.5)
        self.run_job()
        self.store.close()
        self.store = J.Store(self.directory)
        self.run_job(apply=True)
        self.assertEqual((FakeBroker.inferences, FakeBroker.evaluations), (1, 1))

    def test_decision_rejects_extra_fields_target_swap_and_boolean_version(self):
        prompt = {'job_digest': 'c' * 64, 'question_id': 'a' * 64, 'answer_id': 'b' * 64}
        good = {'version': 1, **prompt, 'judgment': 'useful', 'reason': '条件に合います。'}
        for field, value in [('version', True), ('answer_id', 'x' * 64),
                             ('judgment', 'execute'), ('reason', 'line\ncommand'),
                             ('shell', 'do not execute this')]:
            bad = dict(good); bad[field] = value
            with self.subTest(field=field), self.assertRaises(J.Failure):
                J.validate_decision(bad, prompt)

    def test_model_only_decides_verdict_and_reason_local_snapshot_pins_target(self):
        prompt = {'job_digest': 'c' * 64, 'question_id': 'a' * 64, 'answer_id': 'b' * 64}
        decision = {'version': 1, 'judgment': 'not_useful', 'reason': '答えは条件に合いません。'}
        bound = J.bind_model_decision(decision, prompt)
        self.assertEqual({key: bound[key] for key in prompt}, prompt)
        self.assertEqual(bound['judgment'], 'not_useful')
        for key in ['question_id', 'answer_id', 'job_digest', 'shell']:
            with self.subTest(key=key), self.assertRaises(J.Failure) as error:
                J.bind_model_decision(dict(decision, **{key: 'another target'}), prompt)
            self.assertEqual(error.exception.detail, 'judgment_schema')

    def test_invalid_judgment_records_static_rejection_stage_without_applying(self):
        class Rejected(FakeBroker):
            def infer(self, _prompt):
                raise J.Failure('invalid_judgment', detail='judgment_schema')
        with self.assertRaises(J.Failure):
            J.execute(self.cfg, TASK, self.store, True, Rejected)
        entry = next(iter(self.store.value['jobs'].values()))
        self.assertEqual(entry['rejection_stage'], 'judgment_schema')
        self.assertEqual(entry['rejected_phase'], 'inference')
        self.assertEqual(FakeBroker.evaluations, 0)
        self.assertEqual(self.store.value['counts']['failures'], 1)

    def test_dry_run_then_apply_reuses_exact_decision_and_duplicate_never_resends(self):
        self.run_job()
        self.assertEqual((FakeBroker.inferences, FakeBroker.evaluations), (1, 0))
        self.run_job(apply=True); self.run_job(apply=True)
        self.assertEqual((FakeBroker.inferences, FakeBroker.evaluations), (1, 1))
        self.assertEqual(self.store.value['counts'], {
            'attempts': 2, 'successes': 2, 'failures': 0, 'holds': 0})

    def test_abstain_is_hold_without_evaluation_or_repeated_inference(self):
        FakeBroker.judgment = 'abstain'
        self.run_job(apply=True); self.run_job(apply=True)
        self.assertEqual((FakeBroker.inferences, FakeBroker.evaluations), (1, 0))
        self.assertEqual(self.store.status_state, 'hold')
        self.assertEqual(self.store.reason, 'model_abstained')

    def test_unknown_apply_is_permanent_failure_without_retry(self):
        FakeBroker.fail_apply = True
        for _ in range(2):
            with self.assertRaises(J.Failure) as error:
                self.run_job(apply=True)
            self.assertEqual(error.exception.reason, 'apply_outcome_unknown')
        self.assertEqual((FakeBroker.inferences, FakeBroker.evaluations), (1, 1))
        self.assertEqual(self.store.status_state, 'failure')
        self.assertEqual(self.store.value['counts']['failures'], 1)

    def test_crash_after_apply_reservation_does_not_repeat_model_or_sdk(self):
        key = J.digest([J.POLICY, self.cfg['room']['certificate']['signed']['room_id'],
                        TASK['question_id'], TASK['answer_id']])
        self.store.value['jobs'][key] = {'phase': 'applying', 'counted': False}
        self.store.value['counts']['attempts'] = 1; self.store.save()
        with self.assertRaises(J.Failure):
            self.run_job(apply=True)
        self.assertEqual((FakeBroker.inferences, FakeBroker.evaluations), (0, 0))

    def test_target_content_change_after_dry_run_blocks_apply(self):
        self.run_job()
        FakeBroker.records_value = copy.deepcopy(RECORDS)
        FakeBroker.records_value[1]['solution'] = '5です。'
        with self.assertRaises(J.Failure):
            self.run_job(apply=True)
        self.assertEqual(FakeBroker.evaluations, 0)

    def test_safe_status_does_not_contain_ids_private_reason_or_model_text(self):
        self.run_job()
        status = (self.directory / 'status.json').read_text()
        self.assertNotIn(TASK['answer_id'], status)
        self.assertNotIn('整数の和', status)
        self.assertEqual((self.directory / 'journal.json').stat().st_mode & 0o777, 0o600)
        self.assertEqual((self.directory / 'status.json').stat().st_mode & 0o777, 0o600)

    def test_corrupt_journal_is_not_reinitialized(self):
        self.store.close(); self.store.path.write_text('{bad')
        before = self.store.path.read_bytes()
        with self.assertRaises(J.Failure):
            J.Store(self.directory)
        self.assertEqual(self.store.path.read_bytes(), before)

    def test_trusted_job_requires_fixed_shape_owner_and_regular_file(self):
        path = Path(self.temporary.name) / 'job.json'
        path.write_text(json.dumps(TASK)); path.chmod(0o600)
        with patch.object(J, 'TRUSTED_UID', os.geteuid()):
            self.assertEqual(J.job(path), TASK)
            path.chmod(0o666)
            with self.assertRaises(J.Failure): J.job(path)
            path.chmod(0o600)
            linked = path.with_name('link.json'); linked.symlink_to(path)
            with self.assertRaises(J.Failure): J.job(linked)

    def test_broker_deadline_is_finite(self):
        with self.assertRaises(J.Failure):
            J.Broker(self.cfg, time.monotonic() - 1).remaining()

    def test_private_room_public_false_may_be_omitted_but_true_is_rejected(self):
        path = Path(self.temporary.name) / 'config.json'
        value = copy.deepcopy(self.cfg)
        value.update(sdk='/usr/local/lib/idobata/idobata', socket='/run/idobata/ipc.sock',
                     queue='/etc/idobata-judge/jobs', state='/home/dsh/.local/state/idobata-judge')
        value['room']['certificate']['signed']['room_id'] = 'a' * 64
        for setting in [False, None, True]:
            room = value['room']['certificate']['signed']
            if setting is None: room.pop('public', None)
            else: room['public'] = setting
            path.write_text(json.dumps(value))
            with patch.object(J, 'trusted', side_effect=lambda filename, **_kw: Path(filename)):
                if setting is True:
                    with self.assertRaises(J.Failure): J.config(path)
                else:
                    J.config(path)

    def test_pending_authorization_guard_existence_and_io_errors_fail_closed(self):
        marker = Path(self.temporary.name) / 'authorization-update.pending'
        marker.write_text('pending')
        with patch.object(J, 'AUTHORIZATION_UPDATE_PENDING', marker):
            with self.assertRaises(J.Failure) as error: J.config('/not-read')
            self.assertEqual(error.exception.reason, 'configuration_invalid')
        with patch.object(J, 'AUTHORIZATION_UPDATE_PENDING') as inaccessible:
            inaccessible.lstat.side_effect = PermissionError('static fixture')
            with self.assertRaises(J.Failure): J.config('/not-read')

    def test_authorization_configuration_is_reloaded_after_the_lock(self):
        self.store.close()
        queue = Path(self.temporary.name) / 'queue'; queue.mkdir()
        (queue / 'job.json').write_text(json.dumps(TASK))
        old = dict(self.cfg, queue=str(queue))
        new = copy.deepcopy(old); new['room']['certificate']['signed']['epoch'] = 2
        calls = []
        def execute(cfg, *_args):
            calls.append(cfg['room']['certificate']['signed']['epoch'])
        with patch.object(J, 'config', side_effect=[old, new]), \
                patch.object(J, 'runtime_identity'), patch.object(J, 'TRUSTED_UID', os.geteuid()), \
                patch.object(J, 'execute', side_effect=execute), \
                patch.object(sys, 'argv', ['runner']), contextlib.redirect_stdout(io.StringIO()):
            J.main()
        self.assertEqual(calls, [2])

    def test_authorization_update_between_initial_read_and_lock_blocks_execution(self):
        self.store.close()
        with patch.object(J, 'config', side_effect=[self.cfg, J.Failure('configuration_invalid')]), \
                patch.object(J, 'runtime_identity'), patch.object(J, 'execute') as execute, \
                patch.object(sys, 'argv', ['runner']), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(J.main(), 22)
        execute.assert_not_called()
        status = json.loads((self.directory / 'status.json').read_text())
        self.assertEqual(status['reason'], 'configuration_invalid')
        self.assertEqual(status['counts']['attempts'], 0)

    def test_control_plane_failure_does_not_invent_a_model_attempt(self):
        self.store.close()
        with patch.object(J, 'config', side_effect=J.Failure('configuration_invalid')), \
                patch.object(J, 'runtime_identity'), patch.object(J, 'AGENT_UID', os.geteuid()), \
                patch.object(J, 'DEFAULT_STATE', str(self.directory)), \
                patch.object(sys, 'argv', ['runner']), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(J.main(), 22)
        status = json.loads((self.directory / 'status.json').read_text())
        self.assertEqual(status['state'], 'failure')
        self.assertEqual(status['reason'], 'configuration_invalid')
        self.assertTrue(all(count == 0 for count in status['counts'].values()))

    def test_empty_queue_is_fresh_idle_without_fake_attempt_or_success(self):
        self.store.close()
        queue = Path(self.temporary.name) / 'queue'; queue.mkdir()
        value = dict(self.cfg, queue=str(queue))
        with patch.object(J, 'config', return_value=value) as load, patch.object(J, 'runtime_identity'), \
                patch.object(sys, 'argv', ['runner']), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(J.main(), 10)
            self.assertEqual(load.call_count, 2)
        status = json.loads((self.directory / 'status.json').read_text())
        self.assertEqual(status['state'], 'hold')
        self.assertEqual(status['reason'], 'no_open_questions')
        self.assertTrue(all(count == 0 for count in status['counts'].values()))
        self.assertIsNone(status['last_success_at'])
        self.assertIsNone(status['started_at'])
        self.assertIsNone(status['completed_at'])
        self.assertEqual(FakeBroker.inferences, 0)

    def test_model_request_has_no_tools_and_rejects_returned_tool_calls(self):
        prompt = {'version': 1, 'job_digest': 'c' * 64, 'question_id': 'a' * 64,
                  'answer_id': 'b' * 64, 'untrusted_question': RECORDS[0], 'untrusted_answer': RECORDS[1]}
        class Response:
            def __enter__(self): return self
            def __exit__(self, *_args): pass
            def read(self, _limit):
                return json.dumps({'choices': [{'finish_reason': 'stop', 'message': {
                    'content': '{}', 'tool_calls': [{'name': 'bash'}]}}]}).encode()
        class Opener:
            def open(inner, request, timeout):
                payload = json.loads(request.data)
                self.assertNotIn('tools', payload)
                self.assertEqual(payload['tool_choice'], 'none')
                self.assertIs(payload['store'], False)
                self.assertEqual(set(json.loads(payload['messages'][1]['content'])), {
                    'version', 'untrusted_question', 'untrusted_answer'})
                self.assertEqual(request.full_url, J.ENDPOINT)
                self.assertLessEqual(timeout, 180)
                return Response()
        broker = J.Broker(self.cfg, time.monotonic() + 180)
        with patch.object(J.urllib.request, 'build_opener', return_value=Opener()), \
                patch.object(J.subprocess, 'run') as shell:
            with self.assertRaises(J.Failure): broker.infer(prompt)
            shell.assert_not_called()

    def test_explicit_root_pair_get_does_not_depend_on_one_operator_explore_ranking(self):
        broker = J.Broker(self.cfg, time.monotonic() + 180)
        def sdk(arguments, _data=None):
            if arguments == ['info']:
                return 0, {'peer_id': 'subject', 'rooms': [{'name': 'dsh-lab',
                    'authorized': True, 'public': False, 'knowledge_automation_required': True}]}
            if arguments[1] == 'search':
                self.assertIn('--explore', arguments)
                return 0, {'search_mode': 'explore', 'hits': [{'id': 'c' * 64}]}
            identifier = arguments[-1]
            self.assertIn(identifier, [TASK['question_id'], TASK['answer_id']])
            return 0, {'found': True, 'untrusted': True, 'public_key': 'issuer-key',
                'record': {'id': identifier, 'room_id': 'r' * 64, 'public': False,
                    'author_peer_id': 'issuer', 'policy_id': 'p' * 64, **RECORDS[0]}}
        broker.sdk = sdk
        subject, records = broker.records(TASK)
        self.assertEqual(subject, 'subject')
        self.assertEqual(len(records), 2)

    def challenge(self, review):
        room = self.cfg['room']['certificate']['signed']
        claim = {'version': 1, 'id': 'd' * 64, 'room_id': room['room_id'],
                 'subject_peer_id': 'subject', 'action_digest': J.digest([
                     room['room_id'], TASK['answer_id'], 'subject', review,
                     J.digest(J.canonical_room(self.cfg['room'])['certificate'])]),
                 'purpose': 'evaluate', 'issued_at': int(time.time()),
                 'expires_at': int(time.time()) + 120, 'seed': '0' * 64}
        return {'status': 'automation_challenge_required', 'enqueued': False, 'stored': False,
                'untrusted': True, 'task_spec': {'algorithm': 'sha256-u16le-sort-rotate-fold-v1',
                    'version': 1, 'case_count': 24, 'values_per_case': 16,
                    'assurance': 'automation_tested'}, 'tasks': public_task_cases(claim['seed']),
                'challenge': {'challenge': {'signed': claim, 'public_key': 'issuer-key',
                    'signature': 'test-only'}, 'certificate': self.cfg['room']}}

    def test_automation_is_target_bound_and_proof_is_private_then_removed(self):
        broker = J.Broker(self.cfg, time.monotonic() + 180)
        decision = {'judgment': 'useful', 'reason': '条件に合います。'}
        calls = []
        def sdk(arguments, data):
            calls.append(arguments)
            if len(calls) == 1: return 31, self.challenge(data)
            proof = Path(arguments[-1])
            self.assertEqual(proof.stat().st_mode & 0o777, 0o600)
            self.assertEqual(len(json.loads(proof.read_text())['answers']), 24)
            return 0, {'status': 'accepted', 'id': TASK['answer_id'], 'evaluation_applied': True}
        broker.sdk = sdk
        broker.evaluate(TASK, decision, 'subject', self.directory)
        self.assertEqual(len(calls), 2)
        self.assertFalse(Path(calls[-1][-1]).exists())

    def test_automation_wrong_action_never_submits_proof(self):
        broker = J.Broker(self.cfg, time.monotonic() + 180)
        calls = []
        def sdk(arguments, data):
            calls.append(arguments); offered = self.challenge(data)
            offered['challenge']['challenge']['signed']['action_digest'] = 'f' * 64
            return 31, offered
        broker.sdk = sdk
        with self.assertRaises(J.Failure):
            broker.evaluate(TASK, {'judgment': 'not_useful', 'reason': '条件と違います。'},
                            'subject', self.directory)
        self.assertEqual(len(calls), 1)


if __name__ == '__main__':
    unittest.main()
