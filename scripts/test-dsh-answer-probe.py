#!/usr/bin/env python3
"""実モデル・実SDKを呼ばず、一回検証のtarget/WAL/no-tools境界を確認する。"""
import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('answer_probe', Path(__file__).with_name('verify-dsh-answer.py'))
P = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(P)
J = P.J
TASK = {'version': 1, 'question_id': 'a' * 64, 'run_number': 1}
CFG = {'room_alias': 'dsh-lab', 'room': {'certificate': {'signed': {
    'room_id': 'b' * 64, 'epoch': 2, 'members': [{'peer_id': 'dsh'}]}}}}
QUESTION = {'message_id': TASK['question_id'], 'thread_id': TASK['question_id'], 'reply_to': None,
            'kind': 'question', 'public': False, 'untrusted': True, 'question_state': 'open',
            'created_at': 100, 'title': 'Explicit question', 'body': 'Facts and question.', 'references': []}


class FakeBroker:
    infer_count = 0
    post_count = 0
    status = 'answer'
    fail_post = False
    state_path = None

    def __init__(self, _cfg, _deadline): pass
    def question(self, identifier):
        assert identifier == TASK['question_id']
        return 'dsh', copy.deepcopy(QUESTION)
    def infer(self, question, _response_path):
        type(self).infer_count += 1
        assert question == QUESTION
        return {'version': 1, 'status': self.status,
                'body': 'Original answer.' if self.status == 'answer' else ''}, 'f' * 64
    def post(self, identifier, draft):
        type(self).post_count += 1
        assert identifier == TASK['question_id']
        assert draft == {'kind': 'answer', 'title': P.TITLE, 'body': 'Original answer.', 'references': []}
        durable = json.loads(self.state_path.read_text())
        assert durable['phase'] == 'posting' and durable['post_attempts'] == 1
        assert durable['draft_and_target_digest'] == J.digest([identifier, False, draft])
        if self.fail_post:
            raise J.Failure('ipc_unavailable')
        return 0, {'status': 'accepted', 'enqueued': True, 'request_id': 'c' * 64}


class ProbeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / 'answer-probe.json'
        FakeBroker.infer_count = FakeBroker.post_count = 0
        FakeBroker.status = 'answer'; FakeBroker.fail_post = False
        FakeBroker.state_path = self.path

    def tearDown(self): self.temp.cleanup()

    def test_manifest_has_no_model_target_or_command_override(self):
        self.assertEqual(P.manifest(TASK), TASK)
        for bad in [dict(TASK, public=True), dict(TASK, reply_to='c' * 64),
                    dict(TASK, question_id='invalid'), dict(TASK, version=True),
                    dict(TASK, run_number=5), dict(TASK, run_number=True)]:
            with self.assertRaises(J.Failure): P.manifest(bad)

    def test_model_schema_rejects_target_tools_metadata_and_invalid_body(self):
        good = {'body': 'Answer with reasoning.'}
        self.assertEqual(P.validate_answer(good), {'version': 1, 'status': 'answer', **good})
        self.assertEqual(P.validate_answer({'body': ''})['status'], 'abstain')
        for key, value in [('version', True), ('status', 'post'), ('reply_to', 'c' * 64),
                           ('tools', []), ('public', True), ('body', 'x' * 4097), ('body', '\x00')]:
            bad = dict(good); bad[key] = value
            with self.subTest(key=key), self.assertRaises(J.Failure): P.validate_answer(bad)

    def test_target_and_private_draft_pinned_and_fsynced_before_sdk_post(self):
        result = P.run(CFG, TASK, self.path, FakeBroker)
        self.assertEqual(result['phase'], 'accepted')
        self.assertIs(result['independent_rubric_verified'], False)
        self.assertIs(result['delivery_confirmed_by_submit_result'], False)
        self.assertEqual((FakeBroker.infer_count, FakeBroker.post_count), (1, 1))
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_completed_duplicate_never_reinfers_or_reposts(self):
        P.run(CFG, TASK, self.path, FakeBroker)
        result = P.run(CFG, TASK, self.path, FakeBroker)
        self.assertTrue(result['duplicate'])
        self.assertEqual((FakeBroker.infer_count, FakeBroker.post_count), (1, 1))

    def test_lost_post_response_is_explicit_unknown_and_never_retried(self):
        FakeBroker.fail_post = True
        with self.assertRaises(J.Failure) as error: P.run(CFG, TASK, self.path, FakeBroker)
        self.assertEqual(error.exception.reason, 'apply_outcome_unknown')
        self.assertEqual(json.loads(self.path.read_text())['phase'], 'unknown')
        result = P.run(CFG, TASK, self.path, FakeBroker)
        self.assertEqual(result['phase'], 'unknown')
        self.assertEqual((FakeBroker.infer_count, FakeBroker.post_count), (1, 1))

    def test_abstention_sends_no_post_and_is_not_reinferred(self):
        FakeBroker.status = 'abstain'
        self.assertEqual(P.run(CFG, TASK, self.path, FakeBroker)['phase'], 'abstained')
        P.run(CFG, TASK, self.path, FakeBroker)
        self.assertEqual((FakeBroker.infer_count, FakeBroker.post_count), (1, 0))

    def test_different_question_cannot_reuse_existing_probe_state(self):
        P.run(CFG, TASK, self.path, FakeBroker)
        with self.assertRaises(J.Failure):
            P.run(CFG, dict(TASK, question_id='d' * 64), self.path, FakeBroker)
        self.assertEqual(FakeBroker.post_count, 1)

    def test_explicit_new_run_only_after_known_no_post_failure(self):
        previous = {'policy': P.POLICY, 'task': TASK, 'phase': 'failed', 'post_attempts': 0}
        J.atomic(self.path, previous)
        P.authorize_new_run(dict(TASK, run_number=2), self.path.parent)
        for phase, attempts in [('unknown', 1), ('posting', 1), ('accepted', 1), ('inference', 0)]:
            J.atomic(self.path, dict(previous, phase=phase, post_attempts=attempts))
            with self.subTest(phase=phase), self.assertRaises(J.Failure):
                P.authorize_new_run(dict(TASK, run_number=2), self.path.parent)

    def test_new_run_cannot_change_question_or_skip_retained_history(self):
        J.atomic(self.path, {'policy': P.POLICY, 'task': TASK, 'phase': 'failed', 'post_attempts': 0})
        with self.assertRaises(J.Failure):
            P.authorize_new_run(dict(TASK, question_id='f' * 64, run_number=2), self.path.parent)
        with self.assertRaises(FileNotFoundError):
            P.authorize_new_run(dict(TASK, run_number=3), self.path.parent)

    def test_crash_reservation_never_starts_a_second_inference_or_post(self):
        J.atomic(self.path, {'manifest_digest': J.digest([P.POLICY, 'b' * 64, TASK]), 'phase': 'posting'})
        result = P.run(CFG, TASK, self.path, FakeBroker)
        self.assertEqual(result['phase'], 'posting')
        self.assertEqual((FakeBroker.infer_count, FakeBroker.post_count), (0, 0))

    def test_sdk_post_argv_has_fixed_private_thread_target(self):
        broker = P.Broker(CFG, time.monotonic() + 20)
        with patch.object(broker, 'sdk', return_value=(0, {})) as sdk:
            broker.post(TASK['question_id'], {'kind': 'answer'})
        args, draft = sdk.call_args.args
        self.assertIn('--reply-to', args)
        self.assertEqual(args[args.index('--reply-to') + 1], TASK['question_id'])
        self.assertNotIn('--public', args)
        self.assertEqual(draft, {'kind': 'answer'})

    def test_question_must_be_open_private_and_in_exact_thread(self):
        broker = P.Broker(CFG, time.monotonic() + 20)
        info = {'peer_id': 'dsh', 'rooms': [{'name': 'dsh-lab', 'authorized': True, 'public': False, 'epoch': 2}]}
        for key, value in [('public', True), ('question_state', 'answered'),
                           ('thread_id', 'd' * 64), ('reply_to', 'd' * 64), ('kind', 'answer')]:
            question = dict(QUESTION); question[key] = value
            with patch.object(broker, 'sdk', return_value=(0, info)), \
                    patch.object(broker, 'thread', return_value=[question]):
                with self.subTest(key=key), self.assertRaises(J.Failure): broker.question(TASK['question_id'])

    def test_model_input_has_no_ids_or_sdk_and_returned_tools_are_rejected(self):
        class Response:
            def __enter__(self): return self
            def __exit__(self, *_args): pass
            def read(self, _limit):
                return json.dumps({'choices': [{'finish_reason': 'stop', 'message': {
                    'content': '{}', 'tool_calls': [{'name': 'shell'}]}}]}).encode()
        class Opener:
            def open(inner, request, timeout):
                payload = json.loads(request.data)
                self.assertEqual(request.full_url, J.ENDPOINT)
                self.assertNotIn('tools', payload)
                self.assertEqual(payload['tool_choice'], 'none')
                self.assertFalse(payload['store'])
                user = json.loads(payload['messages'][1]['content'])
                self.assertEqual(set(user), {'untrusted_question'})
                self.assertEqual(set(user['untrusted_question']), {'title', 'body', 'references'})
                self.assertNotIn(TASK['question_id'], payload['messages'][1]['content'])
                self.assertLessEqual(timeout, 180)
                return Response()
        broker = P.Broker(CFG, time.monotonic() + 180)
        with patch.object(P.urllib.request, 'build_opener', return_value=Opener()), \
                patch.object(J.subprocess, 'run') as commands:
            with self.assertRaises(J.Failure): broker.infer(QUESTION, self.path.with_suffix('.response'))
            commands.assert_not_called()
        self.assertEqual(self.path.with_suffix('.response').stat().st_mode & 0o777, 0o600)


if __name__ == '__main__': unittest.main()
