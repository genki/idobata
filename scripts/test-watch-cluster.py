#!/usr/bin/env python3
"""集計の情報境界と観測系列の分離を、実機操作なしで確認する。"""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    'watch_cluster', Path(__file__).with_name('watch-cluster.py'))
WATCH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(WATCH)


def knowledge():
    return {
        'storage': {'bytes': 1024, 'quota_bytes': 64 * 1024 * 1024,
                    'objects': 2, 'reviews': 1, 'max_objects': 8192},
        'replication_factor': 3, 'staging_records': 1,
        'pending_replications': 1, 'pending_repairs': 2,
        'pending_inventory_pages': 3, 'pending_automation': 0,
    }


def ledger(reason):
    value = {'status': 'hold', 'reason': reason, 'experiment_only': True,
             'chain_id': 'private-chain-sentinel', 'peer_id': 'private-peer-sentinel',
             'pending': [{'transaction_id': 'private-tx-sentinel'}]}
    if reason == 'ledger_not_configured':
        return value
    value['consensus'] = {'height': 1, 'round': 0,
                          'status': 'hold_independent_operators',
                          'independent_operators': 1, 'quorum': 3,
                          'committed_blocks': 0, 'double_vote_evidence': 0,
                          'prevotes': 0, 'precommits': 0, 'locked': False,
                          'lock_round': None, 'valid_round': None,
                          'experiment_only': True, 'block_id': 'private-block-sentinel'}
    value.update(application_height=0, active_questions=0, closed_questions=0,
                 total_minted=0, pending_transactions=0, queued_requests=0,
                 seconds_since_commit=30, pending_requests=0)
    return value


class WatchClusterTests(unittest.TestCase):
    def test_new_canary_keeps_previous_receipts_while_waiting(self):
        previous = {'request_id': 'old-private-id', 'created_at': 100,
                    'complete': True, 'delivered_count': 3, 'recipient_count': 3}
        calls = []

        def invoke(_node, args, _data=None):
            calls.append(args[0])
            return ({'request_id': 'new-private-id'} if args[0] == 'post'
                    else {'delivered_count': 0, 'recipient_count': 3})

        result = WATCH.advance_canary([{}], previous, 3701, invoke)
        self.assertEqual(result['phase'], 'checking')
        self.assertEqual(result['deadline_at'], 3746)
        self.assertEqual(result['last_complete']['created_at'], 100)
        self.assertNotIn('private-id', json.dumps(result['last_complete']))
        self.assertEqual(calls, ['post', 'status'])
        self.assertTrue(previous['complete'])

    def test_pending_canary_deadline_is_not_reset_by_status_failure(self):
        current = {'request_id': 'private-id', 'created_at': 100,
                   'deadline_at': 145, 'complete': False, 'phase': 'checking'}

        def failed(*_args):
            raise RuntimeError('fixture_status_unavailable')

        pending = WATCH.advance_canary([{}], current, 130, failed)
        self.assertEqual(pending['phase'], 'checking')
        self.assertTrue(pending['check_failed'])
        expired = WATCH.advance_canary([{}], pending, 146, failed)
        self.assertEqual(expired['phase'], 'failed')
        self.assertEqual(expired['deadline_at'], 145)

    def test_pending_canary_becomes_complete_only_after_all_three_receipts(self):
        current = {'request_id': 'private-id', 'created_at': 100,
                   'deadline_at': 145, 'complete': False, 'phase': 'checking'}
        result = WATCH.advance_canary([{}], current, 130,
                                     lambda *_: {'delivered_count': 3, 'recipient_count': 3})
        self.assertEqual(result['phase'], 'complete')
        self.assertTrue(result['complete'])
        self.assertEqual(result['last_complete']['created_at'], 100)
        self.assertNotIn('request_id', result['last_complete'])

    def test_knowledge_contains_only_allowlisted_counts(self):
        value = knowledge()
        value['record_id'] = 'private-record-sentinel'
        value['query'] = 'private-query-sentinel'
        value['storage']['body'] = 'private-body-sentinel'
        result = WATCH.summarize_knowledge(value)
        self.assertEqual(result['status'], 'healthy')
        self.assertEqual(result['pending_repairs'], 2)
        self.assertNotIn('sentinel', json.dumps(result))
        self.assertNotIn('oldest_staging_age_seconds', result)

    def test_missing_or_malformed_counts_are_not_zero(self):
        self.assertEqual(WATCH.summarize_knowledge(None)['status'], 'unavailable')
        for invalid in [True, -1, 1.5, 'private-body-sentinel', 2**53]:
            value = knowledge()
            value['storage']['bytes'] = invalid
            result = WATCH.summarize_knowledge(value)
            self.assertEqual(result['status'], 'invalid')
            self.assertNotIn('sentinel', json.dumps(result))
        value = knowledge()
        del value['pending_repairs']
        result = WATCH.summarize_knowledge(value)
        self.assertIsNone(result['pending_repairs'])

    def test_quota_overrun_and_inconsistent_counts_are_invalid(self):
        value = knowledge()
        value['storage']['bytes'] = value['storage']['quota_bytes'] + 1
        result = WATCH.summarize_knowledge(value)
        self.assertEqual(result['reason'], 'knowledge_quota_exceeded')
        self.assertGreater(result['storage']['bytes'], result['storage']['quota_bytes'])
        for field, invalid in [('replication_factor', 4), ('staging_records', 3)]:
            value = knowledge()
            value[field] = invalid
            self.assertEqual(WATCH.summarize_knowledge(value)['status'], 'invalid')

    def test_observe_excludes_raw_identity_and_preserves_room_flag(self):
        info = {
            'version': '0.3.0', 'uptime_seconds': 10, 'policy_id': 'public-profile',
            'peer_id': 'private-peer-sentinel', 'body': 'private-body-sentinel',
            'connected_peers': 0, 'pending_count': 0, 'held_count': 0,
            'delivered_count': 3, 'knowledge': knowledge(),
            'rooms': [{'name': 'engineering', 'authorized': True,
                       'expires_at': 20_000, 'epoch': 2,
                       'knowledge_automation_required': True}],
        }
        with patch.object(WATCH, 'call', return_value={'status': 'healthy', 'daemon': info}):
            result = WATCH.observe({'label': 'fixture', 'platform': 'linux'})
        self.assertEqual(result['knowledge']['status'], 'healthy')
        self.assertTrue(result['rooms'][0]['knowledge_automation_required'])
        self.assertNotIn('sentinel', json.dumps(result))

    def test_v03_starts_fresh_without_reusing_or_overwriting_v02_history(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            old = {'version': 1, 'started_at': 1, 'checked_at': 500_000,
                   'samples': 10_000, 'elapsed_seconds': 499_999}
            legacy = root / 'stability.json'
            legacy.write_text(json.dumps(old))
            before = legacy.read_bytes()
            self.assertEqual(WATCH.load_history(root, 'v03', 500_100), {})
            fresh = {'version': 2, 'series': 'v03', 'started_at': 500_100,
                     'checked_at': 500_100, 'samples': 1, 'elapsed_seconds': 0}
            WATCH.save(WATCH.history_path(root, 'v03'), fresh)
            self.assertEqual(legacy.read_bytes(), before)
            resumed = WATCH.load_history(root, 'v03', 500_130)
            self.assertEqual(resumed['started_at'], 500_100)
            self.assertEqual(resumed['samples'], 1)
            self.assertEqual(WATCH.load_history(root, 'v02', 500_130), old)

    def test_series_path_traversal_and_wrong_version_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for label in ['../v02', '/tmp/other', 'v03/../../history', 'v05']:
                with self.assertRaises(ValueError):
                    WATCH.history_path(root, label)
            for previous in [
                {'version': 1, 'series': 'v03', 'started_at': 10, 'checked_at': 20, 'samples': 1},
                {'version': 2, 'series': 'v02', 'started_at': 10, 'checked_at': 20, 'samples': 1},
                {'version': 2, 'series': 'v03', 'started_at': 30, 'checked_at': 20, 'samples': 1},
            ]:
                WATCH.history_path(root, 'v03').write_text(json.dumps(previous))
                with self.assertRaises(ValueError):
                    WATCH.load_history(root, 'v03', 100)

    def test_required_room_is_checked_without_changing_authorization(self):
        observation = {'rooms': [{'name': 'engineering',
                                  'knowledge_automation_required': True}]}
        self.assertTrue(WATCH.automation_rooms_healthy(observation, ['engineering']))
        self.assertFalse(WATCH.automation_rooms_healthy(observation, ['commons']))
        self.assertEqual(observation['rooms'][0]['name'], 'engineering')

    def test_v04_does_not_reuse_or_overwrite_v03_history(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            old = {'version': 2, 'series': 'v03', 'started_at': 1,
                   'checked_at': 500_000, 'samples': 10_000}
            path = WATCH.history_path(root, 'v03')
            path.write_text(json.dumps(old))
            before = path.read_bytes()
            self.assertEqual(WATCH.load_history(root, 'v04', 500_100), {})
            WATCH.save(WATCH.history_path(root, 'v04'),
                       {'version': 2, 'series': 'v04', 'started_at': 500_100,
                        'checked_at': 500_100, 'samples': 1})
            self.assertEqual(path.read_bytes(), before)
            self.assertEqual(WATCH.load_history(root, 'v04', 500_130)['samples'], 1)

    def test_public_cache_empty_is_healthy_failure_is_distinct_and_unknown_fields_drop(self):
        value = {'version': 1, 'cache_available': True, 'cache_write_failed': False, 'sources': 0, 'bytes': 0,
                 'partial_snapshots': 200, 'active_queries': 0,
                 'body': 'private-sentinel', 'peer_id': 'private-sentinel'}
        self.assertEqual(WATCH.summarize_public_projection(value)['status'], 'healthy')
        self.assertNotIn('sentinel', json.dumps(WATCH.summarize_public_projection(value)))
        value['cache_write_failed'] = True
        self.assertEqual(WATCH.summarize_public_projection(value)['reason'],
                         'public_cache_write_failed')
        value['cache_write_failed'] = False
        self.assertEqual(WATCH.summarize_public_projection(value)['status'], 'healthy')
        value['cache_available'] = False
        self.assertEqual(WATCH.summarize_public_projection(value)['status'], 'fault')
        for key, invalid in [('version', True), ('sources', 257),
                             ('bytes', 4 * 1024 * 1024 + 1), ('active_queries', -1)]:
            value = {'version': 1, 'cache_available': True, 'cache_write_failed': False, 'sources': 0, 'bytes': 0,
                     'partial_snapshots': 0, 'active_queries': 0}
            value[key] = invalid
            self.assertEqual(WATCH.summarize_public_projection(value)['status'], 'invalid')

    def test_ledger_hold_fault_and_numeric_allowlist(self):
        for reason in ['ledger_not_configured', 'insufficient_independent_operators']:
            value = ledger(reason)
            result = WATCH.summarize_ledger(value)
            self.assertEqual(result['status'], 'hold')
            self.assertEqual(result['reason'], reason)
            self.assertNotIn('sentinel', json.dumps(result))
        value = {'status': 'fault', 'reason': 'private-error-sentinel',
                 'experiment_only': True, 'peer_id': 'private-peer-sentinel'}
        result = WATCH.summarize_ledger(value)
        self.assertEqual(result, {'status': 'fault', 'reason': 'ledger_fault',
                                  'experiment_only': True})
        for malformed in [[], {}, 123]:
            self.assertEqual(WATCH.summarize_ledger(
                {'status': 'fault', 'reason': malformed,
                 'experiment_only': True})['reason'], 'ledger_fault')
            self.assertEqual(WATCH.summarize_ledger(
                {'status': 'hold', 'reason': malformed,
                 'experiment_only': True})['status'], 'invalid')
        value = ledger('insufficient_independent_operators')
        value.update(status='ready', reason=None)
        self.assertEqual(WATCH.summarize_ledger(value)['status'], 'invalid')
        value = ledger('insufficient_independent_operators')
        value['consensus']['height'] = True
        self.assertEqual(WATCH.summarize_ledger(value)['status'], 'invalid')

    def test_authorization_regression_hold_fails_stability_but_normal_hold_does_not(self):
        observation = {'status': 'up', 'knowledge': {'status': 'healthy'},
                       'public_projection': {'status': 'healthy'},
                       'ledger': {'status': 'hold', 'reason': 'ledger_not_configured'},
                       'rooms': []}
        self.assertTrue(WATCH.observation_healthy(observation, 'v04', []))
        observation['ledger']['reason'] = 'ledger_room_authorization_changed'
        self.assertFalse(WATCH.observation_healthy(observation, 'v04', []))

    def test_v04_ledger_fault_does_not_make_live_healthy_knowledge_peer_look_stopped(self):
        info = {'status': 'ready', 'version': '0.4.0', 'uptime_seconds': 10,
                'policy_id': 'public-profile', 'connected_peers': 3,
                'pending_count': 0, 'held_count': 0, 'delivered_count': 3,
                'knowledge': knowledge(),
                'ledger': {'status': 'fault', 'reason': 'protected_storage_failed',
                           'experiment_only': True},
                'rooms': [{'name': 'engineering', 'authorized': True,
                           'expires_at': 20_000, 'epoch': 2,
                           'knowledge_automation_required': True}]}
        info['knowledge']['public_projection'] = {
            'version': 1, 'cache_available': True, 'cache_write_failed': False, 'sources': 0, 'bytes': 0,
            'partial_snapshots': 0, 'active_queries': 0}
        with patch.object(WATCH, 'call', return_value={'status': 'degraded', 'daemon': info}):
            result = WATCH.observe({'label': 'fixture', 'platform': 'linux'}, 'v04')
        self.assertEqual(result['status'], 'up')
        self.assertEqual(result['knowledge']['status'], 'healthy')
        self.assertEqual(result['ledger']['status'], 'fault')
        self.assertFalse(WATCH.observation_healthy(result, 'v04', ['engineering']))
        with patch.object(WATCH, 'call', return_value={'status': 'degraded', 'daemon': info}):
            self.assertEqual(WATCH.observe({'label': 'fixture', 'platform': 'linux'}, 'v03')['status'], 'down')
        info['rooms'][0]['authorized'] = False
        with patch.object(WATCH, 'call', return_value={'status': 'degraded', 'daemon': info}):
            self.assertEqual(WATCH.observe({'label': 'fixture', 'platform': 'linux'}, 'v04')['status'], 'down')


if __name__ == '__main__':
    unittest.main()
