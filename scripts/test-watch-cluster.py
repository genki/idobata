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


class WatchClusterTests(unittest.TestCase):
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
            for label in ['../v02', '/tmp/other', 'v03/../../history', 'v04']:
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


if __name__ == '__main__':
    unittest.main()
