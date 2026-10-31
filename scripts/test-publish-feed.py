#!/usr/bin/env python3
"""Publisher transaction tests: every subprocess is fake; no cluster is contacted."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location('publisher', Path(__file__).with_name('publish-feed.py'))
PUBLISHER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PUBLISHER)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def feed(revision=10, expires=10500, posts=None):
    if posts is None:
        posts = [{'signed': {'id': 'test-post', 'policy_id': 'fixed-policy',
                             'content': {'body': '公開された通常の検証メモ'}}}]
    return {'public_key': 'public-test-publisher', 'signature': 'valid',
            'signed': {'version': 2, 'revision': revision, 'issued_at': expires-600,
                       'expires_at': expires, 'count': len(posts), 'withdrawn': [],
                       'feed': {'version': 1, 'updated_at': expires-600, 'posts': posts}}}


def bootstrap(revision=7, expires=10500, peer='public-test-peer'):
    return {'key_id': 'public-test-authority', 'signature': 'valid',
            'signed': {'version': 1, 'revision': revision, 'issued_at': expires-600,
                       'expires_at': expires,
                       'peers': [{'peer_id': peer, 'addresses': ['test-public-wss'],
                                  'roles': ['bootstrap'], 'advertised_at': expires-600,
                                  'expires_at': expires, 'signature': 'valid'}]}}


class PublisherFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        self.now = 10000
        self.calls = []
        self.patches = []
        self.verify_calls = []
        self.profile = {'policy_id': 'fixed-policy'}
        self.freeze_refresh = False
        self.forced_revision = None
        self.invalid_local = False
        self.next_posts = None
        self.next_withdrawn = None
        self.new_peer = 'public-test-peer'
        self.bootstrap_extra = {}
        self.peer_extra = {}
        self.patch_conflict = False
        self.readback_feed = None
        self.gets = 0
        self.current = {'metadata': {'resourceVersion': '10'},
                        'data': {'posts.json': encoded(feed()),
                                 'bootstrap.json': encoded(bootstrap())}}
        (self.home / 'posts.json').write_text(encoded(feed()))
        (self.home / 'bootstrap.json').write_text(encoded(bootstrap()))
        (self.home / 'publisher.json').write_text(encoded('public-test-publisher'))
        self.route = self.home / 'route.json'
        self.route.write_text(encoded({'reachable': True, 'signed_receipts': 1,
                                       'checked_at': self.now}))
        for patch in [mock.patch.object(PUBLISHER, 'HOME', self.home),
                      mock.patch.object(PUBLISHER, 'ROUTE', self.route),
                      mock.patch.object(PUBLISHER.time, 'time', lambda: self.now),
                      mock.patch.object(PUBLISHER.subprocess, 'run', self.runner)]:
            patch.start()
            self.addCleanup(patch.stop)
        (self.home / 'publication-context.json').write_text(
            encoded({'public_context': PUBLISHER.public_context()}))
        self.calls.clear()

    def runner(self, args, input=None, **_options):
        self.calls.append(list(args))
        def done(value=None, code=0):
            return subprocess.CompletedProcess(args, code, encoded(value) if value is not None else '', '')
        if args[0] == 'kubectl':
            self.assertEqual(args[1:5], ['--kubeconfig', str(self.home / 'kubeconfig'), '-n', 'default'])
            self.assertIn(args[5], ['get', 'patch'])
            self.assertEqual(args[6:8], ['configmap', 'idobata-feed'])
            if args[5] == 'get':
                self.gets += 1
                if self.gets > 1 and self.readback_feed is not None:
                    self.current['data']['posts.json'] = encoded(self.readback_feed)
                return done(copy.deepcopy(self.current))
            changes = json.loads(input)
            self.assertEqual(changes[0]['op'], 'test')
            self.assertEqual(changes[0]['path'], '/metadata/resourceVersion')
            if self.patch_conflict:
                return done(code=1)
            self.assertEqual(changes[0]['value'], self.current['metadata']['resourceVersion'])
            self.patches.append(copy.deepcopy(changes))
            for change in changes[1:]:
                self.assertIn(change['path'], ['/data/posts.json', '/data/bootstrap.json'])
                key = change['path'].split('/')[-1]
                if change['op'] == 'remove':
                    self.current['data'].pop(key)
                else:
                    self.current['data'][key] = change['value']
            self.current['metadata']['resourceVersion'] = str(int(self.current['metadata']['resourceVersion'])+1)
            return done()
        self.assertEqual(args[0], PUBLISHER.BINARY)
        if args[1:] == ['profile']:
            return done(self.profile)
        if 'refresh' in args:
            if not self.freeze_refresh:
                value = json.loads((self.home / 'posts.json').read_text())
                signed = value['signed']
                signed['revision'] = (self.forced_revision if self.forced_revision is not None
                                      else signed['revision']+1)
                signed['issued_at'] = self.now
                signed['expires_at'] = self.now+600
                if self.next_posts is not None:
                    signed['feed']['posts'] = copy.deepcopy(self.next_posts)
                if self.next_withdrawn is not None:
                    signed['withdrawn'] = self.next_withdrawn
                signed['count'] = len(signed['feed']['posts'])
                if not signed['count']:
                    signed['feed']['updated_at'] = self.now
                if self.invalid_local:
                    value['signature'] = 'invalid'
                (self.home / 'posts.json').write_text(encoded(value))
            return done({'status': 'refreshed'})
        if 'verify' in args:
            path = Path(args[args.index('--feed')+1])
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            value = json.loads(path.read_text())
            signed = value['signed']
            checkpoint = Path(args[args.index('--checkpoint')+1])
            self.verify_calls.append((checkpoint.name, signed['revision']))
            if value['signature'] != 'valid' or signed['expires_at'] <= self.now:
                return done(code=1)
            previous = json.loads(checkpoint.read_text()) if checkpoint.exists() else {}
            if signed['revision'] < previous.get('revision', 0):
                return done(code=1)
            checkpoint.write_text(encoded({'revision': signed['revision']}))
            return done({'status': 'verified', 'revision': signed['revision'],
                         'count': signed['count'], 'expires_at': signed['expires_at']})
        if 'bootstrap' in args and 'create' in args:
            output = Path(args[args.index('--output')+1])
            number = int(args[args.index('--revision')+1])
            value = bootstrap(number, self.now+600, self.new_peer)
            value['signed'].update(self.bootstrap_extra)
            value['signed']['peers'][0].update(self.peer_extra)
            output.write_text(encoded(value))
            return done({'status': 'signed'})
        self.fail('unexpected subprocess capability')

    def changed_paths(self):
        return [change['path'] for patch in self.patches for change in patch[1:]]

    def test_repeated_unchanged_ticks_keep_cm_and_bootstrap_bytes_stable(self):
        original = copy.deepcopy(self.current['data'])
        for offset in [0, 30, 60, 90, 120, 150, 180]:
            self.now = 10000 + offset
            result = PUBLISHER.main()
            self.assertEqual(result['revision'], 10)
            self.assertEqual(result['count'], 1)
            self.assertEqual(result['expires_at'], 10500)
            self.assertFalse(result['feed_updated'])
            self.assertFalse(result['bootstrap_updated'])
            self.assertEqual(self.current['data'], original)
        self.assertEqual(self.patches, [])
        self.assertGreater(json.loads((self.home / 'posts.json').read_text())['signed']['revision'], 10)
        self.assertEqual(json.loads((self.home / 'served-checkpoint.json').read_text())['revision'], 10)

    def test_feed_renews_at_300_seconds_but_fresh_bootstrap_does_not(self):
        self.current['data']['posts.json'] = encoded(feed(expires=10300))
        self.current['data']['bootstrap.json'] = encoded(bootstrap(expires=10600))
        (self.home / 'bootstrap.json').write_text(self.current['data']['bootstrap.json'])
        result = PUBLISHER.main()
        self.assertEqual(self.changed_paths(), ['/data/posts.json'])
        self.assertEqual(result['expires_at'], self.now+600)

    def test_bootstrap_renews_at_300_seconds_without_publishing_local_feed(self):
        self.current['data']['bootstrap.json'] = encoded(bootstrap(expires=10300))
        (self.home / 'bootstrap.json').write_text(self.current['data']['bootstrap.json'])
        result = PUBLISHER.main()
        self.assertEqual(self.changed_paths(), ['/data/bootstrap.json'])
        self.assertEqual(result['revision'], 10)

    def test_new_post_is_published_on_next_tick(self):
        self.next_posts = feed()['signed']['feed']['posts'] + [{'signed': {'id': 'new-public-post'}}]
        result = PUBLISHER.main()
        self.assertEqual(result['revision'], 11)
        self.assertEqual(result['count'], 2)
        self.assertEqual(self.changed_paths(), ['/data/posts.json'])

    def test_withdrawal_is_published_without_waiting_for_expiry(self):
        self.next_posts = []
        self.next_withdrawn = ['test-post']
        result = PUBLISHER.main()
        self.assertEqual(result['count'], 0)
        self.assertEqual(self.changed_paths(), ['/data/posts.json'])

    def test_empty_feed_timestamp_is_not_content_change(self):
        empty = encoded(feed(posts=[]))
        self.current['data']['posts.json'] = empty
        (self.home / 'posts.json').write_text(empty)
        for _ in range(3):
            self.assertFalse(PUBLISHER.main()['feed_updated'])
            self.now += 30
        self.assertEqual(self.patches, [])

    def test_changed_public_trust_or_profile_requires_new_feed_publication(self):
        (self.home / 'trust-root.json').write_text(encoded('pinned-public-root'))
        (self.home / 'trust.json').write_text(encoded({'revision': 2}))
        result = PUBLISHER.main()
        self.assertTrue(result['feed_updated'])
        self.assertTrue(result['bootstrap_updated'])
        verify_calls = [args for args in self.calls if 'verify' in args]
        self.assertTrue(all('--trust-bundle' in args for args in verify_calls))
        self.assertTrue(all(args[args.index('--trust-publisher')+1] == str(self.home / 'trust-root.json')
                            for args in verify_calls))
        self.patches.clear()
        self.profile = {'policy_id': 'new-fixed-profile'}
        self.assertTrue(PUBLISHER.main()['feed_updated'])

    def test_same_revision_same_exact_bytes_is_idempotent_success(self):
        self.freeze_refresh = True
        result = PUBLISHER.main()
        self.assertEqual(result['revision'], 10)
        self.assertEqual(self.patches, [])
        self.assertIn(('checkpoint.json', 10), self.verify_calls)
        self.assertIn(('served-checkpoint.json', 10), self.verify_calls)

    def test_same_revision_different_bytes_is_rejected(self):
        self.forced_revision = 10
        with self.assertRaisesRegex(RuntimeError, 'publication_revision_conflict'):
            PUBLISHER.main()
        self.assertEqual(self.patches, [])

    def test_lower_revision_is_rejected(self):
        self.forced_revision = 9
        with self.assertRaisesRegex(RuntimeError, 'publication_revision_conflict'):
            PUBLISHER.main()
        self.assertEqual(self.patches, [])

    def test_invalid_local_signature_cannot_update_cm(self):
        self.invalid_local = True
        with self.assertRaises(RuntimeError):
            PUBLISHER.main()
        self.assertEqual(self.patches, [])

    def test_invalid_or_expired_current_feed_is_not_reused(self):
        value = feed(expires=9999)
        value['signature'] = 'invalid'
        self.current['data']['posts.json'] = encoded(value)
        result = PUBLISHER.main()
        self.assertEqual(result['revision'], 11)
        self.assertEqual(self.changed_paths(), ['/data/posts.json'])

    def test_expired_but_valid_current_signature_is_replaced(self):
        self.current['data']['posts.json'] = encoded(feed(expires=self.now))
        result = PUBLISHER.main()
        self.assertEqual(result['expires_at'], self.now+600)
        self.assertEqual(self.changed_paths(), ['/data/posts.json'])

    def test_route_failure_removes_bootstrap_even_if_later_local_verification_fails(self):
        self.route.write_text(encoded({'reachable': False, 'checked_at': self.now}))
        self.invalid_local = True
        with self.assertRaises(RuntimeError):
            PUBLISHER.main()
        self.assertNotIn('bootstrap.json', self.current['data'])
        self.assertEqual(self.changed_paths(), ['/data/bootstrap.json'])
        self.assertFalse(any('create' in args for args in self.calls))

    def test_recovered_route_adds_only_bootstrap(self):
        self.current['data'].pop('bootstrap.json')
        result = PUBLISHER.main()
        self.assertTrue(result['bootstrap_active'])
        self.assertEqual(self.changed_paths(), ['/data/bootstrap.json'])

    def test_changed_bootstrap_identity_is_published_independently(self):
        self.new_peer = 'replacement-public-test-peer'
        PUBLISHER.main()
        self.assertEqual(self.changed_paths(), ['/data/bootstrap.json'])

    def test_changed_signed_bootstrap_policy_field_is_not_ignored(self):
        value = bootstrap()
        value['signed']['policy_id'] = 'old-policy'
        self.current['data']['bootstrap.json'] = encoded(value)
        (self.home / 'bootstrap.json').write_text(encoded(value))
        self.bootstrap_extra = {'policy_id': 'new-policy'}
        PUBLISHER.main()
        self.assertEqual(self.changed_paths(), ['/data/bootstrap.json'])

    def test_changed_peer_bootstrap_policy_field_is_not_ignored(self):
        value = bootstrap()
        value['signed']['peers'][0]['profile_id'] = 'old-profile'
        self.current['data']['bootstrap.json'] = encoded(value)
        (self.home / 'bootstrap.json').write_text(encoded(value))
        self.peer_extra = {'profile_id': 'new-profile'}
        PUBLISHER.main()
        self.assertEqual(self.changed_paths(), ['/data/bootstrap.json'])

    def test_unrecognized_bootstrap_signature_is_replaced_with_cli_generated_bytes(self):
        value = bootstrap()
        value['signature'] = 'invalid'
        self.current['data']['bootstrap.json'] = encoded(value)
        PUBLISHER.main()
        self.assertEqual(self.changed_paths(), ['/data/bootstrap.json'])

    def test_bootstrap_revision_does_not_roll_back_when_cm_document_is_malformed(self):
        (self.home / 'served-bootstrap.json').write_text(encoded(bootstrap(revision=100)))
        self.current['data']['bootstrap.json'] = 'not a signed document'
        PUBLISHER.main()
        served = json.loads(self.current['data']['bootstrap.json'])
        self.assertGreater(served['signed']['revision'], 100)

    def test_resource_version_conflict_is_not_reported_as_success(self):
        self.next_posts = []
        self.patch_conflict = True
        with self.assertRaises(RuntimeError):
            PUBLISHER.main()
        self.assertEqual(json.loads(self.current['data']['posts.json'])['signed']['revision'], 10)

    def test_status_reports_actual_readback_not_local_revision(self):
        self.next_posts = []
        self.readback_feed = feed(revision=30, expires=10700, posts=[])
        result = PUBLISHER.main()
        self.assertEqual(result['revision'], 30)
        self.assertEqual(result['count'], 0)
        self.assertEqual(result['expires_at'], 10700)

    def test_invalid_readback_is_not_published_success(self):
        self.readback_feed = feed(revision=30)
        self.readback_feed['signature'] = 'invalid'
        with self.assertRaises(RuntimeError):
            PUBLISHER.main()

    def test_status_permission_is_set_before_atomic_replace(self):
        path = self.home / 'public-status.json'
        original = Path.replace
        observed = []
        def replace(source, target):
            observed.append(source.stat().st_mode & 0o777)
            return original(source, target)
        with mock.patch.object(Path, 'replace', replace):
            PUBLISHER.atomic_json(path, {'status': 'published'}, mode=0o640)
        self.assertEqual(observed, [0o640])
        self.assertEqual(path.stat().st_mode & 0o777, 0o640)


if __name__ == '__main__':
    unittest.main()
