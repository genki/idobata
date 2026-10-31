#!/usr/bin/env python3
"""Verify public publication and update only the dedicated feed ConfigMap."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

HOME = Path('/var/lib/idobata-publisher')
BINARY = '/usr/local/lib/idobata/idobata'
STATUS = Path('/run/idobata/publisher-status.json')
ROUTE = Path('/run/idobata/public-route.json')
REFRESH_SECONDS = 600
RENEW_BEFORE_SECONDS = 300


def run(args, data=None):
    result = subprocess.run(args, input=data, capture_output=True, text=True, timeout=90)
    if result.returncode:
        raise RuntimeError('publication_operation_failed')
    return result.stdout


def optional_json(path):
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return None


def atomic_text(path, value, mode=0o600):
    with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=path.parent,
                                     prefix=path.name + '.', delete=False) as stream:
        temporary = Path(stream.name)
        try:
            os.fchmod(stream.fileno(), mode)
            stream.write(value)
            stream.flush()
            temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)


def atomic_json(path, value, mode=0o600):
    atomic_text(path, json.dumps(value, ensure_ascii=False) + '\n', mode)


def trust_arguments():
    if (HOME / 'trust-root.json').exists():
        return ['--trust-publisher', str(HOME / 'trust-root.json'),
                '--trust-bundle', str(HOME / 'trust.json')]
    return ['--trust-publisher', str(HOME / 'publisher.json')]


def verify_feed(raw, checkpoint):
    # Verify the exact immutable bytes being compared/published, not a mutable
    # original path another public CLI operation could replace after this check.
    with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=HOME,
                                     suffix='.json') as stream:
        stream.write(raw)
        stream.flush()
        result = json.loads(run([BINARY, 'public', 'verify', '--feed', stream.name,
                                 '--checkpoint', str(checkpoint)] + trust_arguments()))
    if result.get('status') != 'verified':
        raise RuntimeError('publication_verification_failed')
    return result


def revision(document):
    value = document['signed']['revision']
    if type(value) is not int or not 0 < value <= 9_007_199_254_740_991:
        raise RuntimeError('publication_invalid_revision')
    return value


def feed_payload(document):
    signed = document['signed']
    # Renewal metadata is excluded. An empty feed's updated_at changes every
    # refresh even though there is no new post to serve.
    return {'version': signed['version'], 'public_key': document['public_key'],
            'feed_version': signed['feed']['version'],
            'posts': signed['feed']['posts'], 'withdrawn': signed['withdrawn']}


def public_context():
    # These are public trust documents/profile, never identity/storage keys or
    # kubeconfig. Their fingerprint is local publication state, not a new trust.
    value = {name: optional_json(HOME / name)
             for name in ['publisher.json', 'trust-root.json', 'trust.json']}
    value['profile'] = json.loads(run([BINARY, 'profile']))
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'))
                          .encode()).hexdigest()


def bootstrap_payload(document):
    signed = copy.deepcopy(document['signed'])
    for key in ['revision', 'issued_at', 'expires_at']:
        signed.pop(key, None)
    for peer in signed['peers']:
        for key in ['advertised_at', 'expires_at', 'signature']:
            peer.pop(key, None)
    return {'signed': signed, 'key_id': document['key_id']}


def current_map(command):
    return json.loads(run(command + ['get', 'configmap', 'idobata-feed', '-o', 'json']))


def patch_map(command, current, changes):
    if changes:
        patch = [{'op': 'test', 'path': '/metadata/resourceVersion',
                  'value': current['metadata']['resourceVersion']}] + changes
        run(command + ['patch', 'configmap', 'idobata-feed', '--type=json',
                       '--patch-file=/dev/stdin'], json.dumps(patch))


def main():
    command = ['kubectl', '--kubeconfig', str(HOME / 'kubeconfig'), '-n', 'default']
    current = current_map(command)
    route = optional_json(ROUTE) or {}
    now = time.time()
    checked = route.get('checked_at')
    reachable = (route.get('reachable') is True and type(route.get('signed_receipts')) is int
                 and route['signed_receipts'] == 1
                 and type(checked) in [int, float] and 0 <= now - checked <= 600)
    bootstrap_removed = not reachable and 'bootstrap.json' in current['data']
    if bootstrap_removed:
        # An unreachable advertisement is removed even if a later feed check
        # fails. Its deletion still tests this ConfigMap's resourceVersion.
        patch_map(command, current, [{'op': 'remove', 'path': '/data/bootstrap.json'}])
        current = current_map(command)

    feed = HOME / 'posts.json'
    run([BINARY, '--home', str(HOME), '--socket', '/run/idobata/ipc.sock',
         'public', 'refresh', '--feed', str(feed), '--room', 'commons',
         '--ttl-seconds', str(REFRESH_SECONDS)])
    local_raw = feed.read_text()
    verify_feed(local_raw, HOME / 'checkpoint.json')
    local = json.loads(local_raw)
    local_revision = revision(local)
    previous_raw = current['data']['posts.json']
    previous = json.loads(previous_raw)
    previous_revision = revision(previous)
    if local_revision < previous_revision or (local_revision == previous_revision
                                            and local_raw != previous_raw):
        raise RuntimeError('publication_revision_conflict')
    served_checkpoint = HOME / 'served-checkpoint.json'
    try:
        verify_feed(previous_raw, served_checkpoint)
        previous_valid = True
    except (RuntimeError, OSError, ValueError):
        previous_valid = False
    if not previous_valid and local_revision <= previous_revision:
        raise RuntimeError('publication_current_verification_failed')
    checkpoint = optional_json(served_checkpoint) or {}
    if local_revision < checkpoint.get('revision', 0):
        raise RuntimeError('publication_revision_conflict')
    context = public_context()
    saved_context = optional_json(HOME / 'publication-context.json') or {}
    reuse = (previous_valid and feed_payload(previous) == feed_payload(local)
             and previous['signed']['expires_at'] - time.time() > RENEW_BEFORE_SECONDS
             and saved_context.get('public_context') == context)
    feed_changed = local_raw != previous_raw and not reuse
    changes = []
    if feed_changed:
        changes.append({'op': 'replace', 'path': '/data/posts.json', 'value': local_raw})

    fresh_bootstrap_raw = None
    known_bootstrap_raw = None
    bootstrap_floor = 0
    bootstrap_path = HOME / 'bootstrap.json'
    cache_path = HOME / 'served-bootstrap.json'
    for path in [cache_path, bootstrap_path]:
        try:
            raw = path.read_text()
            if raw == current['data'].get('bootstrap.json'):
                known_bootstrap_raw = raw
            try:
                bootstrap_floor = max(bootstrap_floor, revision(json.loads(raw)))
            except (KeyError, TypeError, ValueError, RuntimeError):
                pass
        except OSError:
            pass
    if reachable:
        try:
            old_bootstrap_revision = revision(json.loads(current['data']['bootstrap.json']))
        except (KeyError, ValueError, TypeError, RuntimeError):
            old_bootstrap_revision = 0
        run([BINARY, '--home', str(HOME), 'bootstrap', 'create', '--node-home',
             '/var/lib/idobata', '--output', str(bootstrap_path), '--revision',
             str(max(local_revision, old_bootstrap_revision + 1, bootstrap_floor + 1))])
        fresh_bootstrap_raw = bootstrap_path.read_text()
        fresh_bootstrap = json.loads(fresh_bootstrap_raw)
        bootstrap_reusable = False
        if known_bootstrap_raw is not None:
            try:
                old = json.loads(known_bootstrap_raw)
                bootstrap_reusable = (
                    bootstrap_payload(old) == bootstrap_payload(fresh_bootstrap)
                    and old['signed']['expires_at'] - time.time() > RENEW_BEFORE_SECONDS
                    and saved_context.get('public_context') == context)
            except (KeyError, TypeError, ValueError):
                pass
        if not bootstrap_reusable:
            if ('bootstrap.json' in current['data']
                    and revision(fresh_bootstrap) <= old_bootstrap_revision
                    and fresh_bootstrap_raw != current['data']['bootstrap.json']):
                raise RuntimeError('bootstrap_revision_conflict')
            changes.append({'op': 'add', 'path': '/data/bootstrap.json',
                            'value': fresh_bootstrap_raw})
    patch_map(command, current, changes)

    # Status describes the CM read back after the decision, including no-ops.
    # A newer unpublished local revision is never reported as being served.
    served = current_map(command)
    served_raw = served['data']['posts.json']
    verified = verify_feed(served_raw, served_checkpoint)
    bootstrap_raw = served['data'].get('bootstrap.json')
    if not reachable and bootstrap_raw is not None:
        raise RuntimeError('bootstrap_removal_not_observed')
    if reachable:
        if bootstrap_raw not in [known_bootstrap_raw, fresh_bootstrap_raw] or bootstrap_raw is None:
            raise RuntimeError('bootstrap_readback_conflict')
        if json.loads(bootstrap_raw)['signed']['expires_at'] <= time.time():
            raise RuntimeError('bootstrap_readback_expired')
        atomic_text(cache_path, bootstrap_raw)
    atomic_json(HOME / 'publication-context.json', {'public_context': context})
    checked_at = time.time()
    return {'version': 1, 'status': 'published', 'checked_at': checked_at,
            'last_success': checked_at, 'revision': verified['revision'],
            'count': verified['count'], 'expires_at': verified['expires_at'],
            'bootstrap_active': bootstrap_raw is not None,
            'feed_updated': feed_changed,
            'bootstrap_updated': bootstrap_removed or any(
                change['path'] == '/data/bootstrap.json' for change in changes)}


if __name__ == '__main__':
    try:
        status = main()
    except Exception:
        last = optional_json(STATUS) or {}
        status = {'version': 1, 'status': 'failed', 'checked_at': time.time(),
                  'last_success': last.get('last_success'), 'reason': 'publication_failed',
                  'revision': last.get('revision'), 'count': last.get('count'),
                  'expires_at': last.get('expires_at', 0), 'served_metadata_current': False}
    atomic_json(STATUS, status, mode=0o640)
    print(json.dumps({'status': status['status'], 'revision': status.get('revision')}))
    raise SystemExit(0 if status['status'] == 'published' else 1)
