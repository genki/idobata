#!/usr/bin/env python3
"""DSH検証peerと判断runnerだけを監視し、既存4peerの観測へ混ぜない。"""
from concurrent.futures import ThreadPoolExecutor
import argparse
import json
import os
from pathlib import Path
import selectors
import stat
import subprocess
import tempfile
import time

ROOT = Path('/home/vagrant/.local/state/idobata')
METADATA = dict(synthetic=True, common_controller='s21g',
                operator='machinaai-test', executor='dsh',
                model_provider='qwen', model_tools=False,
                actual_operator_contribution=0)
SUCCESS = {'dry_run_complete', 'evaluation_applied', 'duplicate_completed'}
HOLD = {'model_abstained', 'decision_expired', 'no_open_questions',
        'no_eligible_answer',
        'already_reserved', 'capacity_hold', 'ledger_not_configured',
        'insufficient_independent_operators'}
FAILURE = {'model_timeout', 'model_failed', 'invalid_judgment',
           'ipc_unavailable', 'inspection_rejected', 'apply_outcome_unknown',
           'configuration_invalid', 'state_invalid', 'runner_failed'}
MAX_INTEGER = 9_007_199_254_740_991


def count(value):
    return type(value) is int and 0 <= value <= MAX_INTEGER


def timestamp(value):
    return type(value) in (int, float) and 0 <= value <= MAX_INTEGER


def metadata_valid(value):
    return isinstance(value, dict) and all(
        type(value.get(k)) is type(v) and value[k] == v
        for k, v in METADATA.items())


def summarize_peer(value, now):
    invalid = {'state': 'unavailable', 'reason': 'peer_status_invalid',
               'checked_at': now}
    if not isinstance(value, dict) or not isinstance(value.get('daemon'), dict):
        return invalid
    node = value['daemon']
    rooms = node.get('rooms')
    if (value.get('status') != 'healthy' or node.get('status') != 'ready'
            or node.get('version') != '0.4.0' or not isinstance(rooms, list)
            or not 1 <= len(rooms) <= 32
            or not count(node.get('connected_peers'))
            or not count(node.get('uptime_seconds'))
            or any(not isinstance(r, dict) or r.get('authorized') is not True
                   or not timestamp(r.get('expires_at'))
                   or r['expires_at'] <= now for r in rooms)):
        return invalid
    return {'state': 'up', 'reason': None, 'checked_at': now,
            'version': '0.4.0', 'doctor': 'healthy',
            'connected_peers': node['connected_peers'],
            'uptime_seconds': node['uptime_seconds'],
            'authorized_rooms': len(rooms), 'rooms': len(rooms)}


def summarize_runner(value, now):
    invalid = {'state': 'unavailable', 'reason': 'runner_status_invalid'}
    if (not isinstance(value, dict) or type(value.get('version')) is not int
            or value['version'] != 1):
        return invalid
    state = value.get('state')
    reasons = {'success': SUCCESS, 'hold': HOLD, 'failure': FAILURE,
               'running': {'running'}, 'not_run': {'not_run'}}
    counters = value.get('counts')
    if (state not in reasons or value.get('reason') not in reasons[state]
            or not timestamp(value.get('checked_at'))
            or not isinstance(counters, dict)
            or any(not count(counters.get(k)) for k in
                   ['attempts', 'successes', 'failures', 'holds'])
            or sum(counters[k] for k in ['successes', 'failures', 'holds'])
            > counters['attempts']):
        return invalid
    result = {'state': state, 'reason': value['reason'],
              'checked_at': value['checked_at'],
              'counts': {k: counters[k] for k in
                         ['attempts', 'successes', 'failures', 'holds']}}
    for key in ['started_at', 'completed_at', 'last_success_at', 'deadline_at']:
        v = value.get(key)
        if v is not None and (not timestamp(v) or v > now + 60):
            # runningのdeadlineだけは未来にあることが正しい。
            if key != 'deadline_at' or not timestamp(v):
                return invalid
        result[key] = v
    if value['checked_at'] > now + 60:
        return invalid
    if state == 'running':
        start, deadline = result['started_at'], result['deadline_at']
        if (start is None or deadline is None or start > now + 60
                or not 0 < deadline - start <= 300):
            return invalid
        # 期限超過は表示側が現在時刻で判定する。まだrunnerが確定していない
        # failure件数をcollectorが発行・加算しない。
    elif (state in ['success', 'failure', 'hold']
          and not (state == 'hold' and value['reason'] in
                   ['no_open_questions', 'no_eligible_answer'])):
        if (result['completed_at'] is None or result['started_at'] is None
                or result['completed_at'] < result['started_at']):
            return invalid
        key = {'success': 'successes', 'failure': 'failures',
               'hold': 'holds'}[state]
        if counters[key] == 0:
            return invalid
    return result


def bounded_call(argv, limit=65_536, timeout=18):
    """stdout/stderrを上限付きで読み、例外や任意stderrを監視へ渡さない。"""
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    buffers = {'stdout': bytearray(), 'stderr': bytearray()}
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as selected:
            selected.register(process.stdout, selectors.EVENT_READ, 'stdout')
            selected.register(process.stderr, selectors.EVENT_READ, 'stderr')
            while selected.get_map():
                left = deadline - time.monotonic()
                if left <= 0:
                    raise RuntimeError('command_unavailable')
                for key, _ in selected.select(min(left, 1)):
                    chunk = os.read(key.fileobj.fileno(), 8192)
                    if not chunk:
                        selected.unregister(key.fileobj)
                    else:
                        buffers[key.data].extend(chunk)
                        if len(buffers[key.data]) > limit:
                            raise RuntimeError('command_unavailable')
        process.wait(timeout=max(0.01, deadline - time.monotonic()))
        if process.returncode not in [0, 10, 30]:
            raise RuntimeError('command_unavailable')
        return json.loads(buffers['stdout'].decode('utf-8'))
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        process.stdout.close()
        process.stderr.close()


def observe(argv, kind, now, invoke=bounded_call):
    try:
        value = invoke(argv, limit=65_536 if kind == 'peer' else 16_384)
        return (summarize_peer(value, now) if kind == 'peer'
                else summarize_runner(value, now))
    except (OSError, ValueError, TypeError, RuntimeError, subprocess.SubprocessError):
        return {'state': 'unavailable', 'reason': kind + '_unavailable',
                'checked_at': now}


def config_valid(config):
    if (not isinstance(config, dict) or type(config.get('version')) is not int
            or config['version'] != 1
            or config.get('enabled') is not True or not metadata_valid(config)
            or type(config.get('runner_stale_seconds')) is not int
            or not 30 <= config['runner_stale_seconds'] <= 300):
        return False
    for key in ['doctor_argv', 'runner_argv']:
        command = config.get(key)
        if (not isinstance(command, list) or not 1 <= len(command) <= 32
                or any(not isinstance(v, str) or not v or len(v) > 8192
                       or '\x00' in v or '\n' in v or '\r' in v
                       for v in command)):
            return False
    return True


def collect(config, now, invoke=bounded_call):
    with ThreadPoolExecutor(max_workers=2) as pool:
        peer = pool.submit(observe, config['doctor_argv'], 'peer', now, invoke)
        runner = pool.submit(observe, config['runner_argv'], 'runner', now, invoke)
        return {'version': 1, 'checked_at': now, **METADATA,
                'peer': peer.result(), 'runner': runner.result()}


def save(path, value):
    fd, name = tempfile.mkstemp(prefix=path.name+'.', suffix='.tmp',
                                dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(json.dumps(value) + '\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, default=ROOT/'delegation-watch.json')
    parser.add_argument('--output-root', type=Path, default=ROOT)
    parser.add_argument('--once', action='store_true')
    args = parser.parse_args()
    details = args.config.lstat()
    if (not stat.S_ISREG(details.st_mode) or details.st_uid != os.geteuid()
            or stat.S_IMODE(details.st_mode) & 0o077 or details.st_size > 65_536):
        parser.error('protected configuration required')
    config = json.loads(args.config.read_text())
    if not config_valid(config):
        parser.error('invalid delegation configuration')
    args.output_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    monitor_config = {
        'version': 1, 'enabled': True, **METADATA,
        'runner_stale_seconds': config['runner_stale_seconds']}
    activated = False
    while True:
        save(args.output_root/'delegation-status.json', collect(config, time.time()))
        if not activated:
            # 初回だけstatusを先に確定し、enabledと初回観測の間に欠測を作らない。
            save(args.output_root/'delegation-monitor.json', monitor_config)
            activated = True
        if args.once:
            break
        time.sleep(30)


if __name__ == '__main__':
    main()
