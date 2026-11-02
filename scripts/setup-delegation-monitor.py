#!/usr/bin/env python3
"""既存4peerを変更せずDSH補助監視を準備し、明示時だけ有効化する。"""
import argparse
import base64
import importlib.util
import json
from pathlib import Path
import shlex
import subprocess
import time

SPEC = importlib.util.spec_from_file_location(
    'watch_delegation', Path(__file__).with_name('watch-delegation.py'))
WATCH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(WATCH)
UNIT = '''[Unit]
Description=idobata synthetic DSH peer and judgment runner metadata
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=vagrant
Group=vagrant
ExecStart=/usr/bin/python3 /usr/local/lib/idobata/watch-delegation.py
Restart=on-failure
RestartSec=15
TimeoutStopSec=10
KillMode=control-group
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/home/vagrant/.local/state/idobata

[Install]
WantedBy=multi-user.target
'''


def transport(command):
    encoded = base64.b64encode(command.encode()).decode()
    guest = ['/usr/bin/ssh', '-T', '-oBatchMode=yes', '-oConnectTimeout=5',
             '-oForwardAgent=no', '-oControlMaster=no', '-oControlPath=none',
             '-F', '/Users/machinaai/.lima/dsh/ssh.config', 'lima-dsh',
             'sudo -n /usr/local/sbin/dsh-websh-exec ' + encoded]
    return ['ssh', '-T', '-oBatchMode=yes', '-oConnectTimeout=12',
            '-oForwardAgent=no', '-oControlMaster=no', '-oControlPath=none',
            'machinaai', shlex.join(guest)]


def configuration():
    return {'version': 1, 'enabled': True, **WATCH.METADATA,
            'runner_stale_seconds': 180,
            'doctor_argv': transport(
                '/usr/local/bin/idobata --socket /run/idobata/ipc.sock doctor'),
            'runner_argv': transport(
                'cat /home/dsh/.local/state/idobata-judge/status.json')}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true',
                        help='実peer/runnerのmetadataが有効な場合だけ設置・起動する')
    parser.add_argument('--prepare-dir', type=Path,
                        default=Path('/tmp/idobata-dsh-monitor-prepared'))
    args = parser.parse_args()
    config = configuration()
    assert WATCH.config_valid(config)
    args.prepare_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    config_path = args.prepare_dir/'delegation-watch.json'
    WATCH.save(config_path, config)
    unit_path = args.prepare_dir/'idobata-delegation-watch.service'
    unit_path.write_text(UNIT)
    if not args.apply:
        print(json.dumps({'status': 'prepared', 'enabled': False,
                          **WATCH.METADATA}))
        return
    # 初期構築のNGを配信しない。有効化前に専用peerとrunnerの実状態を検査する。
    now = time.time()
    result = WATCH.collect(config, now)
    runner_at = result['runner'].get('checked_at')
    if (result['peer']['state'] != 'up'
            or result['runner']['state'] == 'unavailable'
            or not WATCH.timestamp(runner_at)
            or not -60 <= now - runner_at <= config['runner_stale_seconds']):
        raise SystemExit('dedicated peer and runner are not ready; not enabled')
    root = WATCH.ROOT
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    WATCH.save(root/'delegation-watch.json', config)
    subprocess.run(['sudo', '-n', 'install', '-m', '0644',
                    str(Path(__file__).with_name('watch-delegation.py')),
                    '/usr/local/lib/idobata/watch-delegation.py'], check=True)
    subprocess.run(['sudo', '-n', 'install', '-m', '0644', str(unit_path),
                    '/etc/systemd/system/idobata-delegation-watch.service'],
                   check=True)
    subprocess.run(['sudo', '-n', 'systemctl', 'daemon-reload'], check=True)
    subprocess.run(['sudo', '-n', 'systemctl', 'enable',
                    'idobata-delegation-watch.service'], check=True)
    subprocess.run(['sudo', '-n', 'systemctl', 'restart',
                    'idobata-delegation-watch.service'], check=True)
    print(json.dumps({'status': 'enabled', **WATCH.METADATA,
                      'existing_four_peer_collector_changed': False}))


if __name__ == '__main__':
    main()
