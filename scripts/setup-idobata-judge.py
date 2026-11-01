#!/usr/bin/env python3
"""DSH VMの管理者が既存UID/seccomp境界へ判断runnerだけを設置する。"""
import argparse
import json
import os
from pathlib import Path
import pwd
import shutil
import subprocess

FILES = ['idobata-judge.py', 'idobata_judge.py', 'idobata_judge_automation.py']
SERVICE = '''[Unit]
Description=Explicit private idobata jobs judged by existing DSH Qwen provider
After=idobata-dsh-peer.service dsh-relay.service
[Service]
Type=oneshot
ExecStart=/usr/bin/setpriv --seccomp-filter /etc/dsh-relay/agent.bpf --reuid=dsh --regid=dsh --init-groups --no-new-privs /usr/bin/python3 -I -B /usr/local/lib/idobata-judge/idobata-judge.py --config /etc/idobata-judge/config.json --apply
WorkingDirectory=/home/dsh/workspace
Environment=HOME=/home/dsh LANG=C.UTF-8
UMask=0077
NoNewPrivileges=true
CapabilityBoundingSet=CAP_SETUID CAP_SETGID
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/home/dsh/.local/state/idobata-judge
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
PrivateDevices=true
PrivateTmp=true
Slice=dsh-workload.slice
MemoryMax=512M
TasksMax=32
RuntimeMaxSec=210
TimeoutStartSec=210
SuccessExitStatus=10
'''
TIMER = '''[Unit]
Description=Bounded explicit private idobata judgment queue
[Timer]
OnBootSec=45
OnUnitInactiveSec=120
AccuracySec=1
Unit=idobata-judge.service
[Install]
WantedBy=timers.target
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-dir', type=Path, required=True)
    parser.add_argument('--config', type=Path, required=True)
    args = parser.parse_args()
    assert os.geteuid() == 0
    actor = pwd.getpwnam('dsh'); assert actor.pw_uid == actor.pw_gid == 2000
    configuration = json.loads(args.config.read_text())
    assert configuration['deadline_seconds'] == 180
    assert configuration['state'] == '/home/dsh/.local/state/idobata-judge'
    assert configuration['queue'] == '/etc/idobata-judge/jobs'
    assert Path('/etc/dsh-relay/agent.bpf').is_file()
    active = subprocess.check_output(['systemctl', 'show', 'idobata-judge.service',
                                     '--property=ActiveState', '--value'], text=True).strip()
    assert active in ['inactive', 'failed'], 'wait for the existing bounded job before upgrading'
    subprocess.run(['systemctl', 'stop', 'idobata-judge.timer'], check=False)
    for directory in ['/usr/local/lib/idobata-judge', '/etc/idobata-judge', '/etc/idobata-judge/jobs']:
        Path(directory).mkdir(parents=True, exist_ok=True)
        os.chown(directory, 0, 0); os.chmod(directory, 0o755)
    for name in FILES:
        source = args.source_dir / name
        assert source.is_file() and not source.is_symlink()
        target = Path('/usr/local/lib/idobata-judge') / name
        temporary = target.with_suffix(target.suffix + '.new')
        shutil.copyfile(source, temporary)
        os.chown(temporary, 0, 0); os.chmod(temporary, 0o644); os.replace(temporary, target)
    target = Path('/etc/idobata-judge/config.json')
    temporary = target.with_suffix('.new')
    temporary.write_text(json.dumps(configuration, ensure_ascii=False) + '\n')
    os.chown(temporary, 0, 0); os.chmod(temporary, 0o644); os.replace(temporary, target)
    state = Path(configuration['state'])
    state.mkdir(parents=True, exist_ok=True)
    os.chown(state, 2000, 2000); os.chmod(state, 0o700)
    for name, value in [('idobata-judge.service', SERVICE), ('idobata-judge.timer', TIMER)]:
        path = Path('/etc/systemd/system') / name
        path.write_text(value); os.chown(path, 0, 0); os.chmod(path, 0o644)
    subprocess.run(['systemctl', 'daemon-reload'], check=True)
    subprocess.run(['systemctl', 'enable', '--now', 'idobata-judge.timer'], check=True)
    print(json.dumps({'installed': True, 'timer_enabled': True,
                      'ordinary_runner_uid': 2000, 'new_model_or_provider': False}))


if __name__ == '__main__':
    main()
