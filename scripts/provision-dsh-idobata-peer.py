#!/usr/bin/env python3
"""Install the isolated synthetic DSH peer; never import a host identity or genesis."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import plistlib
import pwd
import grp
import shlex
import stat
import subprocess
import sys
import tempfile

USER = 'idobata-test'
AGENT_UID = 2000
HOME = Path('/var/lib/idobata-machinaai-test')
SDK = Path('/usr/local/lib/idobata/idobata')
ENTRY = Path('/usr/local/bin/idobata')
OPS = Path('/usr/local/lib/idobata-dsh-peer')
ADMIN = Path('/etc/idobata-dsh-peer')
SOCKET = '/run/idobata/ipc.sock'
SERVICE = 'idobata-dsh-peer.service'
ROOM = 'dsh-lab'
CHAIN = 'IDOBATA_DSH_PEER'
TEMP_COMMENT = 'idobata-dsh-configuring'


def require(value, reason):
    if not value:
        raise RuntimeError(reason)


def run(args, expected=(0,), data=None):
    p = subprocess.run([str(x) for x in args], input=data,
                       capture_output=True, timeout=45)
    require(p.returncode in expected, 'subcommand_failed')
    return p


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def regular(path, uid=None, mode=None):
    s = path.lstat()
    require(stat.S_ISREG(s.st_mode) and s.st_nlink == 1, 'unsafe_file')
    if uid is not None:
        require(s.st_uid == uid, 'unexpected_file_owner')
    if mode is not None:
        require(stat.S_IMODE(s.st_mode) == mode, 'unexpected_file_mode')
    return s


def directory(path, uid=0, gid=0, mode=0o755):
    if path.exists() or path.is_symlink():
        s = path.lstat()
        require(stat.S_ISDIR(s.st_mode) and s.st_uid == uid and
                stat.S_IMODE(s.st_mode) == mode, 'unsafe_directory')
    else:
        path.mkdir(parents=True, mode=mode)
        os.chown(path, uid, gid)
        path.chmod(mode)


def atomic(path, data, uid=0, gid=0, mode=0o644):
    if path.exists() or path.is_symlink():
        regular(path, uid=uid)
    fd, temporary = tempfile.mkstemp(prefix='.idobata-stage-', dir=path.parent)
    try:
        os.fchown(fd, uid, gid)
        os.fchmod(fd, mode)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def managed_file(path, data, mode=0o644):
    if path.exists() or path.is_symlink():
        regular(path, uid=0, mode=mode)
        require(path.read_bytes() == data, 'managed_file_conflict')
        return
    atomic(path, data, mode=mode)


def firewall_rules():
    # Replies to accepted inbound Noise connections, native peer, then public WSS.
    rules = [['-m', 'conntrack', '--ctstate', 'RELATED,ESTABLISHED', '-j', 'ACCEPT'],
             ['-d', '127.0.0.1/32', '-p', 'tcp', '--dport', '39113', '-j', 'ACCEPT']]
    # A systemd-resolved Unix IPC request does not need an IP exemption.
    private = ['0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8',
               '169.254.0.0/16', '172.16.0.0/12', '192.0.0.0/24',
               '192.0.2.0/24', '192.168.0.0/16', '198.18.0.0/15',
               '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4']
    rules += [['-d', cidr, '-j', 'REJECT'] for cidr in private]
    rules += [['-p', 'tcp', '--dport', '443', '-j', 'ACCEPT']]
    # The VM uses public resolvers; no private resolver or LAN exemption.
    for protocol in ['udp', 'tcp']:
        for resolver in ['1.1.1.1/32', '8.8.8.8/32']:
            rules.append(['-d', resolver, '-p', protocol, '--dport', '53', '-j', 'ACCEPT'])
    rules.append(['-j', 'REJECT'])
    return rules


def firewall(check_only=False):
    uid = pwd.getpwnam(USER).pw_uid
    require(uid != AGENT_UID and uid != 0, 'service_uid_not_separate')
    owner = ['-m', 'owner', '--uid-owner', str(uid)]
    temporary = owner + ['-m', 'comment', '--comment', TEMP_COMMENT, '-j', 'REJECT']
    jump = owner + ['-j', CHAIN]
    if not check_only:
        if run(['iptables', '-w', '-C', 'OUTPUT'] + temporary, (0, 1)).returncode:
            run(['iptables', '-w', '-I', 'OUTPUT', '1'] + temporary)
        run(['iptables', '-w', '-N', CHAIN], (0, 1))
        run(['iptables', '-w', '-F', CHAIN])
        for rule in firewall_rules():
            run(['iptables', '-w', '-A', CHAIN] + rule)
        if run(['iptables', '-w', '-C', 'OUTPUT'] + jump, (0, 1)).returncode:
            run(['iptables', '-w', '-I', 'OUTPUT', '1'] + jump)
        if run(['ip6tables', '-w', '-C', 'OUTPUT'] + owner + ['-j', 'REJECT'], (0, 1)).returncode:
            run(['ip6tables', '-w', '-I', 'OUTPUT', '1'] + owner + ['-j', 'REJECT'])
    run(['iptables', '-w', '-C', 'OUTPUT'] + jump)
    run(['ip6tables', '-w', '-C', 'OUTPUT'] + owner + ['-j', 'REJECT'])
    actual = run(['iptables', '-w', '-S', CHAIN]).stdout.decode().splitlines()
    require(len(actual) == len(firewall_rules()) + 1, 'peer_firewall_rule_count_changed')
    for rule in firewall_rules():
        run(['iptables', '-w', '-C', CHAIN] + rule)
    # The private-range rejects must occur before the broad public 443 accept.
    public_index = next(i for i, line in enumerate(actual) if '--dport 443' in line)
    for cidr in ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '169.254.0.0/16']:
        require(next(i for i, line in enumerate(actual) if '-d ' + cidr + ' ' in line)
                < public_index, 'peer_firewall_rule_order_changed')
    if not check_only:
        run(['iptables', '-w', '-D', 'OUTPUT'] + temporary)
    else:
        require(run(['iptables', '-w', '-C', 'OUTPUT'] + temporary, (0, 1)).returncode == 1,
                'peer_firewall_configuration_incomplete')


def service_unit():
    return f'''[Unit]
Description=idobata synthetic machinaai-test peer (controller s21g, executor dsh)
After=network-online.target idobata-dsh-peer-firewall.service
Wants=network-online.target
Requires=idobata-dsh-peer-firewall.service
[Service]
Type=simple
User={USER}
Group={USER}
SupplementaryGroups=dsh
RuntimeDirectory=idobata
RuntimeDirectoryMode=0755
RuntimeDirectoryPreserve=restart
ExecStartPre=+/usr/bin/python3 {OPS}/provision.py --mode firewall-check
ExecStart={SDK} --home {HOME} daemon
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths={HOME} /run/idobata
LimitCORE=0
UMask=0077
[Install]
WantedBy=multi-user.target
'''


def firewall_unit():
    return f'''[Unit]
Description=Restricted networking for the synthetic idobata service UID
After=network-online.target dsh-firewall.service
Before={SERVICE}
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 {OPS}/provision.py --mode firewall-apply
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
'''


def linux_tunnel_unit():
    return '''[Unit]
Description=Loopback-only Noise transport to the isolated DSH peer
After=network-online.target
Wants=network-online.target
[Service]
User=vagrant
ExecStart=/usr/bin/ssh -N -T -o BatchMode=yes -o ExitOnForwardFailure=yes -o ServerAliveInterval=20 -o ServerAliveCountMax=3 -o ControlMaster=no -o ControlPath=none -L 127.0.0.1:39135:127.0.0.1:39135 machinaai
Restart=always
RestartSec=10
NoNewPrivileges=true
[Install]
WantedBy=multi-user.target
'''


def host_tunnel_plist():
    return {'Label': 'com.s21g.idobata-dsh-link', 'UserName': 'machinaai',
            'GroupName': 'staff', 'RunAtLoad': True, 'KeepAlive': True,
            'ThrottleInterval': 10,
            'ProgramArguments': ['/usr/bin/ssh', '-N', '-T', '-o', 'BatchMode=yes',
                '-o', 'ExitOnForwardFailure=yes', '-o', 'ServerAliveInterval=20',
                '-o', 'ServerAliveCountMax=3', '-o', 'ControlMaster=no',
                '-o', 'ControlPath=none', '-F', '/Users/machinaai/.lima/dsh/ssh.config',
                '-L', '127.0.0.1:39135:127.0.0.1:39134',
                '-R', '127.0.0.1:39113:127.0.0.1:39113', 'lima-dsh']}


def as_service(args):
    return run(['runuser', '-u', USER, '--', SDK, '--home', HOME] + args)


def test_room_pin(certificate, member, authority):
    room = certificate['signed']
    require(room.get('public', False) is False and room['version'] == 4
            and room.get('knowledge_automation_required') is True,
            'test_room_must_be_private_v4_with_automation')
    members = room['members']
    claims = room['knowledge_operators']
    require(len(members) == 3 and len({m['peer_id'] for m in members}) == 3,
            'unexpected_test_room_roster')
    require(set(claims['bindings']) == {m['peer_id'] for m in members}
            and sorted(claims['bindings'].values()) == ['machinaai-test', 's21g', 's21g']
            and claims['credits'] == {'s21g': 1000, 'machinaai-test': 1000},
            'unexpected_test_operator_claims')
    require(member in members and claims['bindings'][member['peer_id']] == 'machinaai-test',
            'test_identity_not_bound_to_synthetic_operator')
    return {'authority_peer_id': authority, 'room_id': room['room_id'],
            'members': sorted(members, key=lambda m: m['peer_id']),
            'knowledge_operators': claims, 'public': False,
            'knowledge_automation_required': True}


def prepare(binary, expected, source_sha, apply):
    require(os.geteuid() == 0, 'root_required')
    require(len(expected) == 64 and all(x in '0123456789abcdef' for x in expected), 'invalid_sha256')
    require(len(source_sha) == 64 and all(x in '0123456789abcdef' for x in source_sha), 'invalid_source_sha256')
    regular(binary)
    require(sha(binary) == expected, 'candidate_hash_mismatch')
    require(run([binary, '--version']).stdout.strip() == b'idobata 0.4.0', 'candidate_version_mismatch')
    require(pwd.getpwuid(AGENT_UID).pw_name == 'dsh' and grp.getgrnam('dsh').gr_gid == AGENT_UID,
            'unexpected_agent_identity')
    marker = ADMIN / 'installation.json'
    if not marker.exists():
        require(not any(os.path.lexists(p) for p in [HOME, SDK, ENTRY,
                    Path('/etc/systemd/system') / SERVICE]), 'existing_installation_not_owned')
    else:
        regular(marker, uid=0, mode=0o600)
        installed = json.loads(marker.read_text())
        require(installed['sdk_sha256'] == expected and installed['source_sha256'] == source_sha,
                'existing_installation_requires_guarded_upgrade')
    if not apply:
        return {'status': 'read_only_plan', 'sdk_sha256': expected}
    directory(ADMIN, mode=0o700)
    if not marker.exists():
        atomic(marker, json.dumps({'version': 1, 'controller': 's21g',
            'synthetic': True, 'operator': 'machinaai-test', 'executor': 'dsh',
            'sdk_sha256': expected, 'source_sha256': source_sha}).encode(), mode=0o600)
    try:
        account = pwd.getpwnam(USER)
    except KeyError:
        run(['useradd', '--system', '--user-group', '--home-dir', HOME,
             '--no-create-home', '--shell', '/usr/sbin/nologin', USER])
        account = pwd.getpwnam(USER)
    require(account.pw_uid not in (0, AGENT_UID) and account.pw_dir == str(HOME)
            and account.pw_shell in ('/usr/sbin/nologin', '/bin/false'), 'unexpected_service_identity')
    directory(HOME, account.pw_uid, account.pw_gid, 0o700)
    directory(SDK.parent)
    if SDK.exists():
        regular(SDK, uid=0, mode=0o755)
        require(sha(SDK) == expected, 'installed_sdk_mismatch')
    else:
        atomic(SDK, binary.read_bytes(), mode=0o755)
    if ENTRY.exists() or ENTRY.is_symlink():
        require(ENTRY.is_symlink() and os.readlink(ENTRY) == str(SDK)
                and ENTRY.lstat().st_uid == 0, 'cli_entry_conflict')
    else:
        ENTRY.symlink_to(SDK)
    if not (HOME / 'config.json').exists():
        require(not (HOME / 'identity.key').exists() and not (HOME / 'storage.key').exists(),
                'partial_identity_requires_review')
        as_service(['init', '--listen', '/ip4/127.0.0.1/tcp/39134'])
    for name in ['identity.key', 'storage.key']:
        regular(HOME / name, uid=account.pw_uid, mode=0o600)  # metadata only
    path = HOME / 'config.json'
    regular(path, uid=account.pw_uid, mode=0o600)
    config = json.loads(path.read_text())
    desired = dict(endpoint=SOCKET, client_uids=[AGENT_UID], socket_group=AGENT_UID,
                   listen=['/ip4/127.0.0.1/tcp/39134'])
    if any(config.get(k) != v for k, v in desired.items()):
        active = run(['systemctl', 'is-active', SERVICE], (0, 3, 4)).returncode == 0
        require(not active and not config['rooms'], 'active_configuration_change_requires_review')
        lock = HOME / 'config.lock'
        regular(lock, uid=account.pw_uid, mode=0o600)
        with lock.open('r+') as stream:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            config.update(desired)
            atomic(path, json.dumps(config, separators=(',', ':')).encode(),
                   account.pw_uid, account.pw_gid, 0o600)
    directory(OPS)
    managed_file(OPS / 'provision.py', Path(__file__).read_bytes())
    units = Path('/etc/systemd/system')
    managed_file(units / SERVICE, service_unit().encode())
    managed_file(units / 'idobata-dsh-peer-firewall.service', firewall_unit().encode())
    run(['systemctl', 'daemon-reload'])
    run(['systemctl', 'enable', '--now', 'idobata-dsh-peer-firewall.service', SERVICE])
    member = json.loads(as_service(['identity']).stdout)
    member['addresses'] = ['/ip4/127.0.0.1/tcp/39135']
    atomic(ADMIN / 'member.json', json.dumps(member).encode(), mode=0o600)
    return {'status': 'prepared', 'sdk_sha256': expected, 'synthetic': True,
            'member_handoff': str(ADMIN / 'member.json'), 'keys_exported': False}


def join(invite, authority, apply):
    require(os.geteuid() == 0, 'root_required')
    regular(invite, uid=0, mode=0o600)
    require(invite.stat().st_size <= 256 * 1024, 'invite_too_large')
    certificate = json.loads(invite.read_text())
    room = certificate['signed']
    regular(ADMIN / 'member.json', uid=0, mode=0o600)
    member = json.loads((ADMIN / 'member.json').read_text())
    pin = test_room_pin(certificate, member, authority)
    pin_path = ADMIN / 'room-pin.json'
    if pin_path.exists():
        regular(pin_path, uid=0, mode=0o600)
        require(json.loads(pin_path.read_text()) == pin, 'fixed_test_room_definition_changed')
    if not apply:
        return {'status': 'read_only_join_plan'}
    account = pwd.getpwnam(USER)
    target = HOME / 'dsh-lab-invite.json'
    atomic(target, invite.read_bytes(), account.pw_uid, account.pw_gid, 0o600)
    as_service(['room', 'join', '--room', ROOM, '--invite-file', target,
                '--trust-authority', authority])
    if not pin_path.exists():
        atomic(pin_path, json.dumps(pin, sort_keys=True).encode(), mode=0o600)
    return {'status': 'joined', 'room_alias': ROOM, 'expires_at': room['expires_at'],
            'members': 3, 'synthetic': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=['prepare', 'join', 'firewall-apply',
        'firewall-check', 'render-host-plist', 'render-linux-unit'], required=True)
    parser.add_argument('--binary', type=Path)
    parser.add_argument('--sha256')
    parser.add_argument('--source-sha256')
    parser.add_argument('--invite', type=Path)
    parser.add_argument('--authority')
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    if args.mode == 'render-host-plist':
        sys.stdout.buffer.write(plistlib.dumps(host_tunnel_plist()))
        return
    if args.mode == 'render-linux-unit':
        print(linux_tunnel_unit(), end='')
        return
    if args.mode.startswith('firewall-'):
        require(os.geteuid() == 0, 'root_required')
        firewall(args.mode == 'firewall-check')
        result = {'status': 'firewall_checked'}
    elif args.mode == 'join':
        require(args.invite is not None and args.authority is not None, 'join_arguments_required')
        result = join(args.invite, args.authority, args.apply)
    else:
        require(args.binary is not None and args.sha256 is not None and
                args.source_sha256 is not None, 'candidate_arguments_required')
        result = prepare(args.binary, args.sha256, args.source_sha256, args.apply)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(json.dumps({'status': 'failed', 'error': str(error) if isinstance(error, RuntimeError)
                          else 'provisioning_validation_failed'}))
        raise SystemExit(1)
