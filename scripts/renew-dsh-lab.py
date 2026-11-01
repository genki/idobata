#!/usr/bin/env python3
"""Renew only the fixed synthetic lab; serialize with existing room maintenance."""
import argparse
import contextlib
import fcntl
import json
import os
from pathlib import Path
import pwd
import selectors
import shlex
import stat
import subprocess
import tempfile
import time

SDK = '/usr/local/lib/idobata/idobata'
HOME = Path('/var/lib/idobata')
SHARED_LOCK = Path('/home/vagrant/.local/state/idobata/room-maintenance.lock')
DEFINITION = Path('/etc/idobata-dsh-lab/definition.json')
HOURS = 168
RENEW_BEFORE = 36 * 3600


def require(ok, reason):
    if not ok:
        raise RuntimeError(reason)


def regular(path, uid=None, private=False):
    s = path.lstat()
    require(stat.S_ISREG(s.st_mode) and s.st_nlink == 1 and not (s.st_mode & 0o022),
            'unsafe_administrative_file')
    if uid is not None:
        require(s.st_uid == uid, 'unexpected_administrative_owner')
    if private:
        require(stat.S_IMODE(s.st_mode) == 0o600, 'administrative_file_not_private')
    return s


def immutable_room(room, authority):
    claims = room.get('knowledge_operators')
    require(room.get('public', False) is False and room.get('version') == 4
            and room.get('knowledge_automation_required') is True,
            'lab_policy_changed')
    require(len(room['members']) == 3 and claims is not None
            and set(claims['bindings']) == {m['peer_id'] for m in room['members']}
            and sorted(claims['bindings'].values()) == ['machinaai-test', 's21g', 's21g']
            and claims['credits'] == {'s21g': 1000, 'machinaai-test': 1000},
            'lab_fixed_operators_changed')
    return {'authority_peer_id': authority, 'room_id': room['room_id'],
            'policy_id': room['policy_id'], 'public': False,
            'knowledge_automation_required': True,
            'members': sorted(room['members'], key=lambda m: m['peer_id']),
            'knowledge_operators': claims}


def check_update(old, new):
    require(immutable_room(old['certificate']['signed'], old['authority_peer_id']) ==
            immutable_room(new['certificate']['signed'], new['authority_peer_id']),
            'lab_definition_changed')
    before, after = old['certificate'], new['certificate']
    require(after['signed']['epoch'] >= before['signed']['epoch'], 'lab_epoch_rollback')
    if after['signed']['epoch'] == before['signed']['epoch']:
        require(before == after, 'lab_equal_epoch_different_certificate')


def atomic(path, value, mode=0o600):
    fd, name = tempfile.mkstemp(prefix='.dsh-lab-', dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def root_sdk(args):
    p = subprocess.run(['runuser', '-u', 'idobata', '--', SDK, '--home', str(HOME)] + args,
                       capture_output=True, timeout=45)
    require(p.returncode == 0, 'lab_authority_command_failed')
    return p


def remote_argv(code, guest=True):
    command = 'sudo -n python3 -c ' + shlex.quote(code)
    if guest:
        command = shlex.join(['/usr/bin/ssh', '-T', '-o', 'BatchMode=yes',
            '-o', 'ConnectTimeout=10', '-o', 'ForwardAgent=no', '-o', 'ControlMaster=no',
            '-o', 'ControlPath=none', '-F', '/Users/machinaai/.lima/dsh/ssh.config',
            'lima-dsh', command])
    return ['runuser', '-u', 'vagrant', '--', 'ssh', '-T', '-o', 'BatchMode=yes',
            '-o', 'ConnectTimeout=10', '-o', 'ForwardAgent=no', '-o', 'ControlMaster=no',
            '-o', 'ControlPath=none', 'machinaai', command]


LEASE_CODE = '''import os,stat,fcntl,sys,json,tempfile
from pathlib import Path
lease_path=Path('/home/dsh/.local/state/idobata-judge/runner.lock')
config_path=Path('/etc/idobata-judge/config.json')
marker_path=config_path.parent/'authorization-update.pending'
def sync_directory(path):
 d=os.open(path,os.O_RDONLY|os.O_DIRECTORY)
 try:os.fsync(d)
 finally:os.close(d)
try:
 lease_fd=os.open(lease_path,os.O_RDWR|os.O_NOFOLLOW);lease_stat=os.fstat(lease_fd)
 assert stat.S_ISREG(lease_stat.st_mode) and lease_stat.st_nlink==1 and lease_stat.st_uid==2000 and stat.S_IMODE(lease_stat.st_mode)==0o600
 fcntl.flock(lease_fd,fcntl.LOCK_EX)
except (OSError,AssertionError):
 print('hold',flush=True);raise SystemExit(0)
def assert_lease():
 s=os.fstat(lease_fd);current=lease_path.lstat()
 assert (s.st_dev,s.st_ino)==(current.st_dev,current.st_ino) and s.st_nlink==1
 fcntl.flock(lease_fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
try:
 directory_stat=config_path.parent.lstat();config_stat=config_path.lstat()
 assert stat.S_ISDIR(directory_stat.st_mode) and directory_stat.st_uid==0 and not (directory_stat.st_mode & 0o022)
 assert stat.S_ISREG(config_stat.st_mode) and config_stat.st_uid==0 and config_stat.st_nlink==1 and not (config_stat.st_mode & 0o022)
 if os.path.lexists(marker_path):
  s=marker_path.lstat();assert stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_uid==0 and stat.S_IMODE(s.st_mode)==0o600
 else:
  fd,name=tempfile.mkstemp(prefix='.authorization-update-',dir=config_path.parent)
  with os.fdopen(fd,'w') as f:
   os.fchmod(f.fileno(),0o600);json.dump({'version':1,'phase':'authorization_update'},f);f.flush();os.fsync(f.fileno())
  os.replace(name,marker_path)
 sync_directory(config_path.parent)
 assert_lease()
except BaseException:
 print('invalid',flush=True);os.close(lease_fd);raise SystemExit(1)
print('locked',flush=True)
'''


def lease_worker_source():
    # The updater executes in this actual flock-owning process, not another SSH.
    # A crash at any later point leaves the durable pending marker for the runner.
    return LEASE_CODE + '''
try:
 line=sys.stdin.buffer.readline(262145)
 assert line.endswith(b'\\n') and len(line)<=262144
 candidate=json.loads(line)
 assert isinstance(candidate,dict) and set(candidate)=={'authority_peer_id','certificate'}
 assert isinstance(candidate['authority_peer_id'],str) and 0<len(candidate['authority_peer_id'])<=128
 assert isinstance(candidate['certificate'],dict) and set(candidate['certificate'])=={'signed','public_key','signature'}
 import io
 sys.stdin=io.StringIO(line.decode('utf-8'))
 assert_lease()
 exec(compile(__APPLY_SOURCE__,'<guest-certificate-update>','exec'),globals())
 sys.stdout.flush()
except BaseException:
 print(json.dumps({'status':'failed','reason':'guest_certificate_update_incomplete'}),flush=True)
 raise SystemExit(1)
finally:
 os.close(lease_fd)
'''.replace('__APPLY_SOURCE__', repr(GUEST_UPDATE))


class RunnerLease:
    def __init__(self, process):
        self.process = process

    def check_live(self):
        require(self.process.poll() is None, 'judge_lock_lease_lost')

    def apply(self, trusted):
        self.check_live()
        payload = json.dumps(trusted, separators=(',', ':')).encode() + b'\n'
        require(len(payload) <= 262144, 'lab_certificate_request_too_large')
        try:
            self.process.stdin.write(payload)
            self.process.stdin.flush()
            self.process.stdin.close()
        except (OSError, ValueError):
            raise RuntimeError('judge_lock_lease_lost') from None
        selector = selectors.DefaultSelector()
        selector.register(self.process.stdout, selectors.EVENT_READ)
        require(bool(selector.select(100)), 'guest_update_reply_unavailable')
        reply = self.process.stdout.readline(65537)
        selector.close()
        require(len(reply) <= 65536 and reply.endswith(b'\n'), 'invalid_guest_update_reply')
        value = json.loads(reply)
        require(value.get('status') == 'guest_and_runner_certificate_current'
                and value.get('epoch') == trusted['certificate']['signed']['epoch']
                and value.get('durable_marker_cleared') is True,
                'guest_certificate_update_incomplete')
        require(self.process.wait(timeout=15) == 0, 'guest_update_reply_unavailable')
        return value


@contextlib.contextmanager
def runner_lease():
    # Do not create a root-owned lock inside the agent's private state.
    p = subprocess.Popen(remote_argv(lease_worker_source()), stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    try:
        selector = selectors.DefaultSelector()
        selector.register(p.stdout, selectors.EVENT_READ)
        require(bool(selector.select(320)), 'judge_lock_transport_unavailable')
        line = p.stdout.readline()
        selector.close()
        require(line != b'invalid\n', 'guest_pending_marker_or_configuration_invalid')
        require(line == b'locked\n', 'judge_runner_busy_or_unprepared')
        lease = RunnerLease(p)
        lease.check_live()
        yield lease
    finally:
        if p.stdin and not p.stdin.closed:
            p.stdin.close()
        try:
            p.wait(timeout=10)
        except subprocess.TimeoutExpired:
            p.terminate()
            p.wait(timeout=10)


# Runs inside the actual guest process that holds runner.lock.
GUEST_UPDATE = '''from pathlib import Path
import json,sys,subprocess,os,tempfile,stat
data=json.load(sys.stdin);cert=data['certificate'];authority=data['authority_peer_id']
def pin(c,a):
 r=c['signed'];return {'authority':a,'room_id':r['room_id'],'policy_id':r['policy_id'],'members':sorted(r['members'],key=lambda m:m['peer_id']),'operators':r.get('knowledge_operators'),'public':r.get('public',False),'automation':r.get('knowledge_automation_required',False)}
def write(p,value,mode):
 fd,t=tempfile.mkstemp(prefix='.lab-update-',dir=p.parent)
 with os.fdopen(fd,'w') as f:os.fchmod(f.fileno(),mode);json.dump(value,f);f.flush();os.fsync(f.fileno())
 os.replace(t,p);sync_directory(p.parent)
p=Path('/etc/idobata-judge/config.json');s=p.lstat()
assert stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_uid==0 and not (s.st_mode & 0o022)
assert_lease()
marker=p.parent/'authorization-update.pending';ms=marker.lstat()
assert stat.S_ISREG(ms.st_mode) and ms.st_nlink==1 and ms.st_uid==0 and stat.S_IMODE(ms.st_mode)==0o600
config=json.loads(p.read_text());old=config['room'];assert pin(old['certificate'],old['authority_peer_id'])==pin(cert,authority)
assert old['certificate']['signed']['epoch']<=cert['signed']['epoch']
if old['certificate']['signed']['epoch']==cert['signed']['epoch']:assert old['certificate']==cert
invite=Path('/etc/idobata-dsh-peer/invite.json');write(invite,cert,0o600)
args=['python3','/usr/local/lib/idobata-dsh-peer/provision.py','--mode','join','--invite',str(invite),'--authority',authority,'--apply']
result=subprocess.run(args,capture_output=True,timeout=45);assert result.returncode==0
assert_lease()
config['room']={'authority_peer_id':authority,'certificate':cert};write(p,config,stat.S_IMODE(s.st_mode))
current=json.loads(Path('/var/lib/idobata-machinaai-test/config.json').read_text())
assert current['rooms']['dsh-lab']==config['room']
assert json.loads(p.read_text())['room']==config['room']
assert_lease();marker.unlink();sync_directory(p.parent)
print(json.dumps({'status':'guest_and_runner_certificate_current','epoch':cert['signed']['epoch'],'durable_marker_cleared':True}),flush=True)
'''


NATIVE_UPDATE = '''from pathlib import Path
import os,json,sys,pwd,subprocess,tempfile
data=json.load(sys.stdin);cert=data['certificate'];authority=data['authority_peer_id'];home=Path('/Library/Application Support/idobata')
before=json.loads((home/'config.json').read_text());old=before['rooms']['dsh-lab']
def pin(c,a):
 r=c['signed'];return {'authority':a,'room_id':r['room_id'],'policy_id':r['policy_id'],'members':sorted(r['members'],key=lambda m:m['peer_id']),'operators':r.get('knowledge_operators'),'public':r.get('public',False),'automation':r.get('knowledge_automation_required',False)}
assert pin(old['certificate'],old['authority_peer_id'])==pin(cert,authority)
assert old['certificate']['signed']['epoch']<=cert['signed']['epoch']
if old['certificate']['signed']['epoch']==cert['signed']['epoch']:assert old['certificate']==cert
owner=pwd.getpwnam('_idobata');fd,temp=tempfile.mkstemp(prefix='.dsh-lab-invite-',dir=home)
with os.fdopen(fd,'w') as f:json.dump(cert,f);f.flush();os.fsync(f.fileno())
os.chown(temp,owner.pw_uid,owner.pw_gid);os.chmod(temp,0o600);target=home/'dsh-lab-invite.json';os.replace(temp,target)
p=subprocess.run(['/usr/bin/sudo','-n','-u','_idobata','/usr/local/lib/idobata/idobata','--home',str(home),'room','join','--room','dsh-lab','--invite-file',str(target),'--trust-authority',authority],capture_output=True,timeout=45);assert p.returncode==0
after=json.loads((home/'config.json').read_text());assert all(after['rooms'][k]==v for k,v in before['rooms'].items() if k!='dsh-lab')
print(json.dumps({'status':'native_certificate_current','epoch':cert['signed']['epoch']}))
'''


def remote_update(code, trusted, guest):
    p = subprocess.run(remote_argv(code, guest), input=json.dumps(trusted).encode(),
                       capture_output=True, timeout=80)
    require(p.returncode == 0, 'lab_certificate_distribution_failed')
    return json.loads(p.stdout)


GUEST_CURRENT = '''import json,sys
from pathlib import Path
expected=json.load(sys.stdin)
c=json.loads(Path('/var/lib/idobata-machinaai-test/config.json').read_text())
p=Path('/etc/idobata-judge/config.json')
pending=__import__('os').path.lexists(p.parent/'authorization-update.pending')
current=not pending and p.exists() and json.loads(p.read_text()).get('room')==expected and c['rooms'].get('dsh-lab')==expected
print(json.dumps({'current':current,'pending':pending}))
'''
NATIVE_CURRENT = '''import json,sys
from pathlib import Path
expected=json.load(sys.stdin)
c=json.loads(Path('/Library/Application Support/idobata/config.json').read_text())
print(json.dumps({'current':c['rooms'].get('dsh-lab')==expected}))
'''


def initialize(trusted_path, definition, apply):
    regular(trusted_path, private=True)
    trusted = json.loads(trusted_path.read_text())
    pin = immutable_room(trusted['certificate']['signed'], trusted['authority_peer_id'])
    current = json.loads((HOME/'config.json').read_text())['rooms']['dsh-lab']
    require(current == trusted, 'authority_current_room_does_not_match_handoff')
    value = {'version': 1, 'controller': 's21g', 'synthetic': True,
             'room_alias': 'dsh-lab', 'pin': pin,
             'members_file': '/var/lib/idobata/dsh-lab/members.json',
             'operators_file': '/var/lib/idobata/dsh-lab/operators.json'}
    if definition.exists():
        regular(definition, uid=0, private=True)
        require(json.loads(definition.read_text()) == value, 'definition_already_differs')
    elif apply:
        definition.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        require(definition.parent.lstat().st_uid == 0 and
                stat.S_IMODE(definition.parent.stat().st_mode) == 0o700,
                'unsafe_definition_directory')
        atomic(definition, value)
    return {'status': 'definition_ready' if apply else 'definition_plan'}


def renew(definition, apply, force=False):
    regular(definition, uid=0, private=True)
    d = json.loads(definition.read_text())
    require(d.get('version') == 1 and d.get('controller') == 's21g'
            and d.get('synthetic') is True and d.get('room_alias') == 'dsh-lab',
            'invalid_lab_definition')
    config = json.loads((HOME/'config.json').read_text())
    current = config['rooms']['dsh-lab']
    require(immutable_room(current['certificate']['signed'], current['authority_peer_id']) == d['pin'],
            'authority_lab_definition_changed')
    for field in ['members_file', 'operators_file']:
        regular(Path(d[field]), uid=pwd.getpwnam('idobata').pw_uid, private=True)
    require(sorted(json.loads(Path(d['members_file']).read_text()), key=lambda m: m['peer_id']) == d['pin']['members']
            and json.loads(Path(d['operators_file']).read_text()) == d['pin']['knowledge_operators'],
            'fixed_authority_input_changed')
    remaining = current['certificate']['signed']['expires_at'] - int(time.time())
    if not apply:
        return {'status': 'read_only_plan', 'expires_in_seconds': remaining,
                'renewal_due': force or remaining <= RENEW_BEFORE}
    target_state = remote_update(GUEST_CURRENT, current, True)
    pending_repair = target_state.get('pending') is True
    if not force and remaining > RENEW_BEFORE and not pending_repair:
        if (remote_update(NATIVE_CURRENT, current, False).get('current') is True
                and target_state.get('current') is True):
            return {'status': 'unchanged', 'epoch': current['certificate']['signed']['epoch'],
                    'expires_at': current['certificate']['signed']['expires_at'],
                    'runner_certificate_current': True, 'synthetic': True}
    with runner_lease() as lease:
        lease.check_live()
        renewed = False
        if not pending_repair and (force or remaining <= RENEW_BEFORE):
            output = HOME/'dsh-lab'/('invite-'+str(time.time_ns())+'.json')
            root_sdk(['room', 'create', '--room', 'dsh-lab', '--members-file', d['members_file'],
                '--operators-file', d['operators_file'], '--require-automation',
                '--expires-hours', str(HOURS), '--output', str(output)])
            candidate = {'authority_peer_id': current['authority_peer_id'],
                         'certificate': json.loads(output.read_text())}
            check_update(current, candidate)
            current = candidate
            renewed = True
        lease.check_live()
        remote_update(NATIVE_UPDATE, current, False)
        lease.check_live()
        lease.apply(current)
    return {'status': 'renewed' if renewed else 'reconciled',
            'members': 3, 'epoch': current['certificate']['signed']['epoch'],
            'expires_at': current['certificate']['signed']['expires_at'],
            'runner_certificate_refreshed': True, 'synthetic': True}


def service_unit():
    return '''[Unit]
Description=Renew the fixed synthetic DSH lab and judgment certificate
After=network-online.target
Wants=network-online.target
ConditionPathExists=/etc/idobata-dsh-lab/definition.json
[Service]
Type=oneshot
User=root
ExecStart=/usr/bin/flock -w60 /home/vagrant/.local/state/idobata/room-maintenance.lock /usr/bin/python3 /usr/local/lib/idobata-dsh-lab/renew.py --maintenance-lock-held --apply
TimeoutStartSec=600
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/var/lib/idobata /etc/idobata-dsh-lab /home/vagrant/.local/state/idobata
UMask=0077
'''


def timer_unit():
    return '''[Unit]
Description=Bounded six-hour maintenance of the synthetic DSH lab
[Timer]
OnBootSec=10min
OnUnitActiveSec=6h
RandomizedDelaySec=2min
AccuracySec=1min
Unit=idobata-dsh-renew.service
[Install]
WantedBy=timers.target
'''


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--definition', type=Path, default=DEFINITION)
    p.add_argument('--initialize-from', type=Path)
    p.add_argument('--apply', action='store_true')
    p.add_argument('--force', action='store_true')
    p.add_argument('--maintenance-lock-held', action='store_true')
    p.add_argument('--emit', choices=['service', 'timer'])
    args = p.parse_args()
    if args.emit:
        print(service_unit() if args.emit == 'service' else timer_unit(), end='')
        return
    require(os.geteuid() == 0, 'root_required')
    with contextlib.ExitStack() as stack:
        if not args.maintenance_lock_held:
            regular(SHARED_LOCK, uid=pwd.getpwnam('vagrant').pw_uid, private=True)
            fd = os.open(SHARED_LOCK, os.O_RDWR | os.O_NOFOLLOW)
            stack.callback(os.close, fd)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise RuntimeError('room_maintenance_busy') from None
        result = initialize(args.initialize_from, args.definition, args.apply) if args.initialize_from else renew(args.definition, args.apply, args.force)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as error:
        reason = str(error) if isinstance(error, RuntimeError) else 'lab_renewal_operation_failed'
        hold = reason in ('judge_runner_busy_or_unprepared', 'judge_lock_transport_unavailable', 'room_maintenance_busy')
        print(json.dumps({'status': 'hold' if hold else 'failed', 'reason': reason}))
        raise SystemExit(0 if hold else 1)
