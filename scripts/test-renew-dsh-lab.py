#!/usr/bin/env python3
import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import subprocess
import sys
import fcntl
import unittest
from unittest import mock

spec=importlib.util.spec_from_file_location('renew_lab',Path(__file__).with_name('renew-dsh-lab.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


class RenewalTests(unittest.TestCase):
    def fixture(self):
        return {'authority_peer_id':'authority','certificate':{'signed':{'version':4,'room_id':'lab','policy_id':'fixed','members':[{'peer_id':p,'public_key':'key-'+p,'addresses':[a]} for p,a in [('a','/dns4/idobata-peer.s21g.com/tcp/443/wss'),('b','/ip4/127.0.0.1/tcp/39113'),('c','/ip4/127.0.0.1/tcp/39135')]],'knowledge_operators':{'bindings':{'a':'s21g','b':'s21g','c':'machinaai-test'},'credits':{'s21g':1000,'machinaai-test':1000}},'knowledge_automation_required':True,'epoch':1,'issued_at':1,'expires_at':2},'public_key':'authority-key','signature':'synthetic'}}

    def test_monotonic_epoch_accepts_same_scope_and_omitted_private_flag(self):
        old=self.fixture();new=copy.deepcopy(old);new['certificate']['signed'].update(epoch=2,issued_at=2,expires_at=3)
        m.check_update(old,new);m.check_update(old,copy.deepcopy(old))
        new['certificate']['signed']['public']=False
        m.check_update(old,new)

    def test_rollback_same_epoch_mutation_and_scope_change_rejected(self):
        old=self.fixture()
        for mutate in [lambda n:n['certificate']['signed'].update(epoch=0),lambda n:n['certificate']['signed'].update(expires_at=9),lambda n:n.update(authority_peer_id='other'),lambda n:n['certificate']['signed'].update(room_id='other'),lambda n:n['certificate']['signed'].update(policy_id='other'),lambda n:n['certificate']['signed'].update(knowledge_automation_required=False),lambda n:n['certificate']['signed'].update(public=True),lambda n:n['certificate']['signed']['knowledge_operators']['bindings'].update(c='s21g')]:
            bad=copy.deepcopy(old);mutate(bad)
            with self.assertRaises(RuntimeError):m.check_update(old,bad)

    def test_waiting_lease_never_creates_agent_lock_or_reads_keys(self):
        self.assertIn('os.O_NOFOLLOW',m.LEASE_CODE)
        self.assertNotIn('O_CREAT',m.LEASE_CODE)
        self.assertIn('lease_stat.st_uid==2000',m.LEASE_CODE)
        self.assertIn('stat.S_IMODE(lease_stat.st_mode)==0o600',m.LEASE_CODE)
        self.assertIn('fcntl.LOCK_EX)',m.LEASE_CODE)
        self.assertNotIn('identity.key',m.LEASE_CODE)

    def test_all_embedded_programs_compile_without_credentials(self):
        for code in [m.LEASE_CODE,m.GUEST_UPDATE,m.NATIVE_UPDATE,m.GUEST_CURRENT,m.NATIVE_CURRENT]:
            compile(code,'<maintenance-program>','exec')
            self.assertNotIn('storage.key',code)
        compile(m.lease_worker_source(),'<single-lock-worker>','exec')
        self.assertIn("config['room']={'authority_peer_id':authority,'certificate':cert}",m.GUEST_UPDATE)

    def test_remote_argv_has_fixed_host_and_no_agent_forwarding(self):
        argv=m.remote_argv('print("safe")');self.assertIn('ForwardAgent=no',argv)
        self.assertIn('ControlPath=none',argv);self.assertIn('machinaai',argv)
        self.assertIn('lima-dsh',argv[-1]);self.assertIn('sudo -n python3 -c',argv[-1])
        self.assertNotIn('-A',argv)

    def test_atomic_failure_preserves_prior_definition(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'definition.json';p.write_text('{"prior":true}')
            with mock.patch.object(m.os,'replace',side_effect=OSError('synthetic')):
                with self.assertRaises(OSError):m.atomic(p,{'next':True})
            self.assertEqual(json.loads(p.read_text()),{'prior':True})
            self.assertEqual(list(Path(d).iterdir()),[p])

    def test_lost_lease_is_not_success(self):
        fake=mock.Mock();fake.stdout=mock.Mock();fake.stdout.readline.return_value=b'locked\n';fake.poll.return_value=1
        selector=mock.Mock();selector.select.return_value=[True]
        with mock.patch.object(m.subprocess,'Popen',return_value=fake),mock.patch.object(m.selectors,'DefaultSelector',return_value=selector):
            with self.assertRaisesRegex(RuntimeError,'judge_lock_lease_lost'):
                with m.runner_lease():self.fail('must_not_continue')

    def test_service_serializes_existing_maintenance_and_has_bounded_wait(self):
        self.assertIn('/usr/bin/flock -w60 /home/vagrant/.local/state/idobata/room-maintenance.lock',m.service_unit())
        self.assertIn('TimeoutStartSec=600',m.service_unit())
        self.assertIn('--maintenance-lock-held --apply',m.service_unit())
        self.assertIn('OnUnitActiveSec=6h',m.timer_unit())
        self.assertNotIn('Restart=',m.service_unit())


class SingleHolderTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        for name in ['etc','state','admin','node']:(self.root/name).mkdir(mode=0o700)
        self.lock=self.root/'state/runner.lock';self.lock.write_text('');self.lock.chmod(0o600)
        self.old=RenewalTests().fixture();self.new=copy.deepcopy(self.old);self.new['certificate']['signed'].update(epoch=2,issued_at=2,expires_at=3)
        self.cfg=self.root/'etc/config.json';self.cfg.write_text(json.dumps({'room':self.old,'fixed_setting':'preserved'}));self.cfg.chmod(0o644)
        self.node=self.root/'node/config.json';self.node.write_text(json.dumps({'rooms':{'dsh-lab':self.old}}))
        self.marker=self.root/'etc/authorization-update.pending';self.children=[]

    def tearDown(self):
        for child in self.children:
            if child.poll() is None:child.kill()
            child.communicate()
        self.temp.cleanup()

    def source(self,crash=False):
        src=m.lease_worker_source()
        for old,new in [('/home/dsh/.local/state/idobata-judge/runner.lock',str(self.lock)),('/etc/idobata-judge/config.json',str(self.cfg)),('/var/lib/idobata-machinaai-test/config.json',str(self.node)),('/etc/idobata-dsh-peer/invite.json',str(self.root/'admin/invite.json'))]:src=src.replace(old,new)
        src=src.replace('st_uid==2000','st_uid=='+str(os.getuid())).replace('st_uid==0','st_uid=='+str(os.getuid()))
        injected='''
import subprocess,types
def simulated_sdk(args,**kwargs):
 fd=os.open(lease_path,os.O_RDWR)
 try:
  try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
  except BlockingIOError:pass
  else:raise AssertionError('actual_lock_not_held_during_join')
 finally:os.close(fd)
 assert marker_path.exists()
 invite=Path(args[args.index('--invite')+1]);certificate=json.loads(invite.read_text())
 p=Path(NODE_PATH);value={'rooms':{'dsh-lab':{'authority_peer_id':'authority','certificate':certificate}}}
 with p.open('w') as f:json.dump(value,f);f.flush();os.fsync(f.fileno())
 if CRASH:os._exit(88)
 return types.SimpleNamespace(returncode=0)
subprocess.run=simulated_sdk
'''.replace('NODE_PATH',repr(str(self.node))).replace('CRASH',repr(crash))
        return src.replace("print('locked',flush=True)",injected+"\nprint('locked',flush=True)")

    def start(self,crash=False,expect=b'locked\n'):
        p=subprocess.Popen([sys.executable,'-c',self.source(crash)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        self.children.append(p);self.assertEqual(p.stdout.readline(),expect)
        return p

    def apply(self,p,value):
        p.stdin.write(json.dumps(value).encode()+b'\n');p.stdin.flush();p.stdin.close();p.stdin=None
        out,err=p.communicate(timeout=10)
        return p.returncode,out,err

    def test_same_process_holds_actual_lock_through_join_config_and_reply(self):
        p=self.start();self.assertTrue(self.marker.exists());self.assertEqual(self.marker.stat().st_mode & 0o777,0o600)
        with self.lock.open('r+') as lock:
            with self.assertRaises(BlockingIOError):fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        code,out,err=self.apply(p,self.new);self.assertEqual(code,0,err);result=json.loads(out)
        self.assertTrue(result['durable_marker_cleared']);self.assertFalse(self.marker.exists())
        self.assertEqual(json.loads(self.node.read_text())['rooms']['dsh-lab'],self.new)
        self.assertEqual(json.loads(self.cfg.read_text())['room'],self.new)
        self.assertEqual(json.loads(self.cfg.read_text())['fixed_setting'],'preserved')

    def test_transport_eof_leaves_pending_and_same_epoch_repair_clears_it(self):
        p=self.start();p.stdin.close();p.stdin=None;out,err=p.communicate(timeout=10)
        self.assertNotEqual(p.returncode,0);self.assertTrue(self.marker.exists())
        self.assertEqual(json.loads(self.cfg.read_text())['room'],self.old)
        repair=self.start();code,out,err=self.apply(repair,self.old)
        self.assertEqual(code,0,err);self.assertEqual(json.loads(out)['epoch'],1)
        self.assertFalse(self.marker.exists())

    def test_crash_between_sdk_join_and_config_write_blocks_until_same_target_repair(self):
        p=self.start(crash=True);code,out,err=self.apply(p,self.new)
        self.assertEqual(code,88);self.assertTrue(self.marker.exists())
        self.assertEqual(json.loads(self.node.read_text())['rooms']['dsh-lab'],self.new)
        self.assertEqual(json.loads(self.cfg.read_text())['room'],self.old)
        repair=self.start();code,out,err=self.apply(repair,self.new)
        self.assertEqual(code,0,err);self.assertFalse(self.marker.exists())
        self.assertEqual(json.loads(self.cfg.read_text())['room'],self.new)

    def test_unsafe_pending_symlink_is_rejected_before_update(self):
        self.marker.symlink_to(self.root/'missing')
        p=self.start(expect=b'invalid\n');p.stdin.close();p.stdin=None;p.communicate(timeout=10)
        self.assertNotEqual(p.returncode,0);self.assertTrue(self.marker.is_symlink())
        self.assertEqual(json.loads(self.node.read_text())['rooms']['dsh-lab'],self.old)

    def test_pending_never_takes_the_current_certificate_noop_path(self):
        self.marker.write_text('{}');code=m.GUEST_CURRENT.replace('/etc/idobata-judge/config.json',str(self.cfg)).replace('/var/lib/idobata-machinaai-test/config.json',str(self.node))
        p=subprocess.run([sys.executable,'-c',code],input=json.dumps(self.old).encode(),capture_output=True,check=True)
        value=json.loads(p.stdout);self.assertTrue(value['pending']);self.assertFalse(value['current'])

    def test_unknown_rpc_fields_fail_closed_before_sdk_or_config_mutation(self):
        p=self.start();value=copy.deepcopy(self.new);value['unexpected']='rejected'
        code,out,err=self.apply(p,value);self.assertNotEqual(code,0)
        self.assertTrue(self.marker.exists())
        self.assertEqual(json.loads(self.node.read_text())['rooms']['dsh-lab'],self.old)
        self.assertEqual(json.loads(self.cfg.read_text())['room'],self.old)


if __name__=='__main__':unittest.main()
