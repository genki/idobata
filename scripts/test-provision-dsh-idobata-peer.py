#!/usr/bin/env python3
import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('provision', Path(__file__).with_name('provision-dsh-idobata-peer.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class PeerProvisionTests(unittest.TestCase):
    def test_private_network_rejects_precede_public_wss_and_no_broad_loopback(self):
        rules = m.firewall_rules()
        public = rules.index(['-p', 'tcp', '--dport', '443', '-j', 'ACCEPT'])
        for cidr in ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '169.254.0.0/16', '127.0.0.0/8']:
            self.assertLess(rules.index(['-d', cidr, '-j', 'REJECT']), public)
        loopback_accept = [r for r in rules if '-d' in r and r[r.index('-d') + 1].startswith('127.') and r[-1] == 'ACCEPT']
        self.assertEqual(loopback_accept, [['-d', '127.0.0.1/32', '-p', 'tcp', '--dport', '39113', '-j', 'ACCEPT']])
        self.assertEqual(rules[-1], ['-j', 'REJECT'])

    def test_transport_templates_use_only_loopback_and_no_agent_keys(self):
        args = m.host_tunnel_plist()['ProgramArguments']
        self.assertEqual(args[args.index('-L') + 1], '127.0.0.1:39135:127.0.0.1:39134')
        self.assertEqual(args[args.index('-R') + 1], '127.0.0.1:39113:127.0.0.1:39113')
        self.assertIn('ControlPath=none', args)
        self.assertNotIn('-A', args)
        self.assertNotIn('GatewayPorts=yes', args)
        self.assertIn('-L 127.0.0.1:39135:127.0.0.1:39135', m.linux_tunnel_unit())
        self.assertNotIn('identity.key', str(args))

    def test_daemon_requires_firewall_and_rechecks_every_start(self):
        unit = m.service_unit()
        self.assertIn('Requires=idobata-dsh-peer-firewall.service', unit)
        self.assertIn('ExecStartPre=+/usr/bin/python3', unit)
        self.assertIn('--mode firewall-check', unit)
        self.assertIn('User=idobata-test', unit)
        self.assertIn('SupplementaryGroups=dsh', unit)
        self.assertIn('ProtectHome=true', unit)
        self.assertNotIn('User=dsh\n', unit)

    def test_symlinks_and_multiple_links_are_rejected_without_reading_content(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory);target = root/'target';target.write_text('synthetic')
            link = root/'link';link.symlink_to(target)
            with self.assertRaises(RuntimeError):m.regular(link)
            os.link(target, root/'second')
            with self.assertRaises(RuntimeError):m.regular(target)
            self.assertEqual(target.read_text(), 'synthetic')

    def test_atomic_failure_keeps_prior_file(self):
        with tempfile.TemporaryDirectory() as directory:
            target=Path(directory)/'state';target.write_bytes(b'prior')
            with mock.patch.object(m.os, 'replace', side_effect=OSError('synthetic')):
                with self.assertRaises(OSError):m.atomic(target, b'next', os.getuid(), os.getgid(), 0o600)
            self.assertEqual(target.read_bytes(), b'prior')
            self.assertEqual(list(Path(directory).iterdir()), [target])

    def fixture(self):
        members=[{'peer_id':p,'public_key':'public-'+p,'addresses':[a]} for p,a in [('hub','/dns4/idobata-peer.s21g.com/tcp/443/wss'),('native','/ip4/127.0.0.1/tcp/39113'),('guest','/ip4/127.0.0.1/tcp/39135')]]
        return {'signed':{'version':4,'room_id':'synthetic-room','members':members,'knowledge_automation_required':True,'knowledge_operators':{'bindings':{'hub':'s21g','native':'s21g','guest':'machinaai-test'},'credits':{'s21g':1000,'machinaai-test':1000}},'epoch':1,'issued_at':1,'expires_at':2}},members[2]

    def test_renewal_pin_ignores_only_epoch_and_times(self):
        cert,member=self.fixture();pin=m.test_room_pin(cert,member,'authority')
        newer=copy.deepcopy(cert);newer['signed'].update(epoch=2,issued_at=2,expires_at=3)
        self.assertEqual(pin,m.test_room_pin(newer,member,'authority'))
        self.assertNotEqual(pin,m.test_room_pin(newer,member,'different-authority'))
        newer['signed']['members'][0]['addresses']=['/ip4/127.0.0.1/tcp/9']
        self.assertNotEqual(pin,m.test_room_pin(newer,member,'authority'))

    def test_invalid_operator_or_automation_cannot_join(self):
        cert,member=self.fixture()
        for mutate in [lambda r:r.update(public=True),lambda r:r.update(knowledge_automation_required=False),lambda r:r['knowledge_operators']['bindings'].update(guest='s21g'),lambda r:r['knowledge_operators']['credits'].update(s21g=999),lambda r:r['members'].pop()]:
            bad=copy.deepcopy(cert);mutate(bad['signed'])
            with self.assertRaises(RuntimeError):m.test_room_pin(bad,member,'authority')

    def test_missing_firewall_never_passes_start_check(self):
        with mock.patch.object(m.pwd,'getpwnam',return_value=mock.Mock(pw_uid=991)),mock.patch.object(m,'run',side_effect=RuntimeError('missing_rule')):
            with self.assertRaises(RuntimeError):m.firewall(check_only=True)


if __name__=='__main__':unittest.main()
