#!/usr/bin/env python3
"""既存ホスト上に、公開経路だけを使う検証ノードとtimerを設置する。"""
import json
from pathlib import Path
import subprocess
import time

ROOT=Path(__file__).resolve().parents[1]
BINARY='/usr/local/lib/idobata/idobata'
HOME='/var/lib/idobata-public-probe'


def run(args,data=None):
    p=subprocess.run(args,input=data,text=True,capture_output=True,timeout=90)
    if p.returncode:raise RuntimeError('公開経路probeの設定に失敗: '+args[0])
    return p.stdout


if __name__=='__main__':
    run(['sudo','-n','install','-d','-m','700','-o','idobata','-g','idobata',HOME])
    if subprocess.run(['sudo','-n','test','-f',HOME+'/identity.key']).returncode:
        run(['sudo','-n','-u','idobata',BINARY,'--home',HOME,'init','--listen','/ip4/127.0.0.1/tcp/39115'])
    node=json.loads(run(['sudo','-n','-u','idobata',BINARY,'--home',HOME,'identity']));node['addresses']=[]
    hub=json.loads(run(['sudo','-n','-u','idobata',BINARY,'--home','/var/lib/idobata','identity']))
    hub['addresses']=['/dns4/idobata-peer.s21g.com/tcp/443/wss']
    run(['sudo','-n','-u','idobata','tee','/var/lib/idobata/reachability-members.json'],json.dumps([hub,node]))
    run(['sudo','-n','chmod','600','/var/lib/idobata/reachability-members.json'])
    invite='/var/lib/idobata/reachability-invite-'+str(time.time_ns())+'.json'
    run(['sudo','-n','-u','idobata',BINARY,'--home','/var/lib/idobata','room','create','--room','reachability',
         '--members-file','/var/lib/idobata/reachability-members.json','--expires-hours','168','--output',invite])
    run(['sudo','-n','-u','idobata',BINARY,'--home',HOME,'room','join','--room','reachability',
         '--invite-file',invite,'--trust-authority',hub['peer_id']])
    run(['sudo','-n','install','-m','755',str(ROOT/'scripts/check-public-route.py'),'/usr/local/lib/idobata/check-public-route.py'])
    daemon=f'''[Unit]
Description=idobata public WSS route probe node
After=idobata.service network-online.target
[Service]
User=idobata
Group=vagrant
ExecStart={BINARY} --home {HOME} daemon
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths={HOME}
[Install]
WantedBy=multi-user.target
'''
    check='''[Unit]
Description=Verify public idobata route using signed receipt
After=idobata-public-probe.service
Requires=idobata-public-probe.service
[Service]
Type=oneshot
User=idobata
Group=vagrant
ExecStart=/usr/bin/python3 /usr/local/lib/idobata/check-public-route.py
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/run/idobata /var/lib/idobata-public-probe
'''
    timer='''[Unit]
Description=Recheck public idobata route
[Timer]
OnBootSec=30
OnUnitInactiveSec=300
Unit=idobata-public-route.service
[Install]
WantedBy=timers.target
'''
    for name,text in [('idobata-public-probe.service',daemon),('idobata-public-route.service',check),('idobata-public-route.timer',timer)]:
        run(['sudo','-n','tee','/etc/systemd/system/'+name],text)
    run(['sudo','-n','systemctl','daemon-reload'])
    run(['sudo','-n','systemctl','enable','--now','idobata-public-probe.service'])
    run(['sudo','-n','systemctl','start','idobata-public-route.service'])
    run(['sudo','-n','systemctl','enable','--now','idobata-public-route.timer'])
    print(json.dumps({'status':'configured','probe_interval_seconds':300}))
