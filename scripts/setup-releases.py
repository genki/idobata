#!/usr/bin/env python3
"""TUF四役割を初期化し、オンライン更新者へ二役割だけを渡す。"""
import argparse
import base64
import json
from pathlib import Path
import subprocess
import time

ROOT=Path(__file__).resolve().parents[1]
OFFLINE='/var/lib/idobata-release-offline'
HOME='/var/lib/idobata-release'


def run(args,data=None):
    p=subprocess.run(args,input=data,capture_output=True,text=True,timeout=120)
    if p.returncode:raise RuntimeError('配布設定の操作に失敗: '+args[0])
    return p.stdout


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--context',required=True);parser.add_argument('--artifacts',required=True)
    parser.add_argument('--revision',type=int,default=1)
    parser.add_argument('--apply',action='store_true');args=parser.parse_args()
    if not args.apply:raise SystemExit('--apply が必要です')
    if subprocess.run(['id','idobata-release'],capture_output=True).returncode:
        run(['sudo','-n','useradd','--system','--no-create-home','--shell','/usr/sbin/nologin','idobata-release'])
    run(['sudo','-n','install','-d','-m','700',OFFLINE,OFFLINE+'/keys',OFFLINE+'/metadata'])
    previous=0
    if subprocess.run(['sudo','-n','test','-f',OFFLINE+'/metadata/timestamp.json']).returncode==0:
        previous=json.loads(run(['sudo','-n','cat',OFFLINE+'/metadata/timestamp.json']))['signed']['version']
    changed=args.revision>previous
    if changed:
        run(['sudo','-n','/usr/local/lib/idobata/idobata','release','create','--keys-home',OFFLINE+'/keys',
             '--targets-dir',str(Path(args.artifacts).resolve()),'--output',OFFLINE+'/metadata','--revision',str(args.revision)])
    run(['sudo','-n','install','-d','-m','700','-o','idobata-release','-g','idobata-release',HOME,HOME+'/keys',HOME+'/metadata'])
    for name in ['root.json','1.root.json','targets.json','snapshot.json','timestamp.json']:
        target=HOME+'/metadata/'+name
        if changed or subprocess.run(['sudo','-n','test','-f',target]).returncode:
            run(['sudo','-n','install','-m','600','-o','idobata-release','-g','idobata-release',OFFLINE+'/metadata/'+name,target])
    for role in ['snapshot','timestamp']:
        run(['sudo','-n','install','-m','600','-o','idobata-release','-g','idobata-release',OFFLINE+'/keys/'+role+'.key',HOME+'/keys/'+role+'.key'])
    k=['kubectl','--context',args.context,'-n','default']
    resources=[{'apiVersion':'v1','kind':'ServiceAccount','metadata':{'name':'idobata-release'}},
      {'apiVersion':'rbac.authorization.k8s.io/v1','kind':'RoleBinding','metadata':{'name':'idobata-release'},
       'subjects':[{'kind':'ServiceAccount','name':'idobata-release','namespace':'default'}],
       'roleRef':{'apiGroup':'rbac.authorization.k8s.io','kind':'Role','name':'idobata-publisher'}},
      {'apiVersion':'v1','kind':'Secret','metadata':{'name':'idobata-release-auth',
       'annotations':{'kubernetes.io/service-account.name':'idobata-release'}},'type':'kubernetes.io/service-account-token'}]
    for r in resources:run(k+['apply','-f','-'],json.dumps(r))
    for _ in range(15):
        s=json.loads(run(k+['get','secret','idobata-release-auth','-o','json']))
        if s.get('data',{}).get('token'):break
        time.sleep(1)
    cluster=json.loads(run(['kubectl','--context',args.context,'config','view','--minify','--raw','-o','jsonpath={.clusters[0].cluster}']))
    cfg={'apiVersion':'v1','kind':'Config','clusters':[{'name':'idobata','cluster':cluster}],
         'users':[{'name':'release','user':{'token':base64.b64decode(s['data']['token']).decode()}}],
         'contexts':[{'name':'release','context':{'cluster':'idobata','user':'release','namespace':'default'}}],'current-context':'release'}
    run(['sudo','-n','tee',HOME+'/kubeconfig'],json.dumps(cfg))
    run(['sudo','-n','chown','idobata-release:idobata-release',HOME+'/kubeconfig']);run(['sudo','-n','chmod','600',HOME+'/kubeconfig'])
    for source,name in [(ROOT/'target/debug/examples/refresh-tuf','refresh-tuf'),(ROOT/'scripts/refresh-releases.py','refresh-releases.py')]:
        run(['sudo','-n','install','-m','755',str(source),'/usr/local/lib/idobata/'+name])
    service='''[Unit]
Description=idobata TUF metadata refresh
After=network-online.target
[Service]
Type=oneshot
User=idobata-release
Group=vagrant
RuntimeDirectory=idobata-release
RuntimeDirectoryMode=0750
RuntimeDirectoryPreserve=yes
ExecStart=/usr/bin/python3 /usr/local/lib/idobata/refresh-releases.py
NoNewPrivileges=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/var/lib/idobata-release /run/idobata-release
UMask=0077
'''
    timer='''[Unit]
Description=Refresh TUF metadata every six hours
[Timer]
OnBootSec=60
OnUnitInactiveSec=21600
Unit=idobata-release.service
[Install]
WantedBy=timers.target
'''
    for name,text in [('idobata-release.service',service),('idobata-release.timer',timer)]:
        run(['sudo','-n','tee','/etc/systemd/system/'+name],text)
    run(['sudo','-n','systemctl','daemon-reload']);run(['sudo','-n','systemctl','start','idobata-release.service'])
    run(['sudo','-n','systemctl','enable','--now','idobata-release.timer'])
    updates=ROOT/'site/updates';updates.mkdir(exist_ok=True)
    for name in ['root.json','1.root.json','targets.json','snapshot.json','timestamp.json']:
        (updates/name).write_text(run(['sudo','-n','cat',HOME+'/metadata/'+name]))
    print(json.dumps({'status':'installed','online_roles':['snapshot','timestamp'],'interval_hours':6}))
