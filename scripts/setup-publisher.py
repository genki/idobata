#!/usr/bin/env python3
"""公開データ専用の最小RBACと、既存ホストの更新timerを設置する。"""
import argparse
import base64
import json
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]


def run(argv, data=None):
    p = subprocess.run(argv, input=data, text=True, capture_output=True, timeout=60)
    if p.returncode:
        raise RuntimeError('公開更新の設定に失敗: '+argv[0])
    return p.stdout


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--context', required=True)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    if not args.apply:
        raise SystemExit('明示的な --apply が必要です')
    k = ['kubectl', '--context', args.context, '-n', 'default']
    resources = [
        {'apiVersion': 'v1', 'kind': 'ServiceAccount', 'metadata': {'name': 'idobata-publisher'}},
        {'apiVersion': 'rbac.authorization.k8s.io/v1', 'kind': 'Role',
         'metadata': {'name': 'idobata-publisher'}, 'rules': [
             {'apiGroups': [''], 'resources': ['configmaps'], 'resourceNames': ['idobata-feed'], 'verbs': ['get','patch']}]},
        {'apiVersion': 'rbac.authorization.k8s.io/v1', 'kind': 'RoleBinding',
         'metadata': {'name': 'idobata-publisher'},
         'subjects': [{'kind': 'ServiceAccount', 'name': 'idobata-publisher', 'namespace': 'default'}],
         'roleRef': {'apiGroup': 'rbac.authorization.k8s.io', 'kind': 'Role', 'name': 'idobata-publisher'}},
        {'apiVersion': 'v1', 'kind': 'Secret', 'metadata': {'name': 'idobata-publisher-auth',
             'annotations': {'kubernetes.io/service-account.name': 'idobata-publisher'}},
         'type': 'kubernetes.io/service-account-token'},
    ]
    for resource in resources:
        run(k+['apply','-f','-'], json.dumps(resource))
    credential = None
    for _ in range(15):
        secret = json.loads(run(k+['get','secret','idobata-publisher-auth','-o','json']))
        if secret.get('data',{}).get('token'):
            credential = base64.b64decode(secret['data']['token']).decode(); break
        time.sleep(1)
    if not credential:
        raise RuntimeError('限定資格情報を生成できません')
    cluster = json.loads(run(['kubectl','--context',args.context,'config','view','--minify','--raw',
                             '-o','jsonpath={.clusters[0].cluster}']))
    config = {'apiVersion': 'v1', 'kind': 'Config', 'clusters': [{'name':'idobata','cluster':cluster}],
              'users':[{'name':'publisher','user':{'token':credential}}],
              'contexts':[{'name':'publisher','context':{'cluster':'idobata','user':'publisher','namespace':'default'}}],
              'current-context':'publisher'}
    run(['sudo','-n','install','-d','-m','700','-o','idobata','-g','idobata','/var/lib/idobata-publisher'])
    # 同一ホストの既存公開用鍵を移設する。P2Pノード鍵や他ホストの鍵はコピーしない。
    for source,name in [(Path('/home/vagrant/.local/share/idobata-publication/identity.key'),'identity.key'),
                        (ROOT/'site/posts.json','posts.json'),(ROOT/'site/publisher.json','publisher.json')]:
        destination='/var/lib/idobata-publisher/'+name
        if subprocess.run(['sudo','-n','test','-f',destination]).returncode:
            run(['sudo','-n','install','-m','600','-o','idobata','-g','idobata',str(source),destination])
    for name in ['trust-root.json','trust.json']:
        if (ROOT/'site'/name).exists():run(['sudo','-n','install','-m','600','-o','idobata','-g','idobata',str(ROOT/'site'/name),'/var/lib/idobata-publisher/'+name])
    run(['sudo','-n','tee','/var/lib/idobata-publisher/kubeconfig'],json.dumps(config))
    run(['sudo','-n','chown','idobata:idobata','/var/lib/idobata-publisher/kubeconfig'])
    run(['sudo','-n','chmod','600','/var/lib/idobata-publisher/kubeconfig'])
    for verb,resource,expected in [('get','configmap/idobata-feed','yes'),('patch','configmap/idobata-feed','yes'),
                                   ('get','configmap/moon-frontdoor-config','no'),('patch','deployment/frontdoor','no')]:
        p=subprocess.run(['sudo','-n','-u','idobata','kubectl','--kubeconfig','/var/lib/idobata-publisher/kubeconfig',
                          'auth','can-i',verb,resource,'-n','default'],capture_output=True,text=True,timeout=30)
        if p.stdout.strip()!=expected:
            raise RuntimeError('公開用RBACが想定と一致しません')
    run(['sudo','-n','install','-m','755',str(ROOT/'scripts/publish-feed.py'),'/usr/local/lib/idobata/publish-feed.py'])
    service='''[Unit]
Description=idobata verified public feed publication
After=idobata.service network-online.target
Requires=idobata.service
[Service]
Type=oneshot
User=idobata
Group=vagrant
ExecStart=/usr/bin/python3 /usr/local/lib/idobata/publish-feed.py
NoNewPrivileges=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/var/lib/idobata-publisher /run/idobata
UMask=0077
'''
    timer='''[Unit]
Description=Refresh idobata public feed and bootstrap
[Timer]
OnBootSec=45
OnUnitInactiveSec=30
Unit=idobata-publisher.service
[Install]
WantedBy=timers.target
'''
    for name,text in [('idobata-publisher.service',service),('idobata-publisher.timer',timer)]:
        run(['sudo','-n','tee','/etc/systemd/system/'+name],text)
    run(['sudo','-n','systemctl','daemon-reload'])
    run(['sudo','-n','systemctl','start','idobata-publisher.service'])
    run(['sudo','-n','systemctl','enable','--now','idobata-publisher.timer'])
    print(json.dumps({'status':'installed','update_interval_seconds':30,'scope':'default/configmap/idobata-feed only'}))
