#!/usr/bin/env python3
"""既存Gateとhome経路に、公開peerのWebSocket専用中継だけを追加する。"""
import argparse
import base64
import html
import json
from pathlib import Path
import re
import subprocess
import urllib.parse

FRAGMENT = '''
              # BEGIN IDOBATA PEER
              server {
                listen 80;
                server_name idobata-peer.s21g.com;
                access_log off;
                error_log /dev/stderr warn;
                set $agent_gate_host home.s21g.com;
                resolver kube-dns.kube-system.svc.cluster.local valid=30s ipv6=off;
                location / {
                  include /etc/nginx/idobata-gate-auth/target.conf;
                  proxy_pass https://$agent_gate_host:8443$idobata_target;
                  proxy_ssl_verify on;
                  proxy_ssl_trusted_certificate /etc/nginx/home-upstream-tls/home-8443-trust.pem;
                  proxy_ssl_server_name on;
                  proxy_ssl_name agent-gate;
                  proxy_http_version 1.1;
                  proxy_set_header Host $agent_gate_host;
                  proxy_set_header Authorization $idobata_authorization;
                  proxy_set_header Upgrade $http_upgrade;
                  proxy_set_header Connection $connection_upgrade;
                  proxy_buffering off;
                  proxy_request_buffering off;
                  proxy_read_timeout 1h;
                  proxy_send_timeout 1h;
                }
              }
              # END IDOBATA PEER
'''


def run(argv, data=None):
    p = subprocess.run(argv, input=data, text=True, capture_output=True, timeout=360)
    if p.returncode:
        # curl例外などに資格情報入りURLを含めない。
        raise RuntimeError('操作に失敗しました: ' + argv[0])
    return p.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--context', required=True)
    parser.add_argument('--gate-token-file', default='/vagrant/token')
    parser.add_argument('--gate-ca', default='/home/vagrant/moon/envs/moon/home-s21g-com/tls/home-8443-trust.pem')
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    k = ['kubectl', '--context', args.context, '-n', 'home-s21g-com']
    deployment = json.loads(run(k + ['get', 'deployment', 'home-s21g-com', '-o', 'json']))
    template = deployment['spec']['template']['spec']
    command = template['containers'][0]['args'][-1]
    if 'BEGIN IDOBATA PEER' not in command:
        marker = '\nEOF\n'
        if command.count(marker) != 1:
            raise RuntimeError('既存home設定の挿入位置を確認できません')
        command = command.replace(marker, '\n' + FRAGMENT + marker)
    else:
        start=command.index('# BEGIN IDOBATA PEER');finish=command.index('# END IDOBATA PEER',start)+len('# END IDOBATA PEER')
        command=command[:start]+FRAGMENT.strip()+command[finish:]
    print(json.dumps({'status': 'prepared', 'route': 'idobata-peer.s21g.com',
                      'scope': 'proxy:ws / localhost:39114 / GET /', 'apply': args.apply}), flush=True)
    if not args.apply:
        return
    exists = subprocess.run(k + ['get', 'secret', 'idobata-gate-auth', '-o', 'name'], capture_output=True).returncode == 0
    if not exists:
        token = Path(args.gate_token_file).read_text().strip()
        if not re.fullmatch(r'[A-Za-z0-9_-]{16,256}', token):
            raise RuntimeError('管理資格情報の形式が不正です')
        params = urllib.parse.urlencode({'name': 'idobata-public-peer', 'scopes': 'proxy:ws',
            'methods': 'GET', 'proxy_hosts': 'localhost', 'proxy_ports': '39114',
            'proxy_paths': '/', 'expires_never': 'true'})
        # 管理tokenはargvと公開アクセスログへ載せず、検証済みのloopback TLS経路で使う。
        config = 'url = "https://agent-gate:8443/' + token + '/@tokens"\n'
        page = run(['curl', '--silent', '--show-error', '--fail', '--max-time', '15',
                    '--cacert', args.gate_ca, '--resolve', 'agent-gate:8443:127.0.0.1',
                    '--config', '-', '--data', params], config)
        found = re.search(r'<code class="secret-box">([^<]+)</code>', page)
        if not found:
            raise RuntimeError('限定tokenを発行できませんでした')
        scoped = html.unescape(found.group(1))
        if not re.fullmatch(r'[A-Za-z0-9_.-]{20,512}', scoped):
            raise RuntimeError('限定tokenの形式が不正です')
        value = 'set $idobata_target /@localhost:39114$request_uri;\nset $idobata_authorization \"Bearer ' + scoped + '\";\n'
        secret = {'apiVersion': 'v1', 'kind': 'Secret', 'metadata': {'name': 'idobata-gate-auth'},
                  'type': 'Opaque', 'data': {'target.conf': base64.b64encode(value.encode()).decode()}}
        run(k + ['create', '-f', '-'], json.dumps(secret))
    # 旧形式の自分の限定tokenだけを、URLからBearerへ移す。値は出力しない。
    secret=json.loads(run(k+['get','secret','idobata-gate-auth','-o','json']))
    current=base64.b64decode(secret['data']['target.conf']).decode()
    match=re.search(r'/moon/([A-Za-z0-9_.-]+)/@localhost:39114',current)
    if match:
        value='set $idobata_target /@localhost:39114$request_uri;\nset $idobata_authorization "Bearer '+match.group(1)+'";\n'
        patch=[{'op':'test','path':'/metadata/resourceVersion','value':secret['metadata']['resourceVersion']},
               {'op':'replace','path':'/data/target.conf','value':base64.b64encode(value.encode()).decode()}]
        run(k+['patch','secret','idobata-gate-auth','--type=json','--patch-file=/dev/stdin'],json.dumps(patch))
    elif 'set $idobata_target /moon/@localhost:39114' in current:
        value=current.replace('set $idobata_target /moon/@localhost:39114','set $idobata_target /@localhost:39114')
        patch=[{'op':'test','path':'/metadata/resourceVersion','value':secret['metadata']['resourceVersion']},
               {'op':'replace','path':'/data/target.conf','value':base64.b64encode(value.encode()).decode()}]
        run(k+['patch','secret','idobata-gate-auth','--type=json','--patch-file=/dev/stdin'],json.dumps(patch))
    template['containers'][0]['args'][-1] = command
    volumes = [v for v in template.get('volumes', []) if v['name'] != 'idobata-gate-auth']
    volumes.append({'name': 'idobata-gate-auth', 'secret': {'secretName': 'idobata-gate-auth'}})
    mounts = [m for m in template['containers'][0].get('volumeMounts', []) if m['name'] != 'idobata-gate-auth']
    mounts.append({'name': 'idobata-gate-auth', 'mountPath': '/etc/nginx/idobata-gate-auth', 'readOnly': True})
    template['containers'][0]['volumeMounts'] = mounts
    patch = [{'op': 'test', 'path': '/metadata/resourceVersion', 'value': deployment['metadata']['resourceVersion']},
             {'op': 'add', 'path': '/spec/template/spec/volumes', 'value': volumes},
             {'op': 'replace', 'path': '/spec/template/spec/containers', 'value': template['containers']}]
    run(k + ['patch', 'deployment', 'home-s21g-com', '--type=json', '--patch-file=/dev/stdin'], json.dumps(patch))
    run(k + ['rollout', 'status', 'deployment/home-s21g-com', '--timeout=300s'])
    print(json.dumps({'status': 'deployed', 'credentials_printed': False}))


if __name__ == '__main__':
    main()
