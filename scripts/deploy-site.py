#!/usr/bin/env python3
"""既存frontdoorへ静的サイトだけを追加する。新規Pod・PVC・LBを作らない。"""
import argparse
import base64
from email.message import Message
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
BEGIN = '# BEGIN IDOBATA SITE'
END = '# END IDOBATA SITE'
FILES = {
    'idobata-index.html': 'site/index.html',
    'idobata-docs.html': 'site/docs/index.html',
    'idobata-agents.md': 'site/agents.md',
    'idobata-llms.txt': 'site/llms.txt',
    'idobata-agent.json': 'site/agent.json',
    'idobata-analytics.js': 'site/analytics.js',
    'idobata-analytics-frame.html': 'site/analytics-frame.html',
    'idobata-analytics-sender.js': 'site/analytics-sender.js',
    'idobata-style.css': 'site/style.css',
    'idobata-app.js': 'site/app.js',
    'idobata-posts.json': 'site/posts.json',
    'idobata-publisher.json': 'site/publisher.json',
    'idobata-sitemap.xml': 'site/sitemap.xml',
    'idobata-releases.json': 'site/releases.json',
}
AGENT_ROUTES = {
    '/agents.md': ('idobata-agents.md', 'text/markdown'),
    '/llms.txt': ('idobata-llms.txt', 'text/plain'),
    '/.well-known/idobata/agent.json': ('idobata-agent.json', 'application/json'),
}
ANALYTICS_ROUTES = {
    '/analytics.js': ('idobata-analytics.js', 'text/javascript'),
    '/analytics-frame.html': ('idobata-analytics-frame.html', 'text/html'),
    '/analytics-sender.js': ('idobata-analytics-sender.js', 'text/javascript'),
}


def run(args, data=None):
    return subprocess.run(args, input=data, text=True, capture_output=True,
                          check=True, timeout=60).stdout


def verify_agent_routes(address, assets):
    """Verify public GET bytes and HEAD MIME, without executing guide commands."""
    for route, (name, expected_type) in {**AGENT_ROUTES, **ANALYTICS_ROUTES}.items():
        for head in [False, True]:
            command = ['curl', '--fail', '--silent', '--show-error', '--max-time', '10',
                       '--header', 'X-Idobata-Diagnostic: 1',
                       '--resolve', 'idobata.s21g.com:443:' + address]
            if head:
                command.append('--head')
            command += ['--write-out', '\n%{http_code}\n%{content_type}',
                        'https://idobata.s21g.com' + route]
            response = subprocess.run(command, capture_output=True, check=True, timeout=15)
            body, status, content_type = response.stdout.rsplit(b'\n', 2)
            headers = Message()
            headers['Content-Type'] = content_type.decode()
            if status != b'200' or headers.get_content_type() != expected_type:
                raise ValueError('agent文書のHTTP状態またはMIMEが不一致です')
            if expected_type.startswith('text/') and headers.get_content_charset() != 'utf-8':
                raise ValueError('agent文書のUTF-8 charsetが不一致です')
            if not head and body != assets[name].encode('utf-8'):
                raise ValueError('agent文書の配信bytesが不一致です')
            if not head and route.endswith('.json'):
                if not isinstance(json.loads(body), dict):
                    raise ValueError('agent文書のJSON構造が不正です')


def replace_block(config, fragment):
    if config.count(BEGIN) != config.count(END) or config.count(BEGIN) > 1:
        raise ValueError('idobata設定の境界が不正です')
    if BEGIN in config:
        start = config.index(BEGIN)
        finish = config.index(END, start) + len(END)
        return config[:start] + fragment.rstrip() + config[finish:]
    if 'server_name idobata.s21g.com' in config:
        raise ValueError('管理外のidobata設定があります')
    offset = config.rfind('}')
    if offset < 0 or config[offset + 1:].strip():
        raise ValueError('httpブロックの末尾を確認できません')
    return config[:offset] + fragment + '\n' + config[offset:]


def main():
    import hashlib, time, urllib.request
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--context', required=True)
    parser.add_argument('--namespace', default='default')
    parser.add_argument('--configmap', default='moon-frontdoor-config')
    parser.add_argument('--selector', default='app=frontdoor')
    parser.add_argument('--binary', default=str(ROOT / 'target/debug/idobata'))
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--remove', action='store_true')
    args = parser.parse_args()
    k = ['kubectl', '--context', args.context, '-n', args.namespace]
    cm = json.loads(run(k + ['get', 'configmap', args.configmap, '-o', 'json']))
    original = cm['data']['nginx.conf']
    old_block = original[original.index(BEGIN):original.index(END)+len(END)] if BEGIN in original else ''
    fragment = '' if args.remove else (ROOT/'site/nginx.conf').read_text()
    rendered = replace_block(original, fragment)
    key = json.loads((ROOT/'site/publisher.json').read_text())
    policy = json.loads(run([args.binary, 'profile']))['policy_id']
    trust_value={'publisher':key,'policy':policy}
    if (ROOT/'site/trust-root.json').exists():
        trust_value.update(root=json.loads((ROOT/'site/trust-root.json').read_text()),bundle=json.loads((ROOT/'site/trust.json').read_text()))
    trust = 'window.IDOBATA_TRUST = Object.freeze(' + json.dumps(trust_value) + ');\n'
    assets = {name:(ROOT/path).read_bytes().decode('utf-8') for name,path in FILES.items()
              if name not in ['idobata-posts.json','idobata-publisher.json']}
    assets['idobata-trust.js'] = trust
    for name in ['trust-root.json','trust.json']:
        if (ROOT/'site'/name).exists():assets['idobata-'+name]=(ROOT/'site'/name).read_text()
    assets['idobata-verify-feed.js'] = (ROOT/'site/verify-feed.js').read_text()
    icon = (ROOT/'site/icon.webp').read_bytes()
    digest = hashlib.sha256(json.dumps(assets,sort_keys=True).encode()+icon+fragment.encode()).hexdigest()
    assets['idobata-revision.json'] = json.dumps({'version':1,'revision':digest})
    feed_data = {'posts.json':(ROOT/'site/posts.json').read_text(),
                 'publisher.json':json.dumps(key)}
    existing_feed=subprocess.run(k+['get','configmap','idobata-feed','-o','json'],capture_output=True,text=True,timeout=30)
    if existing_feed.returncode==0:
        existing_data=json.loads(existing_feed.stdout)['data']
        old_revision=json.loads(existing_data['posts.json'])['signed']['revision']
        source_revision=json.loads(feed_data['posts.json'])['signed']['revision']
        if old_revision>=source_revision:feed_data=existing_data
    if (ROOT/'site/bootstrap.json').exists() and 'bootstrap.json' not in feed_data:
        feed_data['bootstrap.json']=(ROOT/'site/bootstrap.json').read_text()
    if (ROOT/'site/releases.json').exists():
        assets['idobata-releases.json']=(ROOT/'site/releases.json').read_text()
    trust_args=['--trust-publisher',str(ROOT/'site/publisher.json')]
    if (ROOT/'site/trust-root.json').exists():
        trust_args=['--trust-publisher',str(ROOT/'site/trust-root.json'),'--trust-bundle',str(ROOT/'site/trust.json')]
    if not args.remove:
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w',suffix='.json') as public_file:
            public_file.write(feed_data['posts.json']);public_file.flush()
            run([args.binary,'public','verify','--feed',public_file.name]+trust_args)
    own_names=set(FILES)
    shared_size=sum(len(v.encode()) for name,v in cm['data'].items()
                    if name not in own_names and name!='nginx.conf')+len(rendered.encode())
    other_binary={name:value for name,value in cm.get('binaryData',{}).items()
                  if name!='idobata-icon.png'}
    shared_size+=sum(len(base64.b64decode(v)) for v in other_binary.values())
    if shared_size>1048576//5 or sum(len(v.encode()) for v in assets.values())+len(icon)>1048576:
        raise ValueError('サイト分離後の容量条件を満たしません')
    if len(icon)>100*1024 or len(feed_data['posts.json'].encode())>256*1024:
        raise ValueError('公開データのサイズ上限を超えています')
    pods=json.loads(run(k+['get','pods','-l',args.selector,'-o','json']))['items']
    ready=[p['metadata']['name'] for p in pods if not p['metadata'].get('deletionTimestamp')
           and any(c['type']=='Ready' and c['status']=='True' for c in p.get('status',{}).get('conditions',[]))]
    if not ready: raise ValueError('検証対象のfrontdoorがありません')
    for pod in ready:
        run(k+['exec','-i',pod,'-c','nginx','--','sh','-c',
               'umask 077; f=$(mktemp /tmp/idobata-nginx.XXXXXX); '
               'trap \'rm -f "$f"\' EXIT; cat > "$f"; nginx -t -c "$f"'],rendered)
    print(json.dumps({'status':'validated','shared_config_bytes':shared_size,
                      'icon_bytes':len(icon),'revision':digest,'apply':args.apply}),flush=True)
    if not args.apply: return
    if not args.remove:
        for name,data,binary in [('idobata-site',assets,{'idobata-icon.webp':base64.b64encode(icon).decode()}),
                                 ('idobata-feed',feed_data,{})]:
            if name=='idobata-feed' and existing_feed.returncode==0:continue
            obj={'apiVersion':'v1','kind':'ConfigMap','metadata':{'name':name,'namespace':args.namespace},'data':data}
            if binary:obj['binaryData']=binary
            run(k+['apply','-f','-'],json.dumps(obj))
        deployment=json.loads(run(k+['get','deployment','frontdoor','-o','json']))
        spec=deployment['spec']['template']['spec']
        volumes=[v for v in spec.get('volumes',[]) if v['name'] not in ['idobata-site','idobata-feed']]
        volumes += [{'name':name,'configMap':{'name':name}} for name in ['idobata-site','idobata-feed']]
        containers=spec['containers']
        for container in containers:
            mounts=[m for m in container.get('volumeMounts',[]) if m['name'] not in ['idobata-site','idobata-feed']]
            mounts += [{'name':name,'mountPath':'/srv/idobata/'+directory,'readOnly':True}
                       for name,directory in [('idobata-site','site'),('idobata-feed','feed')]]
            container['volumeMounts']=mounts
        # 不変な場合はpatchしない。無関係なcontainer設定は保持する。
        patch=[{'op':'test','path':'/metadata/resourceVersion','value':deployment['metadata']['resourceVersion']},
               {'op':'add','path':'/spec/template/spec/volumes','value':volumes},
               {'op':'replace','path':'/spec/template/spec/containers','value':containers}]
        run(k+['patch','deployment','frontdoor','--type=json','--patch-file=/dev/stdin'],json.dumps(patch))
        proc=subprocess.run(k+['rollout','status','deployment/frontdoor','--timeout=600s'],capture_output=True,text=True,timeout=620)
        if proc.returncode: raise RuntimeError('frontdoor volume配備を確認できません')
    # 現在値を読み直して他サービスの変更を保存する。
    current=json.loads(run(k+['get','configmap',args.configmap,'-o','json']))
    patch=[{'op':'test','path':'/metadata/resourceVersion','value':current['metadata']['resourceVersion']},
           {'op':'replace','path':'/data/nginx.conf','value':replace_block(current['data']['nginx.conf'],fragment)}]
    run(k+['patch','configmap',args.configmap,'--type=json','--patch-file=/dev/stdin'],json.dumps(patch))
    if args.remove:
        print(json.dumps({'status':'removed'}));return
    # 構文確認だけで完了とせず、両公開LBの実応答を待つ。
    deadline=time.monotonic()+200
    while time.monotonic()<deadline:
        try:
            for address in ['34.19.105.162','34.53.30.187']:
                for route in ['/', '/docs/', '/posts.json', '/revision.json']:
                    data=run(['curl','--fail','--silent','--show-error','--max-time','10',
                              '--header','X-Idobata-Diagnostic: 1',
                              '--resolve','idobata.s21g.com:443:'+address,'https://idobata.s21g.com'+route])
                    if route=='/revision.json' and json.loads(data).get('revision')!=digest:
                        raise ValueError('revision反映待ち')
                    if route=='/posts.json':
                        if json.loads(data)['signed']['revision']<json.loads(feed_data['posts.json'])['signed']['revision']:
                            raise ValueError('feed反映待ち')
                        import tempfile
                        with tempfile.NamedTemporaryFile(mode='w',suffix='.json') as public_file:
                            public_file.write(data);public_file.flush()
                            run([args.binary,'public','verify','--feed',public_file.name]+trust_args)
                verify_agent_routes(address, assets)
            # 旧workerの終了上限を過ぎてから旧配信ファイルを除く。
            if any(name in cm['data'] for name in FILES) or 'idobata-icon.png' in cm.get('binaryData',{}):
                for _ in range(13):time.sleep(5)
                clean=json.loads(run(k+['get','configmap',args.configmap,'-o','json']))
                cleanup=[{'op':'test','path':'/metadata/resourceVersion','value':clean['metadata']['resourceVersion']}]
                for name in FILES:
                    if name in clean['data']:cleanup.append({'op':'remove','path':'/data/'+name})
                if 'idobata-icon.png' in clean.get('binaryData',{}):cleanup.append({'op':'remove','path':'/binaryData/idobata-icon.png'})
                run(k+['patch','configmap',args.configmap,'--type=json','--patch-file=/dev/stdin'],json.dumps(cleanup))
            print(json.dumps({'status':'published','revision':digest,'load_balancers':2}),flush=True)
            return
        except (subprocess.SubprocessError,ValueError,KeyError,TypeError): time.sleep(5)
    # 失敗したサイトの設定だけを戻す。他サービスの変更は巻き戻さない。
    current=json.loads(run(k+['get','configmap',args.configmap,'-o','json']))
    rollback=[{'op':'test','path':'/metadata/resourceVersion','value':current['metadata']['resourceVersion']},
              {'op':'replace','path':'/data/nginx.conf','value':replace_block(current['data']['nginx.conf'],old_block)}]
    for name,value in cm['data'].items():
        if name in FILES: rollback.append({'op':'add','path':'/data/'+name,'value':value})
    if 'idobata-icon.png' in cm.get('binaryData',{}):
        rollback.append({'op':'add','path':'/binaryData','value':{**current.get('binaryData',{}),'idobata-icon.png':cm['binaryData']['idobata-icon.png']}})
    run(k+['patch','configmap',args.configmap,'--type=json','--patch-file=/dev/stdin'],json.dumps(rollback))
    raise RuntimeError('公開経路を確認できず、サイト設定を復元しました')


if __name__=='__main__':
    main()
