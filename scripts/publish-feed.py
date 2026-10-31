#!/usr/bin/env python3
"""限定した公開受信とidobata-feedだけを更新する常駐運用のoneshot。"""
import json
from pathlib import Path
import subprocess
import time

HOME = Path('/var/lib/idobata-publisher')
BINARY = '/usr/local/lib/idobata/idobata'
STATUS = Path('/run/idobata/publisher-status.json')


def run(args):
    p = subprocess.run(args, capture_output=True, text=True, timeout=90)
    if p.returncode:
        raise RuntimeError('publication_operation_failed')
    return p.stdout


def main():
    feed = HOME/'posts.json'
    run([BINARY, '--home', str(HOME), '--socket', '/run/idobata/ipc.sock', 'public', 'refresh',
         '--feed', str(feed), '--room', 'commons', '--ttl-seconds', '600'])
    trust_args=['--trust-publisher',str(HOME/'publisher.json')]
    if (HOME/'trust-root.json').exists():trust_args=['--trust-publisher',str(HOME/'trust-root.json'),'--trust-bundle',str(HOME/'trust.json')]
    run([BINARY,'public','verify','--feed',str(feed),'--checkpoint',str(HOME/'checkpoint.json')]+trust_args)
    doc = json.loads(feed.read_text())
    revision = doc['signed']['revision']
    route={}
    try:route=json.loads(Path('/run/idobata/public-route.json').read_text())
    except (OSError,ValueError):pass
    reachable=route.get('reachable') is True and 0<=time.time()-route.get('checked_at',0)<=600
    if reachable:
        run([BINARY,'--home',str(HOME),'bootstrap','create','--node-home','/var/lib/idobata',
             '--output',str(HOME/'bootstrap.json'),'--revision',str(revision)])
    k = ['kubectl', '--kubeconfig', str(HOME/'kubeconfig'), '-n', 'default']
    current = json.loads(run(k+['get', 'configmap', 'idobata-feed', '-o', 'json']))
    previous = json.loads(current['data']['posts.json'])
    if previous['signed']['revision'] >= revision:
        raise RuntimeError('publication_revision_conflict')
    patch = [
        {'op': 'test', 'path': '/metadata/resourceVersion', 'value': current['metadata']['resourceVersion']},
        {'op': 'replace', 'path': '/data/posts.json', 'value': feed.read_text()},
    ]
    if reachable:patch.append({'op':'add','path':'/data/bootstrap.json','value':(HOME/'bootstrap.json').read_text()})
    elif 'bootstrap.json' in current['data']:patch.append({'op':'remove','path':'/data/bootstrap.json'})
    p = subprocess.run(k+['patch', 'configmap', 'idobata-feed', '--type=json', '--patch-file=/dev/stdin'],
                       input=json.dumps(patch), text=True, capture_output=True, timeout=30)
    if p.returncode:
        raise RuntimeError('publication_update_failed')
    return {'version': 1, 'status': 'published', 'checked_at': time.time(), 'last_success': time.time(),
            'revision':revision,'count':doc['signed']['count'],'expires_at':doc['signed']['expires_at'],'bootstrap_active':reachable}


if __name__ == '__main__':
    try:
        status = main()
    except Exception:
        last = {}
        if STATUS.exists():
            try: last = json.loads(STATUS.read_text())
            except (OSError, ValueError): pass
        status = {'version': 1, 'status': 'failed', 'checked_at': time.time(),
                  'last_success': last.get('last_success'), 'reason': 'publication_failed'}
    temporary = STATUS.with_suffix('.tmp')
    temporary.write_text(json.dumps(status)+'\n')
    temporary.chmod(0o640)
    temporary.replace(STATUS)
    print(json.dumps({'status': status['status'], 'revision': status.get('revision')}))
    raise SystemExit(0 if status['status'] == 'published' else 1)
