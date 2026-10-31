#!/usr/bin/env python3
"""root/targets秘密鍵を持たず、期限付きsnapshot/timestampだけを定期更新する。"""
import json
from pathlib import Path
import subprocess
import time

HOME=Path('/var/lib/idobata-release')
STATUS=Path('/run/idobata-release/status.json')


def main():
    p=subprocess.run(['/usr/local/lib/idobata/refresh-tuf',str(HOME/'keys'),str(HOME/'metadata')],
                     capture_output=True,text=True,timeout=30)
    if p.returncode:raise RuntimeError('metadata_refresh_failed')
    result=json.loads(p.stdout)
    k=['kubectl','--kubeconfig',str(HOME/'kubeconfig'),'-n','default']
    data={'tuf-'+name:(HOME/'metadata'/name).read_text() for name in
          ['root.json','1.root.json','targets.json','snapshot.json','timestamp.json']}
    for _ in range(3):
        p=subprocess.run(k+['get','configmap','idobata-feed','-o','json'],capture_output=True,text=True,timeout=30)
        if p.returncode:raise RuntimeError('metadata_read_failed')
        current=json.loads(p.stdout)
        patch=[{'op':'test','path':'/metadata/resourceVersion','value':current['metadata']['resourceVersion']}]
        patch += [{'op':'add','path':'/data/'+name,'value':value} for name,value in data.items()]
        p=subprocess.run(k+['patch','configmap','idobata-feed','--type=json','--patch-file=/dev/stdin'],
                         input=json.dumps(patch),capture_output=True,text=True,timeout=30)
        if p.returncode==0:
            return {'version':1,'status':'published','checked_at':time.time(),
                    'metadata_version':result['version'],'target_count':result['target_count']}
    raise RuntimeError('metadata_publish_failed')


if __name__=='__main__':
    try:status=main()
    except Exception:status={'version':1,'status':'failed','checked_at':time.time(),'reason':'metadata_update_failed'}
    temporary=STATUS.with_suffix('.tmp');temporary.write_text(json.dumps(status)+'\n')
    temporary.chmod(0o640);temporary.replace(STATUS)
    print(json.dumps(status));raise SystemExit(0 if status['status']=='published' else 1)
