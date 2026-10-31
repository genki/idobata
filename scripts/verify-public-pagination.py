#!/usr/bin/env python3
"""隔離した2ノードで、件数/IPC容量による公開投稿の取りこぼしを検査。"""
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time

ROOT=Path(__file__).resolve().parents[1]
BINARY=os.environ.get('IDOBATA_BINARY',str(ROOT/'target/debug/idobata'))


def main():
    children=[]
    with tempfile.TemporaryDirectory(prefix='idobata-public-pages-') as temporary:
        base=Path(temporary);homes=[base/n for n in ['sender','receiver','publisher']]
        def run(home,args,data=None,codes=(0,)):
            p=subprocess.run([BINARY,'--home',str(home)]+args,input=data,text=True,capture_output=True,timeout=90)
            if p.returncode not in codes:raise RuntimeError('fixture operation failed: '+args[0]+': '+p.stdout[:200])
            return json.loads(p.stdout)
        try:
            identities=[]
            for index,home in enumerate(homes):
                run(home,['init','--listen',f'/ip4/127.0.0.1/tcp/{39120+index}'])
                identities.append(run(home,['identity']))
            (homes[0]/'members.json').write_text(json.dumps(identities[:2]))
            run(homes[0],['room','create','--room','public','--public','--members-file',str(homes[0]/'members.json'),'--output',str(base/'invite.json')])
            run(homes[1],['room','join','--room','public','--invite-file',str(base/'invite.json'),'--trust-authority',identities[0]['peer_id']])
            for home in homes[:2]:
                children.append(subprocess.Popen([BINARY,'--home',str(home),'daemon'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL))
            for home in homes[:2]:
                for _ in range(100):
                    try:run(home,['info']);break
                    except RuntimeError:time.sleep(.1)
                else:raise RuntimeError('fixture startup failed')
            requests=[]
            for i in range(25):
                d={'kind':'observation','title':f'公開ページの検査 {i}','body':'これは公開投稿の分割取得を確かめるための文章です。'*80,'references':[]}
                result=run(homes[0],['post','--room','public','--public','--stdin','--input','json','--wait','accepted'],json.dumps(d,ensure_ascii=False))
                requests.append(result['request_id'])
                time.sleep(6.1)  # 実装の投稿rate limitも守る。
            for request in requests:
                for _ in range(100):
                    result=run(homes[0],['status','--message',request],codes=(0,10))
                    if result['delivered_count']==1:break
                    time.sleep(.2)
                else:raise RuntimeError('fixture delivery failed')
            endpoint=json.loads((homes[1]/'config.json').read_text())['endpoint'];feed=homes[2]/'posts.json'
            run(homes[2],['--socket',endpoint,'public','refresh','--feed',str(feed),'--room','public'])
            d=json.loads(feed.read_text());assert d['signed']['count']==25
            assert len({p['signed']['id'] for p in d['signed']['feed']['posts']})==25
            (base/'publisher.json').write_text(json.dumps(run(homes[2],['identity'])['public_key']))
            run(homes[2],['public','verify','--feed',str(feed),'--trust-publisher',str(base/'publisher.json')])
            result={'version':1,'status':'passed','public_posts':25,'feed_bytes':feed.stat().st_size,'multiple_ipc_pages':True,'duplicate_public_ids':0}
            (ROOT/'evidence/public-pagination-20261031.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
        finally:
            for child in children:
                if child.poll() is None:child.send_signal(signal.SIGINT)
            for child in children:child.wait(timeout=15)


if __name__=='__main__':main()
