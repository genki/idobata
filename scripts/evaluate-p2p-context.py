#!/usr/bin/env python3
"""固定した合成断片だけで、受理済みP2P情報の連結検査をshadow評価する。"""
import importlib.util
import json
from pathlib import Path
import tempfile
import time

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('peer_fixture',ROOT/'scripts/verify-peers.py')
fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)


if __name__=='__main__':
    binary='/usr/local/lib/idobata/idobata'
    # 公開済みの固定合成例。実環境の秘密値、未送信draft、拒否入力を収集しない。
    synthetic=fixture.SYNTHETIC;parts=[synthetic[i:i+8] for i in range(0,len(synthetic),8)]
    with tempfile.TemporaryDirectory(prefix='idobata-context-evaluation-') as temporary:
        base=Path(temporary)
        nodes=[fixture.Node({'name':'local-'+str(i),'root':str(base),'binary':binary,'port':39130+i},base,str(i)) for i in range(2)]
        try:
            ids=[]
            for node in nodes:
                ids.append(node.run(['init','--listen',f'/ip4/127.0.0.1/tcp/{node.port}'])['identity']);node.initialized=True
            nodes[0].put(nodes[0].home+'/members.json',json.dumps(ids))
            cert=nodes[0].home+'/invite.json'
            nodes[0].run(['room','create','--room','context','--members-file',nodes[0].home+'/members.json','--output',cert])
            nodes[1].run(['room','join','--room','context','--invite-file',cert,'--trust-authority',ids[0]['peer_id']])
            for node in nodes:node.start()
            individual=[]
            for index,part in enumerate(parts):
                individual.append(nodes[0].run(['scan','--offline','--stdin'],part)['code'])
                r=nodes[0].run(['post','--room','context','--stdin','--timeout-seconds','12'],part)
                assert r['delivered_count']==1
                if index+1<len(parts):time.sleep(6.1)
            inbox=nodes[1].run(['inbox','--room','context','--limit','10'])['messages']
            received=[item['body'] for item in reversed(inbox)]
            assert received==parts
            joined=nodes[1].run(['scan','--offline','--stdin'],''.join(received),codes=(20,))
            report={'version':1,'mode':'shadow evaluation, production policy unchanged','source':'fixed authored synthetic fixture, accepted signed P2P messages only','part_bytes':[len(p) for p in parts],'individual_codes':individual,'received_messages':len(inbox),'joined_code':joined['code'],'window_bounds':{'messages':4,'bytes':32},'dictionary_waiver':False,'result':'per-message scanning can miss split strings; bounded concatenation detects this fixture, not all covert channels'}
            (ROOT/'evidence/p2p-context-evaluation-20261031.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
        finally:
            for node in reversed(nodes):node.stop()
            for node in nodes:node.remove_data()
