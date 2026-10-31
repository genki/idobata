#!/usr/bin/env python3
"""本文を取得せず、常設peerの状態と72時間の観測実績を記録する。"""
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import shlex
import subprocess
import time

ROOT = Path('/home/vagrant/.local/state/idobata')


def call(node, args, data=None):
    command=[node['binary'],'--socket',node['endpoint']]+args
    if node.get('ssh'):
        encoded=subprocess.list2cmdline(command) if node['platform']=='windows' else shlex.join(command)
        command=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=10',node['ssh'],encoded]
    p=subprocess.run(command,input=data,capture_output=True,text=True,timeout=18)
    if p.returncode not in [0,10]:raise RuntimeError('node_unavailable')
    return json.loads(p.stdout)


def observe(node):
    at=time.time()
    try:
        result=call(node,['doctor']);info=result['daemon']
        rooms=[{'name':r['name'],'authorized':r['authorized'],'expires_at':r['expires_at'],'epoch':r['epoch']}
               for r in info['rooms']]
        return {'label':node.get('label',node['platform']),'status':'up' if result['status']=='healthy' else 'down',
                'checked_at':at,'version':info['version'],'uptime_seconds':info['uptime_seconds'],
                'policy_id':info['policy_id'],'connected_peers':info['connected_peers'],
                'pending_count':info['pending_count'],'held_count':info['held_count'],
                'delivered_count':info['delivered_count'],'rooms':rooms}
    except (OSError,ValueError,KeyError,subprocess.SubprocessError,RuntimeError):
        return {'label':node.get('label',node['platform']),'status':'down','checked_at':at,'reason':'node_unavailable'}


def save(path,value):
    temporary=path.with_suffix('.tmp');temporary.write_text(json.dumps(value)+'\n')
    temporary.chmod(0o600);temporary.replace(path)


def main():
    ROOT.mkdir(mode=0o700,parents=True,exist_ok=True)
    nodes=json.loads((ROOT/'nodes.json').read_text())
    history=ROOT/'stability.json';previous={}
    if history.exists():
        previous=json.loads(history.read_text())
    start=previous.get('started_at',time.time());samples=previous.get('samples',0)
    restarts=previous.get('service_restarts',{});old_uptimes=previous.get('uptimes',{})
    failed_samples=previous.get('failed_samples',0);last=previous.get('checked_at',time.time())
    max_gap=previous.get('max_observation_gap_seconds',0);canary=previous.get('canary',{})
    while True:
        now=time.time();max_gap=max(max_gap,now-last);last=now
        # inventoryの変更は管理者による次回service起動時に読み込む。
        with ThreadPoolExecutor(max_workers=4) as pool:
            observations=list(pool.map(observe,nodes))
        samples+=1
        if any(n['status']!='up' for n in observations):failed_samples+=1
        for i,node in enumerate(observations):
            if 'uptime_seconds' not in node:continue
            key=str(i)
            if key in old_uptimes and node['uptime_seconds']<old_uptimes[key]:restarts[key]=restarts.get(key,0)+1
            old_uptimes[key]=node['uptime_seconds']
        # 非公開roomの定型canaryで、全宛先の受領を時間を分けて確認する。
        try:
            if not canary or now-canary.get('created_at',0)>3600:
                message={'kind':'observation','title':'定期疎通確認','body':'常設ノード間の配送を定期確認しています。','references':[]}
                result=call(nodes[0],['post','--room','engineering','--stdin','--input','json','--wait','accepted'],json.dumps(message,ensure_ascii=False))
                canary={'request_id':result['request_id'],'created_at':now,'complete':False}
            result=call(nodes[0],['status','--message',canary['request_id']])
            canary.update(complete=result['delivered_count']==result['recipient_count'],
                          delivered_count=result['delivered_count'],recipient_count=result['recipient_count'])
            if canary['complete']:canary['last_success']=now
        except (OSError,ValueError,KeyError,subprocess.SubprocessError,RuntimeError):
            canary['check_failed']=True
        elapsed=now-start
        stability={'version':1,'started_at':start,'checked_at':now,'elapsed_seconds':elapsed,
                   'required_seconds':72*3600,'samples':samples,'failed_samples':failed_samples,
                   'service_restarts':restarts,'uptimes':old_uptimes,'max_observation_gap_seconds':max_gap,
                   'canary':canary,'time_window_complete':elapsed>=72*3600,
                   'os_reboot_test':'not_yet_observed','sleep_test':'not_yet_observed'}
        status={'version':1,'checked_at':now,'nodes':observations,'canary':{k:v for k,v in canary.items() if k!='request_id'},
                'stability':{k:v for k,v in stability.items() if k not in ['uptimes','canary']}}
        save(history,stability);save(ROOT/'cluster-status.json',status)
        time.sleep(30)


if __name__=='__main__':main()
