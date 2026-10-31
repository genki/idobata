#!/usr/bin/env python3
"""本文を取得せず、常設peerの状態と72時間の観測実績を記録する。"""
from concurrent.futures import ThreadPoolExecutor
import argparse
import json
from pathlib import Path
import re
import shlex
import subprocess
import time

ROOT = Path('/home/vagrant/.local/state/idobata')
MAX_SAFE_INTEGER = 9_007_199_254_740_991
KNOWLEDGE_QUOTA_BYTES = 64 * 1024 * 1024


def summarize_knowledge(value):
    """明示した集計値以外を監視へ渡さない。本文・識別子は取得しない。"""
    if not isinstance(value, dict) or not isinstance(value.get('storage'), dict):
        return {'status': 'unavailable', 'reason': 'knowledge_metrics_missing'}
    storage = value['storage']
    required = ['bytes', 'quota_bytes', 'objects', 'reviews', 'max_objects']
    counts = ['staging_records', 'pending_replications', 'replication_factor']
    optional = ['pending_repairs', 'pending_inventory_pages', 'pending_automation']
    for source, names in [(storage, required), (value, counts),
                          (value, [name for name in optional if name in value])]:
        if any(type(source.get(name)) is not int
               or not 0 <= source[name] <= MAX_SAFE_INTEGER for name in names):
            return {'status': 'invalid', 'reason': 'knowledge_metrics_invalid'}
    result = {'status': 'healthy', 'storage': {name: storage[name] for name in required}}
    result.update({name: value[name] for name in counts})
    result.update({name: value.get(name) for name in optional})
    if not 0 < storage['quota_bytes'] <= KNOWLEDGE_QUOTA_BYTES:
        result.update(status='invalid', reason='knowledge_quota_invalid')
    elif storage['bytes'] > storage['quota_bytes']:
        result.update(status='invalid', reason='knowledge_quota_exceeded')
    elif (not 0 < storage['max_objects'] <= 8192
          or storage['objects'] > storage['max_objects']
          or value['staging_records'] > storage['objects']
          or storage['reviews'] > storage['objects'] * 32
          or value['replication_factor'] != 3):
        result.update(status='invalid', reason='knowledge_metrics_inconsistent')
    return result


def history_path(root, series):
    if series not in ['v02', 'v03']:
        raise ValueError('unsupported_observation_series')
    return root / ('stability.json' if series == 'v02' else 'stability-v03.json')


def load_history(root, series, now):
    path = history_path(root, series)
    if not path.exists():
        return {}
    previous = json.loads(path.read_text())
    if (not isinstance(previous, dict)
            or previous.get('series', 'v02') != series
            or previous.get('version') not in ([1, 2] if series == 'v02' else [2])):
        raise ValueError('observation_series_mismatch')
    started = previous.get('started_at')
    checked = previous.get('checked_at')
    if (type(started) not in [int, float] or type(checked) not in [int, float]
            or not 0 <= started <= checked <= now + 60
            or type(previous.get('samples')) is not int or previous['samples'] < 0):
        raise ValueError('invalid_observation_history')
    return previous


def automation_rooms_healthy(observation, required_rooms):
    rooms = {room['name']: room for room in observation.get('rooms', [])}
    return all(name in rooms and rooms[name].get('knowledge_automation_required') is True
               for name in required_rooms)


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
        rooms=[{'name':r['name'],'authorized':r['authorized'],'expires_at':r['expires_at'],'epoch':r['epoch'],
                'knowledge_automation_required': r.get('knowledge_automation_required')
                    if type(r.get('knowledge_automation_required')) is bool else None}
               for r in info['rooms']]
        return {'label':node.get('label',node['platform']),'status':'up' if result['status']=='healthy' else 'down',
                'checked_at':at,'version':info['version'],'uptime_seconds':info['uptime_seconds'],
                'policy_id':info['policy_id'],'connected_peers':info['connected_peers'],
                'pending_count':info['pending_count'],'held_count':info['held_count'],
                'delivered_count':info['delivered_count'],'rooms':rooms,
                'knowledge':summarize_knowledge(info.get('knowledge'))}
    except (OSError,ValueError,KeyError,subprocess.SubprocessError,RuntimeError):
        return {'label':node.get('label',node['platform']),'status':'down','checked_at':at,'reason':'node_unavailable'}


def save(path,value):
    temporary=path.with_suffix('.tmp');temporary.write_text(json.dumps(value)+'\n')
    temporary.chmod(0o600);temporary.replace(path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--series', choices=['v02', 'v03'], default='v02',
                        help='v03は旧stability.jsonを保持して別の観測窓を開始する')
    parser.add_argument('--require-automation-room', action='append', default=[],
                        help='指定roomの必須flagを監視する。認可設定自体は変更しない')
    args = parser.parse_args()
    if any(re.fullmatch(r'[a-z0-9_-]{1,32}', name) is None
           for name in args.require_automation_room):
        parser.error('invalid room alias')
    ROOT.mkdir(mode=0o700,parents=True,exist_ok=True)
    nodes=json.loads((ROOT/'nodes.json').read_text())
    history=history_path(ROOT, args.series)
    previous=load_history(ROOT, args.series, time.time())
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
        unhealthy = any(n['status']!='up' for n in observations)
        if args.series == 'v03':
            unhealthy = unhealthy or any(
                n.get('knowledge', {}).get('status') != 'healthy'
                or not automation_rooms_healthy(n, args.require_automation_room)
                for n in observations)
        if unhealthy:failed_samples+=1
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
                          delivered_count=result['delivered_count'],recipient_count=result['recipient_count'],
                          check_failed=False)
            if canary['complete']:canary['last_success']=now
        except (OSError,ValueError,KeyError,subprocess.SubprocessError,RuntimeError):
            canary['check_failed']=True
        elapsed=now-start
        stability={'version':2,'series':args.series,'started_at':start,'checked_at':now,'elapsed_seconds':elapsed,
                   'required_seconds':72*3600,'samples':samples,'failed_samples':failed_samples,
                   'service_restarts':restarts,'uptimes':old_uptimes,'max_observation_gap_seconds':max_gap,
                   'canary':canary,'time_window_complete':elapsed>=72*3600,
                   'os_reboot_test':'not_yet_observed','sleep_test':'not_yet_observed'}
        status={'version':2,'series':args.series,'checked_at':now,'nodes':observations,
                'required_automation_rooms':sorted(set(args.require_automation_room)),
                'canary':{k:v for k,v in canary.items() if k!='request_id'},
                'stability':{k:v for k,v in stability.items() if k not in ['uptimes','canary']}}
        save(history,stability);save(ROOT/'cluster-status.json',status)
        time.sleep(30)


if __name__=='__main__':main()
