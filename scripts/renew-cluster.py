#!/usr/bin/env python3
"""事前に固定したメンバーだけへ期限付き招待を更新し、各ノードへ配る。"""
import argparse
import base64
import json
from pathlib import Path
import shlex
import subprocess
import tempfile
import time


def run(args,data=None,timeout=90):
    p=subprocess.run(args,input=data,text=True,capture_output=True,timeout=timeout)
    if p.returncode:raise RuntimeError('参加許可の更新に失敗: '+args[0]+': '+p.stderr[-250:])
    return p.stdout


def windows_join(node,room,certificate,authority):
    text=base64.b64encode(json.dumps(certificate).encode()).decode()
    script=r'''
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';[Console]::OutputEncoding=[Text.UTF8Encoding]::new()
$invite='C:\ProgramData\idobata\INVITE'
[IO.File]::WriteAllBytes($invite,[Convert]::FromBase64String('CERTIFICATE'))
icacls $invite /setowner '*S-1-5-19' /Q | Out-Null
$action=New-ScheduledTaskAction -Execute 'C:\Program Files\idobata\idobata.exe' -Argument '--home C:\ProgramData\idobata room join --room ROOM --invite-file C:\ProgramData\idobata\INVITE --trust-authority AUTHORITY'
$principal=New-ScheduledTaskPrincipal -UserId 'S-1-5-19' -LogonType ServiceAccount
Register-ScheduledTask -TaskName 'idobata-room-maintenance' -Action $action -Principal $principal -Force | Out-Null
Start-ScheduledTask -TaskName 'idobata-room-maintenance'
Start-Sleep -Milliseconds 500
for($i=0;$i -lt 60;$i++) {
 if ((Get-ScheduledTask -TaskName 'idobata-room-maintenance').State -ne 'Running') {break}
 Start-Sleep -Milliseconds 500
}
$result=(Get-ScheduledTaskInfo -TaskName 'idobata-room-maintenance').LastTaskResult
if($result -ne 0){throw ('room join exit '+$result)}
'''
    script=script.replace('INVITE',room+'-invite.json').replace('CERTIFICATE',text).replace('ROOM',room).replace('AUTHORITY',authority)
    encoded=base64.b64encode(script.encode('utf-16le')).decode()
    run(['ssh','-o','BatchMode=yes',node['ssh'],'powershell.exe -NoProfile -NonInteractive -EncodedCommand '+encoded])


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--inventory',required=True)
    parser.add_argument('--force',action='store_true');args=parser.parse_args()
    nodes=json.loads(Path(args.inventory).read_text())
    if len(nodes)<2 or len(nodes)>4 or nodes[0]['platform']!='linux':raise ValueError('固定inventoryが不正です')
    binary='/usr/local/lib/idobata/idobata';home='/var/lib/idobata'
    status=json.loads(run([binary,'--socket','/run/idobata/ipc.sock','info']))
    expiry={r['name']:r['expires_at'] for r in status['rooms']}
    members=[node['identity'] for node in nodes]
    address='/dns4/idobata-peer.s21g.com/tcp/443/wss'
    if address not in members[0]['addresses']:members[0]['addresses'].append(address)
    with tempfile.NamedTemporaryFile(mode='w') as file:
        json.dump(members,file);file.flush()
        run(['sudo','-n','install','-m','600','-o','idobata','-g','idobata',file.name,home+'/members.json'])
    for room,public in [('commons',True),('engineering',False)]:
        if not args.force and expiry.get(room,0)>time.time()+36*3600:continue
        output=home+'/'+room+'-invite-'+str(time.time_ns())+'.json'
        command=['sudo','-n','-u','idobata',binary,'--home',home,'room','create','--room',room,
                 '--members-file',home+'/members.json','--expires-hours','168','--output',output]
        if public:command+=['--public']
        run(command)
        cert=json.loads(run(['sudo','-n','cat',output]))
        for node in nodes[1:]:
            if node['platform']=='windows':windows_join(node,room,cert,members[0]['peer_id']);continue
            target=node['home']+'/'+room+'-invite.json'
            run(['ssh','-o','BatchMode=yes',node['ssh'],'sudo -n -u _idobata tee '+shlex.quote(target)+' >/dev/null'],json.dumps(cert))
            run(['ssh','-o','BatchMode=yes',node['ssh'],'sudo -n chmod 600 '+shlex.quote(target)])
            command=['sudo','-n','-u','_idobata',node['binary'],'--home',node['home'],'room','join',
                     '--room',room,'--invite-file',target,'--trust-authority',members[0]['peer_id']]
            run(['ssh','-o','BatchMode=yes',node['ssh'],shlex.join(command)])
        print(json.dumps({'room':room,'epoch':cert['signed']['epoch'],'expires_at':cert['signed']['expires_at'],'members':len(nodes)}))
    # 公開経路専用probeの既存2鍵だけを更新する。共用roomへ参加させない。
    probe_home='/var/lib/idobata-public-probe'
    if subprocess.run(['sudo','-n','test','-f',probe_home+'/identity.key']).returncode==0 and (args.force or expiry.get('reachability',0)<=time.time()+36*3600):
        output=home+'/reachability-invite-'+str(time.time_ns())+'.json'
        run(['sudo','-n','-u','idobata',binary,'--home',home,'room','create','--room','reachability',
             '--members-file',home+'/reachability-members.json','--expires-hours','168','--output',output])
        run(['sudo','-n','-u','idobata',binary,'--home',probe_home,'room','join','--room','reachability',
             '--invite-file',output,'--trust-authority',members[0]['peer_id']])
        print(json.dumps({'room':'reachability','members':2,'status':'renewed'}))



if __name__=='__main__':main()
