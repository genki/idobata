#!/usr/bin/env python3
"""事前に固定したメンバーだけへ期限付き招待を更新し、各ノードへ配る。"""
import argparse
import base64
import json
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import time


def run(args,data=None,timeout=90):
    p=subprocess.run(args,input=data,text=True,capture_output=True,timeout=timeout)
    if p.returncode:raise RuntimeError('参加許可の更新に失敗: '+args[0]+' (exit '+str(p.returncode)+')')
    return p.stdout


def windows_join(node,room,certificate,authority):
    if re.fullmatch(r'[a-z0-9_-]{1,32}', room) is None:
        raise ValueError('invalid_room_alias')
    home=node.get('home','C:/ProgramData/idobata').replace('\\','/').rstrip('/')
    binary=node.get('binary','C:/Program Files/idobata/idobata.exe').replace('\\','/')
    if (re.fullmatch(r'[A-Za-z]:/[^\r\n]+',home) is None
            or re.fullmatch(r'[A-Za-z]:/[^\r\n]+',binary) is None
            or any(part in ['', '.', '..'] for part in home[3:].split('/'))
            or any(part in ['', '.', '..'] for part in binary[3:].split('/'))
            or any(ord(character)<32 for character in home+binary)):
        raise ValueError('invalid_windows_home')
    suffix=str(time.time_ns())
    invite=home+'/'+room+'-invite-'+suffix+'.json'
    task='idobata-room-maintenance-'+suffix
    quote=lambda value:"'"+str(value).replace("'","''")+"'"
    arguments=subprocess.list2cmdline(['--home',home,'room','join','--room',room,
                                      '--invite-file',invite,'--trust-authority',authority])
    script=r'''
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';[Console]::OutputEncoding=[Text.UTF8Encoding]::new()
$invite=INVITE
$task=TASK
try {
$acl=[System.Security.AccessControl.FileSecurity]::new()
$acl.SetAccessRuleProtection($true,$false)
foreach($sid in @('S-1-5-19','S-1-5-18','S-1-5-32-544')) {
 $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new([System.Security.Principal.SecurityIdentifier]::new($sid),'FullControl','Allow'))
}
$acl.SetOwner([System.Security.Principal.SecurityIdentifier]::new('S-1-5-19'))
Set-Acl -LiteralPath $invite -AclObject $acl
$action=New-ScheduledTaskAction -Execute BINARY -Argument ARGUMENTS
$principal=New-ScheduledTaskPrincipal -UserId 'S-1-5-19' -LogonType ServiceAccount
Register-ScheduledTask -TaskName $task -Action $action -Principal $principal | Out-Null
Start-ScheduledTask -TaskName $task
Start-Sleep -Milliseconds 500
for($i=0;$i -lt 60;$i++) {
 if ((Get-ScheduledTask -TaskName $task).State -ne 'Running') {break}
 Start-Sleep -Milliseconds 500
}
$state=(Get-ScheduledTask -TaskName $task).State
if ($state -eq 'Running') { throw 'room join timeout' }
$result=(Get-ScheduledTaskInfo -TaskName $task).LastTaskResult
if($result -ne 0){throw ('room join exit '+$result)}
} finally {
 $existing=Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
 if ($existing) {
  if ($existing.State -eq 'Running') { Stop-ScheduledTask -TaskName $task }
  Unregister-ScheduledTask -TaskName $task -Confirm:$false
 }
 if (Test-Path -LiteralPath $invite) { Remove-Item -LiteralPath $invite -Force }
}
'''
    for placeholder,value in [('INVITE',invite),('TASK',task),('BINARY',binary),('ARGUMENTS',arguments)]:
        script=script.replace(placeholder,quote(value))
    encoded=base64.b64encode(script.encode('utf-16le')).decode()
    with tempfile.TemporaryDirectory(prefix='idobata-renew-') as directory:
        local=Path(directory)/'invite.json'
        local.write_text(json.dumps(certificate,ensure_ascii=False),encoding='utf-8')
        local.chmod(0o600)
        try:
            run(['scp','-q','-o','BatchMode=yes','-o','ConnectTimeout=12',str(local),node['ssh']+':'+invite])
            run(['ssh','-o','BatchMode=yes',node['ssh'],'powershell.exe -NoProfile -NonInteractive -EncodedCommand '+encoded])
        finally:
            cleanup=("$ErrorActionPreference='Stop';$task="+quote(task)+
                     ";$existing=Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue;"
                     "if($existing){if($existing.State -eq 'Running'){Stop-ScheduledTask -TaskName $task};"
                     "Unregister-ScheduledTask -TaskName $task -Confirm:$false};"
                     "if(Test-Path -LiteralPath "+quote(invite)+"){Remove-Item -LiteralPath "+quote(invite)+" -Force}")
            cleanup=base64.b64encode(cleanup.encode('utf-16le')).decode()
            run(['ssh','-o','BatchMode=yes',node['ssh'],'powershell.exe -NoProfile -NonInteractive -EncodedCommand '+cleanup])


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
