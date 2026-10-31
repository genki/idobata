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


class RenewalCommandError(RuntimeError):
    """Keep diagnostic streams privately, without embedding commands/certificates."""
    def __init__(self,tool,returncode,stdout,stderr):
        super().__init__('参加許可の更新に失敗: '+tool+' (exit '+str(returncode)+')')
        self.returncode=returncode
        self.stdout_bytes=stdout
        self.stderr_bytes=stderr
        for encoding in ('utf-8','cp932'):
            try:
                self.stderr=stderr.decode(encoding)
                break
            except UnicodeDecodeError:
                pass
        else:
            self.stderr=stderr.decode('utf-8',errors='replace')


def run(args,data=None,timeout=90):
    # Windows PowerShell can emit CP932 CLIXML progress on stderr even at exit 0.
    # Decode the UTF-8 stdout protocol only; harmless stderr cannot fail success.
    payload=data.encode('utf-8') if isinstance(data,str) else data
    p=subprocess.run(args,input=payload,capture_output=True,timeout=timeout)
    if p.returncode:
        raise RenewalCommandError(args[0],p.returncode,p.stdout,p.stderr)
    return p.stdout.decode('utf-8')


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
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';$OutputEncoding=[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$invite=INVITE
$task=TASK
$primary=$null
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
} catch {
 $primary=$_
 throw
} finally {
 try {
 $existing=Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
 if ($existing) {
  if ($existing.State -eq 'Running') { Stop-ScheduledTask -TaskName $task }
  Unregister-ScheduledTask -TaskName $task -Confirm:$false
 }
 if (Test-Path -LiteralPath $invite) { Remove-Item -LiteralPath $invite -Force }
 } catch {
  if($null -eq $primary){throw}
  [Console]::Error.WriteLine('cleanup_failed_after_primary')
 }
}
# A missing task is normal during idempotent cleanup. PowerShell may otherwise
# propagate its suppressed Get-ScheduledTask failure via $? at script EOF.
exit 0
'''
    for placeholder,value in [('INVITE',invite),('TASK',task),('BINARY',binary),('ARGUMENTS',arguments)]:
        script=script.replace(placeholder,quote(value))
    encoded=base64.b64encode(script.encode('utf-16le')).decode()
    with tempfile.TemporaryDirectory(prefix='idobata-renew-') as directory:
        local=Path(directory)/'invite.json'
        local.write_text(json.dumps(certificate,ensure_ascii=False),encoding='utf-8')
        local.chmod(0o600)
        primary=None
        try:
            run(['scp','-q','-o','BatchMode=yes','-o','ConnectTimeout=12',str(local),node['ssh']+':'+invite])
            run(['ssh','-o','BatchMode=yes',node['ssh'],'powershell.exe -NoProfile -NonInteractive -EncodedCommand '+encoded])
        except BaseException as error:
            primary=error
            raise
        finally:
            cleanup=("$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';"
                     "$OutputEncoding=[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);$task="+quote(task)+
                     ";$existing=Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue;"
                     "if($existing){if($existing.State -eq 'Running'){Stop-ScheduledTask -TaskName $task};"
                     "Unregister-ScheduledTask -TaskName $task -Confirm:$false};"
                     "if(Test-Path -LiteralPath "+quote(invite)+"){Remove-Item -LiteralPath "+quote(invite)+" -Force};exit 0")
            cleanup=base64.b64encode(cleanup.encode('utf-16le')).decode()
            try:
                run(['ssh','-o','BatchMode=yes',node['ssh'],'powershell.exe -NoProfile -NonInteractive -EncodedCommand '+cleanup])
            except BaseException as error:
                if primary is None:
                    raise
                # The failed operation is the cause; cleanup must not replace it.
                primary.cleanup_error=error
                if hasattr(primary,'add_note'):
                    primary.add_note('Windows renewal cleanup also failed; inspect cleanup_error')


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
