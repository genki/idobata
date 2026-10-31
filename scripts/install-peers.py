#!/usr/bin/env python3
"""既存ホストへ専用アカウントのノードだけを導入する。秘密鍵は各ホストで生成。"""
import argparse
import base64
import json
import hashlib
from pathlib import Path
import plistlib
import shlex
import subprocess

ROOT = Path(__file__).resolve().parents[1]
SSH = ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=15']


def run(argv, data=None, timeout=90):
    p = subprocess.run(argv, input=data, text=True, capture_output=True, timeout=timeout)
    if p.returncode:
        raise RuntimeError('ノード導入に失敗: ' + argv[0] + ': ' + p.stderr[-500:])
    return p.stdout


def mac(host, port):
    home = '/Library/Application Support/idobata'
    binary = '/usr/local/lib/idobata/idobata'
    endpoint = '/Library/Caches/idobata-runtime/ipc.sock'
    run(SSH + [host, '''set -eu
if ! id -u _idobata >/dev/null 2>&1; then
  idobata_uid=450
  while dscl . -list /Users UniqueID | awk '{print $2}' | /usr/bin/grep -qx "$idobata_uid"; do idobata_uid=$((idobata_uid+1)); done
  sudo -n dscl . -create /Users/_idobata
  sudo -n dscl . -create /Users/_idobata UniqueID "$idobata_uid"
  sudo -n dscl . -create /Users/_idobata PrimaryGroupID 20
  sudo -n dscl . -create /Users/_idobata UserShell /usr/bin/false
  sudo -n dscl . -create /Users/_idobata NFSHomeDirectory /var/empty
  sudo -n dscl . -create /Users/_idobata IsHidden 1
fi
sudo -n mkdir -p /usr/local/lib/idobata '/Library/Application Support/idobata' /Library/Caches/idobata-runtime /var/log/idobata
sudo -n chown _idobata:staff '/Library/Application Support/idobata' /Library/Caches/idobata-runtime /var/log/idobata
sudo -n chmod 700 '/Library/Application Support/idobata' /var/log/idobata
sudo -n chmod 750 /Library/Caches/idobata-runtime
sudo -n install -m 755 /private/tmp/idobata-20261031-v1/target/release/idobata /usr/local/lib/idobata/idobata.new
sudo -n mv /usr/local/lib/idobata/idobata.new /usr/local/lib/idobata/idobata
'''])
    uid = int(run(SSH + [host, 'id -u']).strip())
    configure = f'''
import json,subprocess,os
home={home!r};binary={binary!r}
if not os.path.exists(home+'/identity.key'):
 subprocess.check_call([binary,'--home',home,'init','--listen','/ip4/127.0.0.1/tcp/{port}'],stdout=subprocess.DEVNULL)
p=home+'/config.json';c=json.load(open(p));c.update(endpoint={endpoint!r},client_uids=[{uid}],socket_group=20)
with open(p,'w') as f:json.dump(c,f)
os.chmod(p,0o600)
'''
    encoded = base64.b64encode(configure.encode()).decode()
    run(SSH + [host, "sudo -n -u _idobata python3 -c " + shlex.quote("import base64;exec(base64.b64decode('" + encoded + "'))")])
    plist = {'Label': 'com.s21g.idobata', 'UserName': '_idobata', 'GroupName': 'staff',
             'ProgramArguments': [binary, '--home', home, 'daemon'], 'RunAtLoad': True,
             'KeepAlive': True, 'ThrottleInterval': 5,
             'StandardOutPath': '/var/log/idobata/stdout.log', 'StandardErrorPath': '/var/log/idobata/stderr.log'}
    run(SSH + [host, 'sudo -n tee /Library/LaunchDaemons/com.s21g.idobata.plist >/dev/null'], plistlib.dumps(plist).decode())
    run(SSH + [host, 'sudo -n chown root:wheel /Library/LaunchDaemons/com.s21g.idobata.plist\nsudo -n chmod 644 /Library/LaunchDaemons/com.s21g.idobata.plist\nif sudo -n launchctl print system/com.s21g.idobata >/dev/null 2>&1; then\n  sudo -n launchctl kickstart -k system/com.s21g.idobata\nelse\n  idobata_loaded=false\n  for idobata_try in 1 2 3 4 5 6 7 8 9 10; do\n    if sudo -n launchctl bootstrap system /Library/LaunchDaemons/com.s21g.idobata.plist 2>/dev/null; then idobata_loaded=true; break; fi\n    sleep 1\n  done\n  $idobata_loaded\nfi'])
    member = json.loads(run(SSH + [host, shlex.join(['sudo','-n','-u','_idobata',binary,'--home',home,'identity'])]))
    return {'ssh': host, 'platform': 'macos', 'home': home, 'binary': binary, 'endpoint': endpoint, 'port': port, 'identity': member}


def linux(binary_source,expected_sha256):
    source=Path(binary_source)
    if not expected_sha256 or hashlib.sha256(source.read_bytes()).hexdigest()!=expected_sha256:
        raise ValueError("Linux binary checksum mismatch; wait for a complete verified transfer")
    version=run([str(source.resolve()),"--version"]).strip()
    if version != "idobata 0.2.0": raise ValueError("Unexpected binary version")
    home = '/var/lib/idobata'
    binary = '/usr/local/lib/idobata/idobata'
    endpoint = '/run/idobata/ipc.sock'
    uid = int(run(['id','-u']).strip()); group = run(['id','-gn']).strip(); gid = int(run(['id','-g']).strip())
    subprocess.run(['sudo','-n','useradd','--system','--user-group','--home-dir',home,'--shell','/usr/sbin/nologin','idobata'],capture_output=True)
    run(['sudo','-n','install','-d','-m','755','/usr/local/lib/idobata'])
    run(['sudo','-n','install','-m','755',str(source.resolve()),binary+'.new'])
    installed=run(['sudo','-n','sha256sum',binary+'.new']).split()[0]
    if installed!=expected_sha256:raise ValueError('Staged binary checksum mismatch')
    run(['sudo','-n','mv',binary+'.new',binary])
    run(['sudo','-n','install','-d','-m','700','-o','idobata','-g','idobata',home])
    if subprocess.run(['sudo','-n','test','-f',home+'/identity.key']).returncode:
        run(['sudo','-n','-u','idobata',binary,'--home',home,'init','--listen','/ip4/127.0.0.1/tcp/39110','--listen','/ip4/127.0.0.1/tcp/39114/ws'])
    configure = "import json,os;p='/var/lib/idobata/config.json';c=json.load(open(p));c.update(endpoint='/run/idobata/ipc.sock',client_uids=["+str(uid)+"],socket_group="+str(gid)+");f=open(p,'w');json.dump(c,f);f.close();os.chmod(p,0o600)"
    run(['sudo','-n','-u','idobata','python3','-c',configure])
    service = f'''[Unit]
Description=idobata authenticated P2P node
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=idobata
Group={group}
RuntimeDirectory=idobata
RuntimeDirectoryMode=0750
ExecStart={binary} --home {home} daemon
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths={home} /run/idobata
LimitCORE=0
UMask=0077
[Install]
WantedBy=multi-user.target
'''
    run(['sudo','-n','tee','/etc/systemd/system/idobata.service'],service)
    run(['sudo','-n','systemctl','daemon-reload']);run(['sudo','-n','systemctl','enable','--now','idobata.service'])
    run(['sudo','-n','systemctl','restart','idobata.service'])
    member=json.loads(run(['sudo','-n','-u','idobata',binary,'--home',home,'identity']))
    return {'platform':'linux','home':home,'binary':binary,'endpoint':endpoint,'port':39110,'identity':member}


def windows():
    script=r'''
$ErrorActionPreference='Stop';[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new()
$bin='C:\Program Files\idobata\idobata.exe';$homeDir='C:\ProgramData\idobata'
$old=Get-ScheduledTask -TaskName 'idobata-node' -ErrorAction SilentlyContinue
if ($old) {Stop-ScheduledTask -TaskName 'idobata-node';Start-Sleep -Seconds 2}
New-Item -ItemType Directory -Force 'C:\Program Files\idobata',$homeDir | Out-Null
Copy-Item 'C:\Users\genta\AppData\Local\Temp\idobata-20261031-v1\target\release\idobata.exe' $bin -Force

$currentSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
function Set-IdobataAcl([string]$directory,[string]$sid) {
 $items=@(Get-Item $directory)+@(Get-ChildItem $directory -Force -Recurse)
 foreach($item in $items) {
  $security=if($item.PSIsContainer){New-Object Security.AccessControl.DirectorySecurity}else{New-Object Security.AccessControl.FileSecurity}
  $security.SetSecurityDescriptorSddlForm(('O:BAG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;'+$sid+')'))
  Set-Acl -LiteralPath $item.FullName -AclObject $security
 }
}
icacls $homeDir /setowner '*S-1-5-32-544' /T /Q | Out-Null
Set-IdobataAcl $homeDir $currentSid
if (-not (Test-Path ($homeDir+'\identity.key'))) {& $bin --home $homeDir init --listen /ip4/127.0.0.1/tcp/39112 | Out-Null;if($LASTEXITCODE){throw 'init failed'}}
$c=Get-Content ($homeDir+'\config.json') -Raw | ConvertFrom-Json
$c.client_sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$endpoint=$c.endpoint
[IO.File]::WriteAllText(($homeDir+'\config.json'),($c|ConvertTo-Json -Depth 30 -Compress),[Text.UTF8Encoding]::new($false))
# 所有者変更前に公開identityだけを取得する。
$identity=& $bin --home $homeDir identity | ConvertFrom-Json
if($LASTEXITCODE){throw 'identity failed'}
Set-IdobataAcl $homeDir 'S-1-5-19'
icacls $homeDir /setowner '*S-1-5-19' /T /Q | Out-Null
$action=New-ScheduledTaskAction -Execute $bin -Argument ('--home "'+$homeDir+'" daemon')
$trigger=New-ScheduledTaskTrigger -AtStartup
$principal=New-ScheduledTaskPrincipal -UserId 'S-1-5-19' -LogonType ServiceAccount
$settings=New-ScheduledTaskSettingsSet -StartWhenAvailable -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName 'idobata-node' -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName 'idobata-node'
@{ssh='winvr';platform='windows';home=$homeDir;binary=$bin;endpoint=$endpoint;port=39112;identity=$identity}|ConvertTo-Json -Depth 20 -Compress
'''
    encoded=base64.b64encode(script.encode('utf-16le')).decode()
    return json.loads(run(SSH+['winvr','powershell.exe -NoProfile -NonInteractive -EncodedCommand '+encoded]))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary');parser.add_argument('--sha256')
    parser.add_argument('--install',action='store_true')
    parser.add_argument('--output',required=True)
    parser.add_argument('--host',choices=['linux','mba22','winvr','machinaai'],required=True)
    args=parser.parse_args()
    if not args.install:raise SystemExit('明示的な --install が必要です')
    if args.host=='linux' and (not args.binary or not args.sha256):parser.error('Linux requires --binary and --sha256')
    node=linux(args.binary,args.sha256) if args.host=='linux' else windows() if args.host=='winvr' else mac('machinaai' if args.host=='machinaai' else 'takiuchi@mba22.local',39113 if args.host=='machinaai' else 39111)
    path=Path(args.output);path.write_text(json.dumps(node,ensure_ascii=False,indent=2)+'\n');path.chmod(0o600)
    print(json.dumps({'status':'installed','node':args.host,'account_isolation':True}))
