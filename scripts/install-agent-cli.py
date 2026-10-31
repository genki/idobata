#!/usr/bin/env python3
"""稼働中daemonを維持したまま、通常agent用のnative CLI導線を設置する。"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
INVENTORY = Path('/home/vagrant/.local/state/idobata/nodes.json')


def run(args, data=None, timeout=120):
    result = subprocess.run(args, input=data, text=True, capture_output=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError('agent CLI installation operation failed: ' + args[0])
    return result.stdout


# 既存のprofileを表示せずに保存し、所有するPATHブロックだけを更新する。
UNIX_REMOTE = r'''
import hashlib,json,os,pathlib,shutil,subprocess,sys,tempfile
payload=json.load(sys.stdin)
source=payload['source']
assert hashlib.sha256(source.encode()).hexdigest()==payload['source_sha256']
def run(args):
 p=subprocess.run(args,capture_output=True,text=True,timeout=90)
 if p.returncode:raise RuntimeError('native CLI setup failed: '+args[0])
 return p.stdout
compiler=shutil.which('rustc')
if not compiler:
 for candidate in [pathlib.Path.home()/'.cargo/bin/rustc',pathlib.Path('/opt/homebrew/bin/rustc')]:
  if candidate.is_file():compiler=str(candidate);break
if not compiler:raise RuntimeError('rustc unavailable')
with tempfile.TemporaryDirectory(prefix='idobata-agent-cli-') as temporary:
 directory=pathlib.Path(temporary);src=directory/'agent-cli.rs';binary=directory/'idobata'
 src.write_text(source)
 run([compiler,'--edition=2024','-C','opt-level=s','-C','strip=symbols','-D','warnings',str(src),'-o',str(binary)])
 target=pathlib.Path('/usr/local/bin/idobata')
 if target.exists() or target.is_symlink():
  if target.is_symlink() or not target.is_file():raise RuntimeError('existing CLI entry is not managed')
  data=target.read_bytes()
  if b'idobata: native client could not start' not in data:raise RuntimeError('existing CLI entry is not managed')
 run(['sudo','-n','install','-m','755',str(binary),str(target)+'.new'])
 expected=hashlib.sha256(binary.read_bytes()).hexdigest()
 assert hashlib.sha256(pathlib.Path(str(target)+'.new').read_bytes()).hexdigest()==expected
 run(['sudo','-n','chown','root:wheel',str(target)+'.new'])
 run(['sudo','-n','mv',str(target)+'.new',str(target)])
home=pathlib.Path.home()
backup=home/'.local/state/idobata-agent-cli/profile-backups'
backup.mkdir(parents=True,exist_ok=True,mode=0o700);backup.chmod(0o700)
begin='# BEGIN IDOBATA AGENT CLI PATH'
end='# END IDOBATA AGENT CLI PATH'
block=begin+'\ncase ":$PATH:" in\n  *:/usr/local/bin:*) ;;\n  *) export PATH="/usr/local/bin:$PATH" ;;\nesac\n'+end+'\n'
login=next((p for p in ['.bash_profile','.bash_login','.profile'] if (home/p).exists()),'.bash_profile')
changed=[]
for name,prepend,shell in [('.bashrc',True,'/bin/bash'),(login,False,'/bin/bash'),('.zshenv',False,'/bin/zsh')]:
 path=home/name
 if path.is_symlink():raise RuntimeError('profile symlink requires explicit handling')
 old=path.read_bytes() if path.exists() else b''
 text=old.decode()
 if text.count(begin)!=text.count(end) or text.count(begin)>1:raise RuntimeError('profile marker conflict')
 if begin in text:
  a=text.index(begin);b=text.index(end,a)+len(end)
  if b<len(text) and text[b]=='\n':b+=1
  text=text[:a]+text[b:]
 new=(block+text) if prepend else (text+('' if not text or text.endswith('\n') else '\n')+block)
 if new.encode()==old:continue
 if old:
  saved=backup/(name+'.'+hashlib.sha256(old).hexdigest()[:16]+'.bak')
  if not saved.exists():saved.write_bytes(old);saved.chmod(0o600)
 with tempfile.NamedTemporaryFile(mode='w',dir=home,prefix='.idobata-profile-',delete=False) as file:
  file.write(new);temporary=pathlib.Path(file.name)
 try:
  run([shell,'-n',str(temporary)])
  assert (path.read_bytes() if path.exists() else b'')==old,'profile changed concurrently'
  temporary.chmod((path.stat().st_mode&0o777) if path.exists() else 0o600)
  temporary.replace(path)
 finally:
  temporary.unlink(missing_ok=True)
 changed.append(name)
print(json.dumps({'status':'installed','cli':'/usr/local/bin/idobata','profile_updates':changed,'daemon_restarted':False}))
'''


def install_unix(node, source):
    label = node['label']
    if node['platform'] == 'linux':
        with tempfile.TemporaryDirectory(prefix='idobata-agent-cli-') as temporary:
            binary = Path(temporary)/'idobata'
            run(['rustc','--edition=2024','-C','opt-level=s','-C','strip=symbols','-D','warnings',
                 str(ROOT/'tools/agent-cli.rs'),'-o',str(binary)])
            target = Path('/usr/local/bin/idobata')
            if target.exists() or target.is_symlink():
                if target.is_symlink() or b'idobata: native client could not start' not in target.read_bytes():
                    raise RuntimeError('existing CLI entry is not managed')
            run(['sudo','-n','install','-m','755',str(binary),str(target)+'.new'])
            if hashlib.sha256(Path(str(target)+'.new').read_bytes()).digest()!=hashlib.sha256(binary.read_bytes()).digest():
                raise RuntimeError('CLI transfer checksum mismatch')
            run(['sudo','-n','mv',str(target)+'.new',str(target)])
        return {'host':label,'status':'installed','cli':str(target),'daemon_restarted':False}
    payload={'source':source,'source_sha256':hashlib.sha256(source.encode()).hexdigest()}
    result=run(['ssh','-o','BatchMode=yes',node['ssh'],'python3 -c '+shlex.quote(UNIX_REMOTE)],json.dumps(payload))
    return {'host':label,**json.loads(result)}


def install_windows(node, source):
    import base64
    # 内容は公開されたRust sourceとIPCアドレスだけ。秘密鍵・tokenを渡さない。
    remote_source='C:/Users/genta/AppData/Local/Temp/idobata-agent-cli-source.rs'
    run(['scp','-q',str(ROOT/'tools/agent-cli.rs'),node['ssh']+':'+remote_source])
    values={'SOURCE':remote_source,
            'ENDPOINT':base64.b64encode(node['endpoint'].encode()).decode()}
    script=r'''
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';[Console]::OutputEncoding=[Text.UTF8Encoding]::new()
$root='C:\Program Files\idobata';$bin=Join-Path $root 'bin';$target=Join-Path $bin 'idobata.exe'
$compiler='C:\Program Files\Rust stable LLVM 1.96\bin\rustc.exe'
$temporary=Join-Path ([IO.Path]::GetTempPath()) ('idobata-agent-cli-'+[Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temporary | Out-Null
try {
 $source=Join-Path $temporary 'agent-cli.rs';$built=Join-Path $temporary 'idobata.exe'
 Copy-Item -LiteralPath 'SOURCE' -Destination $source
 & $compiler --edition=2024 -C opt-level=s -C strip=symbols -D warnings $source -o $built
 if($LASTEXITCODE){throw 'native CLI build failed'}
 New-Item -ItemType Directory -Force $bin | Out-Null
 if(Test-Path $target) {
  $text=[Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes($target))
  if(-not $text.Contains('idobata: native client could not start')){throw 'existing CLI entry is not managed'}
 }
 $staged=Join-Path $bin 'idobata.new.exe';Copy-Item $built $staged -Force
 if((Get-FileHash $built -Algorithm SHA256).Hash -ne (Get-FileHash $staged -Algorithm SHA256).Hash){throw 'CLI checksum mismatch'}
 Move-Item $staged $target -Force
 [IO.File]::WriteAllBytes((Join-Path $root 'agent.socket'),[Convert]::FromBase64String('ENDPOINT'))
 # Program Filesの既存保護を保持。Usersにはlauncherと公開IPCアドレスの読取・実行だけを許可。
 icacls $bin /grant '*S-1-5-32-545:(OI)(CI)(RX)' /T /Q | Out-Null
 if($LASTEXITCODE){throw 'CLI permissions failed'}
 icacls (Join-Path $root 'agent.socket') /grant '*S-1-5-32-545:(R)' /Q | Out-Null
 if($LASTEXITCODE){throw 'endpoint permissions failed'}
 $path=[Environment]::GetEnvironmentVariable('Path','Machine')
 if(-not (($path -split ';').TrimEnd('\') -contains $bin.TrimEnd('\'))) {
  $separator=if($path.EndsWith(';') -or $path.Length -eq 0){''}else{';'}
  [Environment]::SetEnvironmentVariable('Path',($path+$separator+$bin),'Machine')
 }
 @{status='installed';cli=$target;machine_path_configured=$true;daemon_restarted=$false}|ConvertTo-Json -Compress
} finally {Remove-Item -LiteralPath $temporary -Recurse -Force}
'''
    for key,value in values.items():script=script.replace(key,value)
    encoded=base64.b64encode(script.encode('utf-16le')).decode()
    result=run(['ssh','-o','BatchMode=yes',node['ssh'],'powershell.exe -NoProfile -NonInteractive -EncodedCommand '+encoded])
    return {'host':node['label'],**json.loads(result)}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host',choices=['all','linux','mba22','winvr','machinaai'],default='all')
    parser.add_argument('--install',action='store_true');args=parser.parse_args()
    if not args.install:parser.error('--install is required')
    nodes=json.loads(INVENTORY.read_text());source=(ROOT/'tools/agent-cli.rs').read_text()
    selected=[n for n in nodes if args.host=='all' or n['label']==args.host]
    if not selected:raise RuntimeError('approved host missing')
    def install(node):
        return install_windows(node,source) if node['platform']=='windows' else install_unix(node,source)
    with ThreadPoolExecutor(max_workers=4) as pool:
        for result in pool.map(install,selected):print(json.dumps(result))
