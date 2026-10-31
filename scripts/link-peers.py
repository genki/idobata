#!/usr/bin/env python3
"""SSH aliasの既存認証でloopback間を接続。鍵と本文は中継設定へ含めない。"""
import argparse
import subprocess

PEERS = [('mba22','takiuchi@mba22.local',39111),('winvr','winvr',39112),('machinaai','machinaai',39113)]


def run(args,data=None):
    p=subprocess.run(args,input=data,text=True,capture_output=True,timeout=30)
    if p.returncode:raise RuntimeError('SSH経路の設定に失敗しました: '+args[0])
    return p.stdout


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--install',action='store_true')
    args=parser.parse_args()
    if not args.install:raise SystemExit('明示的な --install が必要です')
    user=run(['id','-un']).strip()
    for name,host,port in PEERS:
        command=['/usr/bin/ssh','-N','-o','BatchMode=yes','-o','ExitOnForwardFailure=yes',
            '-o','ServerAliveInterval=15','-o','ServerAliveCountMax=3','-o','ConnectTimeout=15',
            '-L',f'127.0.0.1:{port}:127.0.0.1:{port}']
        for other in [39110,39111,39112,39113]:
            if other!=port:command+=['-R',f'127.0.0.1:{other}:127.0.0.1:{other}']
        command+=[host]
        # 引数は全て固定のaliasとloopback/port。systemdでshellを起動しない。
        unit=f'''[Unit]
Description=idobata loopback peer link {name}
After=network-online.target
Wants=network-online.target
[Service]
User={user}
ExecStart={' '.join(command)}
Restart=always
RestartSec=5
NoNewPrivileges=true
[Install]
WantedBy=multi-user.target
'''
        run(['sudo','-n','tee',f'/etc/systemd/system/idobata-link-{name}.service'],unit)
    run(['sudo','-n','systemctl','daemon-reload'])
    for name,_,_ in PEERS:
        run(['sudo','-n','systemctl','enable','--now',f'idobata-link-{name}.service'])
    print('Configured three persistent loopback links.')
