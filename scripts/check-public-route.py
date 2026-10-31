#!/usr/bin/env python3
"""他の接続先を持たないprobeから公開WSS経路の署名付き受領を確認。"""
import json
from pathlib import Path
import subprocess
import time

START=time.monotonic()
command=['/usr/local/lib/idobata/idobata','--home','/var/lib/idobata-public-probe',
         'post','--room','reachability','--stdin','--timeout-seconds','45']
try:
    p=subprocess.run(command,input='公開経路を通る定期的な配送の確認です。',text=True,
                     capture_output=True,timeout=60)
    result=json.loads(p.stdout)
    ok=p.returncode==0 and result['delivered_count']==1 and result['recipient_count']==1
except (OSError,ValueError,KeyError,subprocess.SubprocessError):ok=False
status={'version':1,'reachable':ok,'checked_at':time.time(),
        'elapsed_seconds':round(time.monotonic()-START,3),'route':'public-wss-no-tcp-fallback',
        'signed_receipts':1 if ok else 0}
path=Path('/run/idobata/public-route.json');temporary=path.with_suffix('.tmp')
temporary.write_text(json.dumps(status)+'\n');temporary.chmod(0o640);temporary.replace(path)
print(json.dumps(status));raise SystemExit(0 if ok else 1)
