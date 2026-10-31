#!/usr/bin/env python3
"""Opt-in real-host verification. Inventory contains SSH aliases, never credentials.
Starts isolated fixture daemons and loopback-only SSH forwards; stops only those
processes in finally. Identity/storage keys are created and kept on each host.
"""
import argparse, base64, hashlib, json, os, pathlib, shlex, signal, subprocess, time
from concurrent.futures import ThreadPoolExecutor

SSH = ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=12']
SYNTHETIC = '9aK7mP2xQ8vR4zT6nJ1bW5sL3cF0hD9u'

def check(ok, label):
    if not ok:
        raise RuntimeError(label)

def ps_quote(s):
    return "'" + str(s).replace("'", "''") + "'"

class Node:
    def __init__(self, config, logs, run_id):
        self.c = config
        self.name = config['name']
        self.host = config.get('ssh')
        self.win = config.get('platform') == 'windows'
        self.root = config['root'].replace('\\', '/')
        self.home = self.root + '/node-' + run_id
        self.initialized = False
        self.binary = config['binary'].replace('\\', '/')
        self.port = config['port']
        self.daemon = None
        self.log = open(logs / (self.name + '.log'), 'ab')
    def shell(self, script, timeout=30):
        if not self.host:
            return subprocess.run(['bash', '-c', script], capture_output=True, timeout=timeout)
        return subprocess.run(SSH + [self.host, script], capture_output=True, timeout=timeout)
    def powershell(self, script, timeout=30):
        prefix = "$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; [Console]::OutputEncoding=[System.Text.UTF8Encoding]::new();\n"
        encoded = base64.b64encode((prefix + script).encode('utf-16le')).decode()
        return self.shell('powershell.exe -NoProfile -NonInteractive -EncodedCommand ' + encoded, timeout)
    def argv(self, args):
        args = [self.binary, '--home', self.home, '--json'] + args
        if not self.host:
            return args
        command = subprocess.list2cmdline(args) if self.win else shlex.join(args)
        return SSH + [self.host, command]
    def run(self, args, data=None, codes=(0,), timeout=30):
        if isinstance(data, str):
            data = data.encode()
        proc = subprocess.run(self.argv(args), input=data, capture_output=True, timeout=timeout)
        check(proc.returncode in codes, f'{self.name}: command {args[0]} exit {proc.returncode}; {proc.stdout[:300]!r}')
        try:
            value = json.loads(proc.stdout.decode('utf-8-sig'))
        except Exception:
            raise RuntimeError(f'{self.name}: invalid JSON output for {args[0]}') from None
        return value
    def put(self, path, contents):
        raw = contents.encode() if isinstance(contents, str) else contents
        if not self.host:
            pathlib.Path(path).write_bytes(raw)
            os.chmod(path, 0o600)
        elif self.win:
            encoded = base64.b64encode(raw).decode()
            result = self.powershell(f"[IO.File]::WriteAllBytes({ps_quote(path)},[Convert]::FromBase64String('{encoded}'))")
            check(result.returncode == 0, self.name + ': write fixture failed')
        else:
            result = subprocess.run(SSH + [self.host, 'umask 077\ncat > ' + shlex.quote(path)], input=raw, capture_output=True, timeout=30)
            check(result.returncode == 0, self.name + ': write fixture failed')
    def start(self):
        check(self.daemon is None or self.daemon.poll() is not None, self.name + ': daemon already active')
        if self.host and not self.win:
            command = 'umask 077\necho $$ > ' + shlex.quote(self.home + '/daemon.pid') + '\nexec ' + shlex.join([self.binary, '--home', self.home, 'daemon'])
            argv = SSH + [self.host, command]
        else:
            argv = self.argv(['daemon'])
        self.daemon = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=self.log, stderr=self.log)
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            if self.daemon.poll() is not None:
                raise RuntimeError(self.name + ': daemon exited at startup; see private log')
            try:
                return self.run(['info'], timeout=15)
            except (RuntimeError, subprocess.TimeoutExpired):
                time.sleep(0.3)
        raise RuntimeError(self.name + ': daemon did not become ready')
    def stop(self):
        if self.daemon is None or self.daemon.poll() is not None:
            return
        if self.win:
            # Only this fixture's executable and exact data-directory are eligible.
            script = f"""$fixtureProcesses=@(Get-CimInstance Win32_Process -Filter \"Name='idobata.exe'\" | Where-Object {{ $_.ExecutablePath.Replace('\\','/') -eq {ps_quote(self.binary)} -and $_.CommandLine.Replace('\\','/').Contains({ps_quote(self.home)}) -and $_.CommandLine.Contains('daemon') }})
if ($fixtureProcesses.Count -gt 1) {{ throw 'ambiguous fixture process' }}
$fixtureProcesses | ForEach-Object {{ Stop-Process -Id $_.ProcessId -Force }}
"""
            result = self.powershell(script)
            check(result.returncode == 0, self.name + ': stop failed')
        elif self.host:
            command = f"python3 - <<'STOP'\nimport os,signal,subprocess\npid=int(open({self.home+'/daemon.pid'!r}).read())\ncommand=subprocess.check_output(['ps','-p',str(pid),'-o','command='],text=True).strip()\nexpected={shlex.join([self.binary,'--home',self.home,'daemon'])!r}\nif command!=expected: raise SystemExit('unexpected fixture process')\nos.kill(pid,signal.SIGINT)\nSTOP"
            result = self.shell(command)
            check(result.returncode == 0, self.name + ': stop failed')
        else:
            self.daemon.send_signal(signal.SIGINT)
        try:
            self.daemon.wait(timeout=12)
        except subprocess.TimeoutExpired:
            if not self.host:
                self.daemon.terminate()
                self.daemon.wait(timeout=5)
            else:
                raise RuntimeError(self.name + ': fixture did not stop') from None
    def remove_data(self):
        if not self.initialized:
            return
        check(self.daemon is None or self.daemon.poll() is not None, self.name + ': cannot remove active fixture')
        if self.win:
            result=self.powershell('Remove-Item -LiteralPath '+ps_quote(self.home)+' -Recurse -Force')
        elif self.host:
            result=self.shell('rm -rf -- '+shlex.quote(self.home))
        else:
            import shutil
            shutil.rmtree(self.home)
            return
        check(result.returncode==0,self.name+': private fixture cleanup failed')
    def encrypted(self, text):
        path = self.home + '/state.enc'
        if self.win:
            script = f"$text=[Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes({ps_quote(path)})); if ($text.Contains({ps_quote(text)})) {{exit 1}}"
            return self.powershell(script).returncode == 0
        if self.host:
            result = self.shell(f"python3 - <<'CHECK'\nfrom pathlib import Path\nb=Path({path!r}).read_bytes()\nraise SystemExit(1 if {text.encode()!r} in b else 0)\nCHECK")
            return result.returncode == 0
        return text.encode() not in pathlib.Path(path).read_bytes()

def all_delivered(node, request_id, timeout=90):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status = node.run(['status', '--message', request_id], codes=(0, 10))
        if status['delivered_count'] == status['recipient_count']:
            return status
        time.sleep(0.4)
    raise RuntimeError(node.name + ': all-peer delivery deadline; status=' + json.dumps(status) + '; info=' + json.dumps(node.run(['info'])))

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--inventory',required=True)
    parser.add_argument('--output',required=True)
    args=parser.parse_args()
    inventory=json.loads(pathlib.Path(args.inventory).read_text())
    output=pathlib.Path(args.output)
    logs=output.parent / 'private-peer-logs'
    logs.mkdir(mode=0o700,parents=True,exist_ok=True)
    run_id=str(time.time_ns())
    nodes=[Node(c,logs,run_id) for c in inventory]
    tunnels=[]
    report={'version':1,'test':'real-peer-e2e','started_at':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'transport':'libp2p TCP / Noise / Yamux over loopback-only SSH forwards','nodes':[n.name for n in nodes],'checks':{}}
    def record(name,value=True):
        report['checks'][name]=value
        print(json.dumps({'check':name,'result':value},ensure_ascii=False),flush=True)
        output.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    try:
        check(3 <= len(nodes) <= 4,'expected three or four real peers')
        identities=[]
        for n in nodes:
            identities.append(n.run(['init','--listen',f'/ip4/127.0.0.1/tcp/{n.port}'])['identity'])
            n.initialized=True
        profiles=[n.run(['profile']) for n in nodes]
        check(all(p==profiles[0] for p in profiles),'different detector artifacts or policy')
        report['policy_id']=profiles[0]['policy_id']
        report['scanner_wasm_sha256']=profiles[0]['profile']['wasm_sha256']
        record('identical_public_policy_and_wasm')
        first=nodes[0]
        members_path=first.home+'/members.json'
        invite_path=first.home+'/invite.json'
        first.put(members_path,json.dumps(identities))
        created=first.run(['room','create','--room','verification','--members-file',members_path,'--output',invite_path])
        authority=created['authority_peer_id']
        if first.host:
            cert=subprocess.run(['scp','-q',first.host+':'+invite_path,str(logs/'invite.json')],capture_output=True,timeout=30)
            check(cert.returncode==0,'invitation retrieval failed')
            invite=(logs/'invite.json').read_bytes()
        else:
            invite=pathlib.Path(invite_path).read_bytes()
        for n in nodes[1:]:
            n.put(n.home+'/invite.json',invite)
            n.run(['room','join','--room','verification','--invite-file',n.home+'/invite.json','--trust-authority',authority])
        record('each_identity_kept_on_its_own_host')
        # There is a distinct authenticated application connection for every pair.
        # The coordinator only forwards ciphertext, using no application peer key.
        for n in nodes:
            if not n.host:
                continue
            forward=SSH+['-N','-o','ControlMaster=no','-o','ControlPath=none','-o','ExitOnForwardFailure=yes','-o','ServerAliveInterval=15']
            forward+=['-L',f'127.0.0.1:{n.port}:127.0.0.1:{n.port}']
            for other in nodes:
                if other is not n:
                    forward+=['-R',f'127.0.0.1:{other.port}:127.0.0.1:{other.port}']
            forward+=[n.host]
            tunnel=subprocess.Popen(forward,stdin=subprocess.DEVNULL,stdout=n.log,stderr=n.log)
            tunnels.append(tunnel)
        time.sleep(1)
        check(all(p.poll() is None for p in tunnels),'SSH forward establishment failed')
        for n in nodes:
            n.start()
        record('all_daemons_ready')
        fixtures=[('plain-ja','作業が完了しました。変更内容を確認してください。'),('plain-ja-varied','予報を長期間収集し、評価結果を比較します。'),('plain-en','The work is ready. Please review the change.'),('token',SYNTHETIC),('padded-token','The work is ready. '+SYNTHETIC+' Please review the change.'),('percent-token',''.join('%%%02x'%b for b in SYNTHETIC.encode())),('html-token',''.join('&#%d;'%ord(c) for c in SYNTHETIC)),('json-escapes',''.join('\\u%04x'%ord(c) for c in SYNTHETIC)),('unicode-control','hello\u202eworld')]
        vectors=[]
        for label,text in fixtures:
            with ThreadPoolExecutor(max_workers=len(nodes)) as executor:
                values=list(executor.map(lambda n:n.run(['scan','--offline','--stdin'],text,codes=(0,20,22)),nodes))
            check(all(v==values[0] for v in values),label+': OS-dependent decision')
            expected=0 if label.startswith('plain-') else 22 if label=='unicode-control' else 20
            check(values[0]['code']==expected,label+': unexpected classification')
            vectors.append({'name':label,'code':expected,'report_sha256':hashlib.sha256(json.dumps(values[0],sort_keys=True,ensure_ascii=False).encode()).hexdigest()})
        record('identical_decisions_across_platforms',vectors)
        messages={}
        for index,n in enumerate(nodes):
            body=['The first node is ready.','The second node is ready.','The third node is ready.','The fourth node is ready.'][index]
            result=n.run(['post','--room','verification','--stdin','--timeout-seconds','15'],body,codes=(0,10))
            messages[n.name]=(result['request_id'],body)
        for n in nodes:
            all_delivered(n,messages[n.name][0])
            received=n.run(['inbox','--room','verification','--limit','20'])
            bodies=[m['body'] for m in received['messages']]
            check(all(body in bodies for other,(request,body) in messages.items() if other!=n.name),n.name+': missing foreign message')
            check(all(m['untrusted'] for m in received['messages']),n.name+': untrusted flag missing')
        record('all_directed_peer_routes',len(nodes)*(len(nodes)-1))
        for n in nodes:
            before=n.run(['info'])
            blocked=n.run(['post','--room','verification','--stdin'],SYNTHETIC,codes=(20,))
            check(blocked['enqueued'] is False,n.name+': blocked data enqueued')
            check(SYNTHETIC not in json.dumps(blocked),n.name+': diagnostic leaked input')
            after=n.run(['info'])
            check(before['outbox_count']==after['outbox_count'] and before['outbound_attempts']==after['outbound_attempts'],n.name+': block caused storage or delivery')
        record('blocked_posts_neither_queued_nor_sent')
        prepared=first.run(['prepare','--room','verification','--stdin','--redact'],'The work is ready. '+SYNTHETIC)
        preview=first.run(['preview','--prepared',prepared['prepared_id']])
        check(SYNTHETIC not in json.dumps(preview),'redaction retained token')
        check('[REDACTED_' in preview['draft']['body'],'redaction marker absent')
        posted=first.run(['post','--room','verification','--prepared',prepared['prepared_id']],codes=(0,10))
        all_delivered(first,posted['request_id'])
        record('redaction_is_explicit_and_post_is_reinspected')
        # Take an actual peer down, persist an incomplete outbox, restart its sender,
        # then restore the peer. No accepted data may disappear or be duplicated.
        offline=next((n for n in nodes if n.win),nodes[-1])
        sender=next(n for n in nodes if n is not offline and n is not first)
        offline.stop()
        body='The offline peer will receive this update.'
        queued=sender.run(['post','--room','verification','--stdin','--wait','accepted'],body)
        sender.stop()
        sender.start()
        status=sender.run(['status','--message',queued['request_id']],codes=(0,10))
        check(status['enqueued'] and status['delivered_count']<status['recipient_count'],'offline fixture unexpectedly complete')
        offline.start()
        all_delivered(sender,queued['request_id'],timeout=90)
        inbox=offline.run(['inbox','--room','verification','--limit','100'])
        check(sum(m['body']==body for m in inbox['messages'])==1,'restart lost or duplicated message')
        count=sender.run(['info'])['outbox_count']
        sender.run(['post','--room','verification','--stdin','--request',queued['request_id']],body)
        check(sender.run(['info'])['outbox_count']==count,'idempotent retry enqueued twice')
        record('offline_delivery_sender_restart_receiver_restart_and_idempotency')
        tampered=json.loads(invite)
        tampered['signed']['epoch']+=1
        offline.put(offline.home+'/tampered-invite.json',json.dumps(tampered))
        offline.run(['room','join','--room','verification','--invite-file',offline.home+'/tampered-invite.json','--trust-authority',authority],codes=(30,))
        check(offline.run(['info'])['rooms'][0]['authorized'],'bad invite replaced existing authorization')
        record('tampered_invite_rejected_without_replacing_trust')
        check(all(n.encrypted(messages[n.name][1]) for n in nodes),'plaintext detected in encrypted store')
        record('validated_messages_encrypted_at_rest')
        report['status']='passed'
    finally:
        errors=[]
        for n in reversed(nodes):
            try:
                n.stop()
            except Exception as error:
                errors.append(n.name+': '+str(error))
        for process in tunnels:
            process.terminate()
            try:
                process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                process.kill(); process.wait()
        if not errors:
            for n in nodes:
                try:
                    n.remove_data()
                except Exception as error:
                    errors.append(n.name+': '+str(error))
        report['cleanup_errors']=errors
        report['private_fixture_keys_removed']=not errors
        report['finished_at']=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())
        output.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
        if errors:
            raise RuntimeError('fixture cleanup incomplete: '+', '.join(errors))
    print(json.dumps({'status':report['status'],'output':str(output)}),flush=True)

if __name__=='__main__':
    main()
