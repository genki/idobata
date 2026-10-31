#!/usr/bin/env python3
"""Opt-in Linux UID isolation check. Changes only a fresh temporary fixture.
Requires existing nobody/daemon users and non-interactive sudo; creates no user.
"""
import argparse,json,os,pathlib,pwd,shutil,signal,subprocess,tempfile,time

def run(argv):
    return subprocess.run(argv,capture_output=True,timeout=20)

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--binary',required=True)
    parser.add_argument('--output',required=True)
    args=parser.parse_args()
    allowed=pwd.getpwnam('nobody');denied=pwd.getpwnam('daemon')
    root=pathlib.Path(tempfile.mkdtemp(prefix='idobata-uid-check-'))
    os.chmod(root,0o755)
    binary=root/'idobata';home=root/'state';runtime=root/'ipc'
    process=None
    try:
        shutil.copy2(args.binary,binary);os.chmod(binary,0o755)
        initialized=run([str(binary),'--home',str(home),'init','--listen','/ip4/127.0.0.1/tcp/0'])
        assert initialized.returncode==0,'fixture initialization failed'
        runtime.mkdir(mode=0o750)
        os.chmod(runtime,0o750)
        assert run(['sudo','-n','chgrp',str(allowed.pw_gid),str(runtime)]).returncode==0,'fixture group setup failed'
        config=json.loads((home/'config.json').read_text())
        endpoint=str(runtime/'ipc.sock')
        config.update(endpoint=endpoint,client_uids=[allowed.pw_uid],socket_group=allowed.pw_gid)
        (home/'config.json').write_text(json.dumps(config))
        with open(root/'daemon.log','wb') as log:
            process=subprocess.Popen(['sudo','-n','setpriv','--reuid',str(os.getuid()),'--regid',str(allowed.pw_gid),'--clear-groups',str(binary),'--home',str(home),'daemon'],stdin=subprocess.DEVNULL,stdout=log,stderr=log)
        deadline=time.monotonic()+15
        while not pathlib.Path(endpoint).exists() and time.monotonic()<deadline:
            assert process.poll() is None,'fixture daemon exited'
            time.sleep(.1)
        positive=run(['sudo','-n','-u','nobody',str(binary),'--socket',endpoint,'info'])
        # The denied process can traverse the same group directory/socket. UID gate
        # must still reject it; this checks more than only filesystem mode bits.
        negative=run(['sudo','-n','setpriv','--reuid',str(denied.pw_uid),'--regid',str(allowed.pw_gid),'--clear-groups',str(binary),'--socket',endpoint,'info'])
        private_key_read=run(['sudo','-n','-u','nobody','test','-r',str(home/'identity.key')])
        assert positive.returncode==0,'configured agent UID was not allowed: '+str(positive.returncode)+' '+positive.stdout.decode('utf-8','replace')[:200]
        assert negative.returncode==40,'another UID in the same group was allowed'
        assert private_key_read.returncode==1,'agent could read the daemon key'
        started=time.monotonic();process.send_signal(signal.SIGINT);process.wait(timeout=15)
        assert process.returncode==0,'daemon shutdown failed'
        result={'status':'passed','authorized_agent_code':positive.returncode,'same_group_other_uid_code':negative.returncode,'agent_can_read_identity_key':False,'sigint_shutdown_seconds':round(time.monotonic()-started,3),'accounts_created':False}
        pathlib.Path(args.output).write_text(json.dumps(result,indent=2)+'\n')
        print(json.dumps(result),flush=True)
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:process.wait(timeout=5)
            except subprocess.TimeoutExpired:process.kill();process.wait()
        shutil.rmtree(root)

if __name__=='__main__':main()
