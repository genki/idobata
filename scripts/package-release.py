#!/usr/bin/env python3
"""実機検証済みの三つのバイナリを、実行せず配布archive化する。"""
import argparse
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tomllib
import zipfile

ROOT=Path(__file__).resolve().parents[1]
VERSION=tomllib.loads((ROOT/'Cargo.toml').read_text())['workspace']['package']['version']


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--binaries',required=True)
    parser.add_argument('--output',required=True);args=parser.parse_args()
    source=Path(args.binaries);out=Path(args.output);out.mkdir(exist_ok=True,parents=True)
    summary=[]
    for platform,name in [('linux-x86_64','idobata-linux-x86_64'),('macos-arm64','idobata-macos-arm64'),('windows-x86_64','idobata-windows-x86_64.exe')]:
        raw=(source/name).read_bytes()
        if len(raw)<1000000:raise ValueError('binary appears incomplete')
        files={'idobata.exe' if platform.startswith('windows') else 'idobata':raw,
               'LICENSE':(ROOT/'LICENSE').read_bytes(),
               'README.txt':('idobata '+VERSION+'\nRun idobata --help. Read https://idobata.s21g.com/docs/\nScanner and fixed profile are embedded.\nSource: https://github.com/genki/idobata\n').encode()}
        package='idobata-'+VERSION+'-'+platform
        if platform.startswith('windows'):
            target=out/(package+'.zip')
            with zipfile.ZipFile(target,'w',zipfile.ZIP_DEFLATED) as archive:
                for n,b in files.items():archive.writestr(package+'/'+n,b)
        else:
            target=out/(package+'.tar.gz')
            with tarfile.open(target,'w:gz') as archive:
                for n,b in files.items():
                    info=tarfile.TarInfo(package+'/'+n);info.size=len(b);info.mode=0o755 if n=='idobata' else 0o644;info.mtime=0
                    archive.addfile(info,io.BytesIO(b))
        summary.append({'target':target.name,'platform':platform,'bytes':target.stat().st_size,
                        'sha256':hashlib.sha256(target.read_bytes()).hexdigest(),'binary_sha256':hashlib.sha256(raw).hexdigest()})
    (ROOT/'site/releases.json').write_text(json.dumps({'version':1,'release':VERSION,'targets':summary},indent=2)+'\n')
    print(json.dumps({'status':'packaged','count':len(summary)}))
