"""Run the full suite against freshly installed wheels, not an editable checkout."""
from __future__ import annotations
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
VERSIONS=('3.10','3.11','3.12','3.13','3.14')

def main():
    uv=shutil.which('uv') or str(ROOT/'.venv/bin/uv')
    if not Path(uv).exists() and not shutil.which('uv'):
        raise RuntimeError('uv is required for the release matrix')
    wheels=sorted((ROOT/'dist').glob('renderdiff-*.whl'))
    if len(wheels)!=1:
        raise RuntimeError('exactly one current release wheel is required')
    wheel=wheels[0]
    wheel_hash=hashlib.sha256(wheel.read_bytes()).hexdigest()
    results=[]
    with tempfile.TemporaryDirectory(prefix='renderdiff-matrix-') as tmp:
        for version in VERSIONS:
            env=Path(tmp)/version
            create=subprocess.run([uv,'venv','--python',version,str(env)],capture_output=True,text=True,timeout=90)
            python=env/'bin/python'
            if create.returncode:
                results.append({'python':version,'state':'BLOCK','phase':'environment','detail':create.stderr[-1000:]})
                continue
            package=str(wheel)+'[api,documents,models,crypto,browser,pdf]'
            install=subprocess.run([uv,'pip','install','--python',str(python),package],capture_output=True,text=True,timeout=180)
            if install.returncode:
                results.append({'python':version,'state':'BLOCK','phase':'install','detail':install.stderr[-1000:]})
                continue
            environment={k:v for k,v in os.environ.items() if k not in {'PYTHONPATH','PYTHONHOME','RENDERDIFF_API_TOKEN'}}
            environment['PYTHONNOUSERSITE']='1'
            run=subprocess.run([str(python),'-m','unittest','discover','-s',str(ROOT/'tests'),'-q'],cwd=tmp,capture_output=True,text=True,timeout=180,env=environment)
            import re
            match=re.search(r'Ran (\d+) tests',run.stderr)
            results.append({'python':version,'state':'PASS' if run.returncode==0 and match else 'BLOCK','phase':'installed-wheel-tests','exit_code':run.returncode,'test_count':int(match.group(1)) if match else None,'summary':run.stderr[-2000:]})
    result={'schema':'renderdiff.python-matrix.v2','wheel_sha256':wheel_hash,'results':results,'status':'PASS' if len(results)==len(VERSIONS) and all(x['state']=='PASS' for x in results) else 'BLOCKED'}
    output=ROOT/'artifacts/release-matrix.json';output.parent.mkdir(exist_ok=True);output.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    print(json.dumps(result,indent=2));return 0 if result['status']=='PASS' else 2
if __name__=='__main__':raise SystemExit(main())
