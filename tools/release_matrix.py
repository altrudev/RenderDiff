"""Run the complete local release suite in isolated supported Python environments."""
import hashlib,json,os,subprocess,sys,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
UV=ROOT/'.venv/bin/uv'
VERSIONS=('3.10','3.11','3.12','3.13','3.14')
def main():
    results=[]
    with tempfile.TemporaryDirectory(prefix='renderdiff-matrix-') as tmp:
        for version in VERSIONS:
            env=Path(tmp)/version
            if version=='3.14':
                python=ROOT/'.venv/bin/python'
            else:
                create=subprocess.run([str(UV),'venv','--python',version,str(env)],capture_output=True,text=True,timeout=90)
                python=env/'bin/python'
                if create.returncode:
                    results.append({'python':version,'state':'BLOCK','phase':'environment','detail':create.stderr[-1000:]});continue
            install=subprocess.run([str(UV),'pip','install','--python',str(python),'--no-deps',str(ROOT)],capture_output=True,text=True,timeout=180)
            if version!='3.14' and install.returncode==0:
                install=subprocess.run([str(UV),'pip','install','--python',str(python),'fastapi>=0.115,<1','uvicorn>=0.30,<1','python-multipart>=0.0.18,<1','pypdf>=6,<7','defusedxml>=0.7.1,<1','tiktoken>=0.8,<1','sentencepiece>=0.2,<1','httpx>=0.27,<1','cryptography>=50,<51','playwright>=1.50,<2','reportlab>=4,<5'],capture_output=True,text=True,timeout=180)
            if install.returncode:
                results.append({'python':version,'state':'BLOCK','phase':'install','detail':install.stderr[-1000:]});continue
            run=subprocess.run([str(python),'-m','unittest','discover','-s','tests','-q'],cwd=ROOT,capture_output=True,text=True,timeout=120,env={**os.environ,'PYTHONPATH':str(ROOT/'src')})
            results.append({'python':version,'state':'PASS' if run.returncode==0 else 'BLOCK','phase':'tests','exit_code':run.returncode,'summary':run.stderr[-1600:]})
    result={'schema':'renderdiff.python-matrix.v1','results':results,'status':'PASS' if len(results)==len(VERSIONS) and all(x['state']=='PASS' for x in results) else 'BLOCKED'}
    output=ROOT/'artifacts/release-matrix.json';output.parent.mkdir(exist_ok=True);output.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    print(json.dumps(result,indent=2));return 0 if result['status']=='PASS' else 2
if __name__=='__main__':raise SystemExit(main())
