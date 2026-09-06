"""Linux-only, fail-closed extraction isolation for untrusted documents."""
from __future__ import annotations
import json, os, shutil, subprocess, sys, tempfile
from pathlib import Path
from .ingest import MAX_BYTES
from .receipt import verify

MAX_REPORT_BYTES=8_000_000

def extract_document(data, *, filename='evidence.bin', timeout=20):
    if not isinstance(data,bytes) or len(data)>MAX_BYTES: raise ValueError('input size limit exceeded')
    bwrap=shutil.which('bwrap')
    if sys.platform!='linux' or not bwrap or os.geteuid()==0: raise RuntimeError('isolated extraction unavailable')
    import site
    source=Path(__file__).resolve().parents[1]
    python=Path(sys.executable).resolve()
    sitepaths=[Path(x) for x in site.getsitepackages() if Path(x).exists()]
    with tempfile.TemporaryDirectory(prefix='renderdiff-extract-') as directory:
        root=Path(directory); (root/'input').write_bytes(data)
        cmd=[bwrap,'--unshare-all','--new-session','--die-with-parent','--ro-bind','/usr','/usr','--ro-bind-try','/lib','/lib','--ro-bind-try','/lib64','/lib64','--ro-bind','/etc','/etc','--proc','/proc','--dev','/dev','--tmpfs','/tmp','--tmpfs','/home','--bind',directory,'/work','--ro-bind',str(source),'/app/src']
        paths=['/app/src']
        for i,path in enumerate(sitepaths):
            cmd+=['--ro-bind',str(path),f'/app/site{i}'];paths.append(f'/app/site{i}')
        cmd+=['--chdir','/work','--setenv','HOME','/work','--setenv','PYTHONPATH',':'.join(paths),str(python),'-s','-m','renderdiff.worker',filename]
        def limits():
            import resource
            resource.setrlimit(resource.RLIMIT_CPU,(12,12))
            resource.setrlimit(resource.RLIMIT_AS,(768*1024*1024,768*1024*1024))
            resource.setrlimit(resource.RLIMIT_FSIZE,(MAX_REPORT_BYTES,MAX_REPORT_BYTES))
        cp=subprocess.run(cmd,stdin=subprocess.DEVNULL,capture_output=True,timeout=timeout,preexec_fn=limits,env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'})
        if cp.returncode: raise RuntimeError('isolated extraction failed; inspect local worker diagnostics')
        output=root/'report.json'
        if not output.exists() or output.stat().st_size>MAX_REPORT_BYTES: raise RuntimeError('extractor output limit exceeded')
        report=json.loads(output.read_text(encoding='utf-8'))
        if not verify(report): raise RuntimeError('extractor receipt verification failed')
        return report
