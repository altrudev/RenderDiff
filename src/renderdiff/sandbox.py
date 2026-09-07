"""Linux-only, fail-closed extraction isolation for untrusted documents."""
from __future__ import annotations
import json, os, shutil, subprocess, sys, tempfile
from pathlib import Path
from .runtime import isolated_python
from .ingest import MAX_BYTES
from .receipt import verify
from .limits import EvidenceLimitError

MAX_REPORT_BYTES=8_000_000

def extract_document(data, *, filename='evidence.bin', timeout=20):
    if not isinstance(data,bytes) or len(data)>MAX_BYTES: raise ValueError('input size limit exceeded')
    bwrap=shutil.which('bwrap')
    if sys.platform!='linux' or not bwrap or os.geteuid()==0: raise RuntimeError('isolated extraction unavailable')
    import site
    source=Path(__file__).resolve().parents[1]
    runtime_mounts,python,runtime_env=isolated_python()
    sitepaths=[Path(x) for x in site.getsitepackages() if Path(x).exists()]
    with tempfile.TemporaryDirectory(prefix='renderdiff-extract-') as directory:
        root=Path(directory); (root/'tmp').mkdir(mode=0o700); (root/'input').write_bytes(data)
        cmd=[bwrap,'--unshare-all','--new-session','--die-with-parent','--cap-drop','ALL','--clearenv','--setenv','PATH','/usr/bin:/bin','--setenv','LANG','C.UTF-8','--ro-bind','/usr','/usr','--ro-bind-try','/lib','/lib','--ro-bind-try','/lib64','/lib64','--tmpfs','/etc','--ro-bind-try','/etc/ssl','/etc/ssl','--ro-bind-try','/etc/fonts','/etc/fonts','--proc','/proc','--dev','/dev','--tmpfs','/tmp','--tmpfs','/home','--bind',directory,'/work','--ro-bind',str(source),'/app/src']
        cmd+=runtime_mounts
        if runtime_env: cmd+=['--setenv','PYTHONHOME',runtime_env['PYTHONHOME']]
        paths=['/app/src']
        for i,path in enumerate(sitepaths):
            cmd+=['--ro-bind',str(path),f'/app/site{i}'];paths.append(f'/app/site{i}')
        cmd+=['--chdir','/work','--setenv','TMPDIR','/work/tmp','--setenv','HOME','/work','--setenv','PYTHONPATH',':'.join(paths),python,'-s','-m','renderdiff.worker',filename]
        def limits():
            import resource
            resource.setrlimit(resource.RLIMIT_CPU,(12,12))
            resource.setrlimit(resource.RLIMIT_AS,(768*1024*1024,768*1024*1024))
            resource.setrlimit(resource.RLIMIT_FSIZE,(MAX_REPORT_BYTES,MAX_REPORT_BYTES))
        cp=subprocess.run(cmd,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=timeout,preexec_fn=limits,env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8',**runtime_env})
        if cp.returncode:
            error=root/'error.json'
            if error.exists() and error.stat().st_size<=4096:
                detail=json.loads(error.read_text(encoding='utf-8'))
                if detail.get('code')=='resource-limit':
                    raise EvidenceLimitError(detail.get('detail','extraction limit exceeded'))
                if detail.get('code')=='invalid-evidence':
                    raise ValueError('invalid or unsupported document evidence')
            raise RuntimeError('isolated extraction failed')
        output=root/'report.json'
        if not output.exists() or output.stat().st_size>MAX_REPORT_BYTES: raise RuntimeError('extractor output limit exceeded')
        report=json.loads(output.read_text(encoding='utf-8'))
        if not verify(report): raise RuntimeError('extractor receipt verification failed')
        return report
