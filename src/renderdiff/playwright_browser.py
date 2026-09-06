"""Active DOM/AX observer with a mandatory outer namespace sandbox."""
from __future__ import annotations
import json,os,shutil,site,subprocess,sys,tempfile
from pathlib import Path

def observe_html(source, *, timeout=20, executable=None):
    if not isinstance(source,str) or len(source.encode())>1_000_000:raise ValueError('HTML exceeds limit')
    bwrap=shutil.which('bwrap');exe=executable or '/snap/chromium/current/usr/lib/chromium-browser/chrome'
    if sys.platform!='linux' or not bwrap or not Path(exe).exists() or os.geteuid()==0:
        return {'available':False,'observer':'playwright-isolated-chromium','reason':'sandbox-prerequisite-unavailable'}
    source_root=Path(__file__).resolve().parents[1];python=Path(sys.executable).resolve()
    with tempfile.TemporaryDirectory(prefix='renderdiff-playwright-') as directory:
        root=Path(directory);(root/'evidence.html').write_text(source,encoding='utf-8');(root/'browser-path').write_text(exe)
        cmd=[bwrap,'--unshare-all','--new-session','--die-with-parent','--ro-bind','/usr','/usr','--ro-bind-try','/lib','/lib','--ro-bind-try','/lib64','/lib64','--ro-bind-try','/snap','/snap','--ro-bind','/etc','/etc','--proc','/proc','--dev','/dev','--tmpfs','/tmp','--tmpfs','/home','--bind',directory,'/work','--ro-bind',str(source_root),'/app/src']
        paths=['/app/src']
        for i,path in enumerate(site.getsitepackages()):
            if Path(path).exists():cmd+=['--ro-bind',path,f'/app/site{i}'];paths.append(f'/app/site{i}')
        cmd+=['--chdir','/work','--setenv','HOME','/work','--setenv','XDG_RUNTIME_DIR','/tmp','--setenv','PYTHONPATH',':'.join(paths),str(python),'-s','-m','renderdiff.browser_worker']
        def limits():
            import resource
            resource.setrlimit(resource.RLIMIT_CPU,(12,12))
            resource.setrlimit(resource.RLIMIT_FSIZE,(8_000_000,8_000_000))
        try:cp=subprocess.run(cmd,stdin=subprocess.DEVNULL,capture_output=True,timeout=timeout,preexec_fn=limits,env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'})
        except (OSError,subprocess.TimeoutExpired) as exc:return {'available':False,'observer':'playwright-isolated-chromium','reason':type(exc).__name__}
        output=root/'report.json'
        if cp.returncode or not output.exists() or output.stat().st_size>8_000_000:return {'available':False,'observer':'playwright-isolated-chromium','reason':'worker-failed','exit_code':cp.returncode,'stderr_tail':cp.stderr.decode(errors='replace')[-500:]}
        return json.loads(output.read_text(encoding='utf-8'))
