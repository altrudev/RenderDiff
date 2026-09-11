"""Active DOM/AX observer with a mandatory outer namespace sandbox."""
from __future__ import annotations
import json,os,shutil,site,subprocess,sys,tempfile
from pathlib import Path
from .runtime import isolated_python

def observe_html(source, *, timeout=20, executable=None):
    if not isinstance(source,str) or len(source.encode())>1_000_000:raise ValueError('HTML exceeds limit')
    bwrap=shutil.which('bwrap');exe=executable or '/snap/chromium/current/usr/lib/chromium-browser/chrome'
    if sys.platform!='linux' or not bwrap or not Path(exe).exists() or os.geteuid()==0:
        return {'available':False,'observer':'playwright-isolated-chromium','reason':'sandbox-prerequisite-unavailable'}
    source_root=Path(__file__).resolve().parents[1];runtime_mounts,python,runtime_env=isolated_python()
    with tempfile.TemporaryDirectory(prefix='renderdiff-playwright-') as directory:
        root=Path(directory); (root/'run').mkdir(mode=0o700); (root/'tmp').mkdir(mode=0o700);(root/'evidence.html').write_text(source,encoding='utf-8');(root/'browser-path').write_text(exe)
        cmd=[bwrap,'--unshare-all','--new-session','--die-with-parent','--cap-drop','ALL','--clearenv','--setenv','PATH','/usr/bin:/bin','--setenv','LANG','C.UTF-8','--ro-bind','/usr','/usr','--ro-bind-try','/lib','/lib','--ro-bind-try','/lib64','/lib64','--ro-bind-try','/snap','/snap','--tmpfs','/etc','--ro-bind-try','/etc/ssl','/etc/ssl','--ro-bind-try','/etc/fonts','/etc/fonts','--proc','/proc','--dev','/dev','--tmpfs','/tmp','--tmpfs','/home','--bind',directory,'/work','--ro-bind',str(source_root),'/app/src']
        cmd+=runtime_mounts
        if runtime_env: cmd+=['--setenv','PYTHONHOME',runtime_env['PYTHONHOME']]
        paths=['/app/src']
        for i,path in enumerate(site.getsitepackages()):
            if Path(path).exists():cmd+=['--ro-bind',path,f'/app/site{i}'];paths.append(f'/app/site{i}')
        cmd+=['--chdir','/work','--setenv','TMPDIR','/work/tmp','--setenv','HOME','/work','--setenv','XDG_RUNTIME_DIR','/work/run','--setenv','PYTHONPATH',':'.join(paths),python,'-s','-m','renderdiff.browser_worker']
        def limits():
            import resource
            resource.setrlimit(resource.RLIMIT_CPU,(12,12))
            resource.setrlimit(resource.RLIMIT_FSIZE,(8_000_000,8_000_000))
        try:cp=subprocess.run(cmd,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=timeout,preexec_fn=limits,env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8',**runtime_env})
        except (OSError,subprocess.TimeoutExpired) as exc:return {'available':False,'observer':'playwright-isolated-chromium','reason':type(exc).__name__}
        output=root/'report.json'
        if cp.returncode or not output.exists() or output.stat().st_size>8_000_000:return {'available':False,'observer':'playwright-isolated-chromium','reason':'worker-failed','exit_code':cp.returncode}
        return json.loads(output.read_text(encoding='utf-8'))
