"""Opt-in Chromium observation in a networkless, filesystem-confined worker."""
from __future__ import annotations
import base64, html, os, re, shutil, subprocess, tempfile
from pathlib import Path

_MARKER=re.compile(r'<meta[^>]*id="renderdiff-observer"[^>]*data-text="([^"]*)"',re.I)

def observe_html(source, *, runner=None, timeout=12):
    if not isinstance(source,str) or len(source.encode())>1_000_000: raise ValueError('HTML exceeds browser limit')
    if runner is None:
        return {'available':False,'observer':'isolated-chromium','reason':'sandbox-runner-not-configured'}
    result=runner(source,timeout=timeout)
    if not isinstance(result,dict) or not isinstance(result.get('available'),bool): raise TypeError('invalid browser result')
    if result['available'] and (not isinstance(result.get('text'),str) or len(result['text'])>1_000_000): raise ValueError('invalid browser text')
    return result

def bubblewrap_chromium(source, *, timeout=12, executable=None):
    """Run active HTML with no network, isolated namespaces and temporary storage.

    The inner --no-sandbox flag is permitted only inside the outer bwrap sandbox.
    A production deployment must additionally enforce cgroup memory/PID limits.
    """
    bwrap=shutil.which('bwrap')
    exe=executable or shutil.which('google-chrome') or shutil.which('chromium')
    if exe and '/snap/bin/' in exe:
        candidate='/snap/chromium/current/usr/lib/chromium-browser/chrome'
        if Path(candidate).exists(): exe=candidate
    if not bwrap or not exe or os.geteuid()==0:
        return {'available':False,'observer':'isolated-chromium','reason':'sandbox-prerequisite-unavailable'}
    probe='''<script>(function(){function emit(){try{var t=(document.body&&document.body.innerText)||"";var m=document.createElement("meta");m.id="renderdiff-observer";m.setAttribute("data-text",btoa(unescape(encodeURIComponent(t))));document.head.appendChild(m)}catch(e){}};if(document.readyState==="loading")document.addEventListener("DOMContentLoaded",emit,{once:true});else emit()})();</script>'''
    with tempfile.TemporaryDirectory(prefix='renderdiff-browser-') as directory:
        root=Path(directory); (root/'run').mkdir(mode=0o700); (root/'tmp').mkdir(mode=0o700); (root/'evidence.html').write_text(source+probe,encoding='utf-8')
        cmd=[bwrap,'--unshare-all','--new-session','--die-with-parent','--cap-drop','ALL','--clearenv','--setenv','PATH','/usr/bin:/bin','--setenv','LANG','C.UTF-8','--ro-bind','/usr','/usr','--ro-bind-try','/lib','/lib','--ro-bind-try','/lib64','/lib64','--ro-bind-try','/snap','/snap','--tmpfs','/etc','--ro-bind-try','/etc/ssl','/etc/ssl','--ro-bind-try','/etc/fonts','/etc/fonts','--proc','/proc','--dev','/dev','--tmpfs','/tmp','--tmpfs','/home','--bind',directory,'/work','--chdir','/work','--setenv','TMPDIR','/work/tmp','--setenv','HOME','/work','--setenv','XDG_RUNTIME_DIR','/work/run',exe,'--headless','--disable-gpu','--no-sandbox','--disable-extensions','--disable-background-networking','--disable-component-update','--disable-sync','--disable-default-apps','--no-first-run','--disable-dev-shm-usage','--user-data-dir=/work/profile','--virtual-time-budget=1200','--dump-dom','file:///work/evidence.html']
        try:
            def limits():
                import resource
                resource.setrlimit(resource.RLIMIT_CPU,(8,8))
                resource.setrlimit(resource.RLIMIT_FSIZE,(8*1024*1024,8*1024*1024))
            with (root/'stdout.html').open('wb') as output:
                cp=subprocess.run(cmd,stdout=output,stderr=subprocess.DEVNULL,timeout=timeout,preexec_fn=limits,env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'})
            if (root/'stdout.html').stat().st_size>8*1024*1024: raise ValueError('browser output limit exceeded')
            captured=(root/'stdout.html').read_text(encoding='utf-8',errors='replace')
        except (subprocess.TimeoutExpired,OSError) as exc:
            return {'available':False,'observer':'isolated-chromium','reason':type(exc).__name__}
        match=_MARKER.search(captured)
        if not match:
            return {'available':False,'observer':'isolated-chromium','reason':'probe-not-observed','exit_code':cp.returncode}
        try: text=base64.b64decode(html.unescape(match.group(1)),validate=True).decode()
        except (ValueError,UnicodeError): return {'available':False,'observer':'isolated-chromium','reason':'probe-decode-failed'}
        return {'available':True,'observer':'isolated-chromium','text':text,'exit_code':cp.returncode,'network':'disabled','filesystem':'temporary-sandbox'}
