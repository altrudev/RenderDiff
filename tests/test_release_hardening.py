import io, json, os, unittest, zipfile
from unittest.mock import patch
from fastapi.testclient import TestClient
from renderdiff import analyze
from renderdiff.assurance import attach
from renderdiff.bundle import verify_bundle
from renderdiff.receipt import verify, seal, verify_seal
from renderdiff.semantic import observe_semantics
from renderdiff.service import app, _rate_windows, _rate_lock, _slots

TOKEN='release-test-'+'a'*48

class ReleaseHardeningTests(unittest.TestCase):
    def test_authentication_and_rate_limit(self):
        with patch.dict(os.environ,{'RENDERDIFF_API_TOKEN':TOKEN,'RENDERDIFF_RATE_LIMIT':'2'}):
            with _rate_lock: _rate_windows.clear()
            with TestClient(app) as c:
                payload={'text':'hello'}
                self.assertEqual(c.post('/v1/analyze',json=payload).status_code,401)
                self.assertEqual(c.post('/v1/analyze',json=payload,headers={'Authorization':'Bearer wrong'}).status_code,401)
                headers={'Authorization':'Bearer '+TOKEN}
                self.assertEqual(c.post('/v1/analyze',json=payload,headers=headers).status_code,200)
                self.assertEqual(c.post('/v1/analyze',json=payload,headers=headers).status_code,200)
                self.assertEqual(c.post('/v1/analyze',json=payload,headers=headers).status_code,429)
    def test_unconfigured_auth_fails_closed(self):
        with patch.dict(os.environ,{'RENDERDIFF_API_TOKEN':''}):
            with TestClient(app) as c:
                self.assertEqual(c.post('/v1/analyze',json={'text':'x'}).status_code,503)
    def test_job_capacity(self):
        from renderdiff.service import _run_bounded
        from fastapi import HTTPException
        import asyncio
        self.assertTrue(_slots.acquire(False))
        self.assertTrue(_slots.acquire(False))
        try:
            with self.assertRaises(HTTPException) as cm:
                asyncio.run(_run_bounded(lambda: None))
            self.assertEqual(cm.exception.status_code,503)
        finally:
            _slots.release();_slots.release()
    def test_receipt_malformed_and_tampering(self):
        r=attach(analyze('pay\u200bment'))
        self.assertTrue(verify(r))
        for bad in [None,[],{}, {'receipt':{'canonical_json_sha256':[]}}, {'receipt':{'canonical_json_sha256':'0'*64},'x':float('nan')}]:
            self.assertFalse(verify(bad))
        r['summary']['severity']='forged'
        self.assertFalse(verify(r))
    def test_unsigned_seal_not_accepted_as_signature(self):
        r=attach(analyze('hello'));s=seal(r)
        self.assertTrue(verify_seal(r,s))
        self.assertFalse(verify_seal(r,s,public_key=object()))
        self.assertFalse(verify_seal(r,{**s,'algorithm':'Ed25519'}))
    def test_semantic_spans_reject_forgery(self):
        source='payment';visible='payment'
        def claim(evidence):
            return lambda _: {'claims':[{'boundary':'instruction','materiality':'material','evidence':[evidence]}]}
        for item in [
            {'view':'machine','start':0,'end':0},
            {'view':'machine','start':False,'end':3},
            {'view':'machine','start':0,'end':7,'text':'forged'},
            {'view':'machine','start':0,'end':7,'sha256':'0'*64},
        ]:
            with self.assertRaises(ValueError):observe_semantics(source,visible,claim(item),observer_id='fixture')
    def test_bundle_expansion_limit(self):
        buf=io.BytesIO()
        with zipfile.ZipFile(buf,'w',compression=zipfile.ZIP_DEFLATED) as z:
            z.writestr('manifest.json','{}')
            z.writestr('report.json',b'x'*8_000_001)
            z.writestr('evidence.bin',b'x')
        self.assertFalse(verify_bundle(buf.getvalue()))
    def test_security_headers_and_ui(self):
        with TestClient(app) as c:
            r=c.get('/')
            self.assertEqual(r.status_code,200)
            self.assertIn('id="access"',r.text)
            self.assertEqual(r.headers['cache-control'],'no-store')
            self.assertEqual(r.headers['x-frame-options'],'DENY')

if __name__=='__main__':unittest.main()

class NamespaceIsolationTests(unittest.TestCase):
    def test_worker_cannot_access_host_or_network(self):
        import shutil, subprocess, sys, tempfile
        from pathlib import Path
        from renderdiff.runtime import isolated_python
        if sys.platform!='linux' or not shutil.which('bwrap'):
            self.skipTest('Linux bubblewrap unavailable')
        mounts,python,environment=isolated_python()
        script='''import json,os,socket
from pathlib import Path
checks={}
checks['host_private_absent']=not Path('/home/triangulatorium/.ssh').exists()
checks['host_passwd_absent']=not Path('/etc/passwd').exists()
try:
 Path('/usr/renderdiff-forbidden').write_text('x')
 checks['readonly_system']=False
except OSError: checks['readonly_system']=True
try:
 socket.create_connection(('1.1.1.1',53),timeout=1)
 checks['network_denied']=False
except OSError: checks['network_denied']=True
Path('/work/output.json').write_text(json.dumps(checks))
'''
        with tempfile.TemporaryDirectory() as directory:
            cmd=['bwrap','--unshare-all','--new-session','--die-with-parent','--cap-drop','ALL','--clearenv','--setenv','PATH','/usr/bin:/bin','--ro-bind','/usr','/usr','--ro-bind-try','/lib','/lib','--ro-bind-try','/lib64','/lib64','--tmpfs','/etc','--proc','/proc','--dev','/dev','--tmpfs','/tmp','--tmpfs','/home','--bind',directory,'/work']+mounts
            if environment:cmd+=['--setenv','PYTHONHOME',environment['PYTHONHOME']]
            cmd += [python,'-S','-c',script]
            run=subprocess.run(cmd,stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=10)
            self.assertEqual(run.returncode,0,run.stderr)
            checks=json.loads((Path(directory)/'output.json').read_text())
            self.assertTrue(all(checks.values()),checks)
