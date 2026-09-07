import io,json,os,sys,tempfile,unittest,zipfile,hashlib
from pathlib import Path
from renderdiff import analyze
from renderdiff.assurance import attach
from renderdiff.bundle import create_bundle,verify_bundle
from renderdiff.ingest import acquire_bytes, acquire_url
from renderdiff.sandbox import extract_document
from renderdiff.playwright_browser import observe_html
from renderdiff.model_probe import compare_model_behaviour
from renderdiff.receipt import verify
from renderdiff.pdf_report import pdf_report
from renderdiff.service import app
from fastapi.testclient import TestClient
from unittest.mock import patch
from pypdf import PdfReader

class IntegrationTests(unittest.TestCase):
    def test_public_api_and_exports(self):
        with patch.dict(os.environ,{'RENDERDIFF_API_TOKEN':'test-only-'+'a'*48}):
            with TestClient(app,headers={'Authorization':'Bearer test-only-'+'a'*48}) as c:
                r=c.post('/v1/analyze',json={'text':'pay\u200bment'});self.assertEqual(r.status_code,200)
                report=r.json();self.assertTrue(verify(report));self.assertEqual(report['views']['assurance']['coverage']['model_input'],'unavailable')
                self.assertFalse(report['views']['assurance']['complete'])
                for fmt in ('html','sarif','pdf'):
                    response=c.post('/v1/export/'+fmt,json=report);self.assertEqual(response.status_code,200)
                    if fmt=='pdf':self.assertTrue(response.content.startswith(b'%PDF-'))
                report['summary']['severity']='forged'
                self.assertEqual(c.post('/v1/export/html',json=report).status_code,400)
                self.assertEqual(c.post('/v1/analyze',json={'text':'x'*64001}).status_code,413)
                self.assertEqual(c.post('/v1/analyze',json={'text':'x','browser':True}).status_code,400)
    def test_upload_limits_and_rejection(self):
        with patch.dict(os.environ,{'RENDERDIFF_API_TOKEN':'test-only-'+'a'*48}):
            with TestClient(app,headers={'Authorization':'Bearer test-only-'+'a'*48}) as c:
                self.assertEqual(c.post('/v1/upload',files={'file':('bad.bin',b'\x00\x01','application/octet-stream')}).status_code,400)
                self.assertEqual(c.post('/v1/upload',files={'file':('big.txt',b'x'*4000001,'text/plain')}).status_code,413)
    def test_bundle_exact_original_bytes(self):
        source=b'hello\xff';r=acquire_bytes(source,filename='x.txt');bundle=create_bundle(r,source)
        self.assertTrue(verify_bundle(bundle))
        with self.assertRaises(ValueError):create_bundle(r,b'hello')
        with zipfile.ZipFile(io.BytesIO(bundle)) as z:
            members={n:z.read(n) for n in z.namelist()}
        members['evidence.bin']=b'forged'
        out=io.BytesIO()
        with zipfile.ZipFile(out,'w') as z:
            for n,data in members.items():z.writestr(n,data)
        self.assertFalse(verify_bundle(out.getvalue()))
    def test_isolated_pdf_extraction(self):
        from reportlab.pdfgen import canvas
        buf=io.BytesIO();c=canvas.Canvas(buf);c.drawString(30,750,'payment');c.save()
        r=extract_document(buf.getvalue(),filename='example.pdf')
        self.assertTrue(verify(r));self.assertIn('payment',r['views']['semantic']['machine_received_text'])
        self.assertEqual(r['views']['source_document']['sha256'],hashlib.sha256(buf.getvalue()).hexdigest())
    def test_isolated_ooxml(self):
        for name,path in [('a.docx','word/document.xml'),('a.xlsx','xl/sharedStrings.xml'),('a.pptx','ppt/slides/slide1.xml')]:
            buf=io.BytesIO()
            with zipfile.ZipFile(buf,'w') as z:z.writestr(path,'<root><t>pay\u200bment</t></root>')
            r=extract_document(buf.getvalue(),filename=name)
            self.assertTrue(verify(r));self.assertIn('invisible-unicode',r['summary']['categories'])
    def test_url_is_explicit_and_bounded(self):
        with self.assertRaises(ValueError):acquire_url('http://127.0.0.1/private')
        with self.assertRaises(ValueError):acquire_url('https://example.test',fetcher=lambda u,n:{'data':b'x'*(n+1)})
        r=acquire_url('https://example.test',fetcher=lambda u,n:{'data':b'hello','content_type':'text/plain'})
        self.assertTrue(verify(r))
    def test_real_browser_networkless(self):
        r=observe_html('<p>Visible</p><p style="display:none">Hidden</p><script>document.body.dataset.executed="yes"</script><canvas width="4" height="5"></canvas>')
        if not r.get('available'):self.skipTest(r.get('reason','browser unavailable'))
        self.assertEqual(r['network'],'disabled');self.assertNotIn('Hidden',r['text'])
        self.assertIn('data-executed="yes"',r['dom']);self.assertTrue(r['accessibility']['available'])
        self.assertEqual(r['canvases'][0]['width'],4)
    def test_model_behaviour_is_advisory(self):
        def model(text):return {'available':True,'metadata':{'response':text.replace('\u200b',''),'model_returned':'fixture'}}
        r=compare_model_behaviour('pay\u200bment','payment',model,observer_id='fixture')
        self.assertTrue(r['responses_equal']);self.assertEqual(r['disposition'],'none')
        r=compare_model_behaviour('A','B',model,observer_id='fixture')
        self.assertEqual(r['disposition'],'context-dependent')
    def test_pdf_receipt_and_escaped_text(self):
        r=attach(analyze('<script>alert(1)</script>'))
        text='\n'.join(p.extract_text() for p in PdfReader(io.BytesIO(pdf_report(r))).pages)
        self.assertIn(r['receipt']['canonical_json_sha256'],text)
        self.assertIn('<script>',text)
    def test_stream_limit_no_partial_clean(self):
        from renderdiff.streaming import analyze_stream
        r=analyze_stream([b'pay',b'\xe2\x80\x8bment']);self.assertTrue(verify(r))
        with self.assertRaises(ValueError):analyze_stream([b'x'*10],max_bytes=9)
    def test_full_browser_unavailable_is_not_clean_certificate(self):
        r=attach(analyze('hello'))
        self.assertEqual(r['views']['assurance']['disposition'],'none')
        self.assertFalse(r['views']['assurance']['complete'])

if __name__=='__main__':unittest.main()
