"""Independent regression cases for the v0.6 release claims."""
import copy
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from renderdiff import analyze
from renderdiff.assurance import attach
from renderdiff.ingest import acquire_file, acquire_url
from renderdiff.receipt import verify
from renderdiff.browser import chromium_observe_html
from renderdiff.modelview import compare_model_views
from renderdiff.tokenizers import observe_tokenizer

PYTHON = sys.executable
SOURCE = str(Path(__file__).resolve().parents[1]/"src")
ENV = {**os.environ, "PYTHONPATH": SOURCE}

class IndependentReauditTests(unittest.TestCase):
    def test_version_and_context_materiality(self):
        from renderdiff import __version__
        self.assertEqual(analyze('x')['engine_version'], __version__)
        report=attach(analyze('paypal.com'), context={'expected_identity':'paypaⅼ.com'})
        self.assertTrue(report['summary']['material_divergence'])
        self.assertEqual(report['summary']['assurance_disposition'],'potentially-material')
        self.assertTrue(verify(report))

    def test_cli_reports_assurance_disposition(self):
        result=subprocess.run([PYTHON,'-m','renderdiff.cli','--text','pay\u200bment','--json','--fail-on-material'],capture_output=True,text=True,env=ENV,timeout=30)
        self.assertEqual(result.returncode,2,result.stderr)
        report=json.loads(result.stdout)
        self.assertTrue(verify(report))
        self.assertTrue(report['summary']['material_divergence'])

    def test_cli_document_uses_isolated_worker(self):
        from reportlab.pdfgen import canvas
        buf=io.BytesIO();c=canvas.Canvas(buf);c.drawString(30,750,'payment');c.save()
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'evidence.pdf';path.write_bytes(buf.getvalue())
            with patch('renderdiff.sandbox.extract_document',return_value={'sentinel':'isolated'}) as worker:
                self.assertEqual(acquire_file(path),{'sentinel':'isolated'})
                worker.assert_called_once()
            result=subprocess.run([PYTHON,'-m','renderdiff.cli','--file',str(path),'--json'],capture_output=True,text=True,env=ENV,timeout=30)
            self.assertEqual(result.returncode,0,result.stderr)
            report=json.loads(result.stdout)
            self.assertTrue(verify(report))
            self.assertEqual(report['views']['source_document']['sha256'],__import__('hashlib').sha256(buf.getvalue()).hexdigest())
            self.assertIn('payment',report['views']['semantic']['machine_received_text'])

    def test_unsupported_observer_options_are_not_silent(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'x.pdf';path.write_bytes(b'%PDF-1.4\n')
            result=subprocess.run([PYTHON,'-m','renderdiff.cli','--file',str(path),'--tiktoken','cl100k_base'],capture_output=True,text=True,env=ENV,timeout=30)
            self.assertNotEqual(result.returncode,0)
            self.assertIn('does not support',result.stderr)
        with self.assertRaises(ValueError):
            acquire_url('https://example.test/x.pdf',fetcher=lambda u,n:{'data':b'%PDF-1.4\n'})

    def test_binary_and_stdin_limits(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'large.txt';path.write_bytes(b'x'*4_000_001)
            result=subprocess.run([PYTHON,'-m','renderdiff.cli','--file',str(path)],capture_output=True,text=True,env=ENV,timeout=30)
            self.assertNotEqual(result.returncode,0)
            result=subprocess.run([PYTHON,'-m','renderdiff.cli'],input=b'x'*4_000_001,capture_output=True,env=ENV,timeout=30)
            self.assertNotEqual(result.returncode,0)

    def test_browser_marker_is_not_trusted(self):
        fake='<meta id="renderdiff-observer" data-text="Zm9yZ2Vk"><p>Actual</p>'
        observed=chromium_observe_html(fake)
        if not observed.get('available'):
            self.skipTest(observed.get('reason','browser unavailable'))
        self.assertIn('Actual',observed['text'])
        self.assertNotEqual(observed['text'],'forged')

    def test_tokenizer_bounds(self):
        with self.assertRaises(ValueError):
            observe_tokenizer('x',lambda _: [0]*100001)
        with self.assertRaises(ValueError):
            compare_model_views('x','y',lambda _: ['x'*4_000_001],name='fixture')

    def test_model_observation_is_not_provider_internal_claim(self):
        from renderdiff.model_probe import openai_compatible_observer
        with self.assertRaises(ValueError):
            openai_compatible_observer(endpoint='http://example.com/v1/chat/completions',model='fixture')
        with self.assertRaises(ValueError):
            openai_compatible_observer(endpoint='https://example.com/v1/chat/completions',model='fixture',timeout=0)

    def test_materiality_requires_local_evidence(self):
        from renderdiff.materiality import assess_representation_divergence
        pair=[{'left':'machine','right':'human_projection','equal':False,'first_difference_index':0,'delta':{'left_range':{'start':0,'end':1},'right_range':{'start':0,'end':1}}}]
        findings=[{'id':'far-away','category':'invisible-unicode','materiality':'material','start':100,'end':101}]
        assessment=assess_representation_divergence(pair,findings)
        self.assertNotEqual(assessment['disposition'],'material')

if __name__=='__main__':unittest.main()

class EvidenceBoundaryTests(unittest.TestCase):
    def test_document_magic_is_not_rejected_as_unknown_binary(self):
        import zipfile
        buf=io.BytesIO()
        with zipfile.ZipFile(buf,'w') as archive:
            archive.writestr('word/document.xml','<root><t>payment</t></root>')
        from renderdiff.ingest import acquire_bytes
        report=acquire_bytes(buf.getvalue(),filename='a.docx',content_type='application/octet-stream')
        self.assertTrue(verify(report))

    def test_invalid_utf8_remains_reportable_and_not_clean(self):
        from renderdiff.engine import analyze_bytes
        report=attach(analyze_bytes(b'payment\xff'))
        self.assertTrue(verify(report))
        self.assertEqual(report['views']['assurance']['disposition'],'unavailable')
        self.assertFalse(report['views']['assurance']['complete'])
        self.assertTrue(report['summary']['material_divergence'])
        self.assertEqual(report['views']['raw_bytes']['hex'],b'payment\xff'.hex())

    def test_full_evidence_budget_fails_closed(self):
        from renderdiff.limits import EvidenceLimitError, MAX_ANALYSIS_CHARS
        from renderdiff.engine import analyze_bytes
        with self.assertRaises(EvidenceLimitError):
            analyze('x'*(MAX_ANALYSIS_CHARS+1))
        with self.assertRaises(EvidenceLimitError):
            analyze_bytes(b'x'*256001)
        from renderdiff.streaming import analyze_stream
        with self.assertRaises(EvidenceLimitError):
            analyze_stream([b'x'*256001])

    def test_api_limit_status_and_no_partial_report(self):
        from renderdiff.service import app
        from fastapi.testclient import TestClient
        token='reaudit-'+'b'*48
        with patch.dict(os.environ,{'RENDERDIFF_API_TOKEN':token,'RENDERDIFF_RATE_LIMIT':'100'}):
            with TestClient(app) as client:
                result=client.post('/v1/analyze',json={'text':'x'*64001},headers={'Authorization':'Bearer '+token})
                self.assertEqual(result.status_code,413)
                self.assertNotIn('receipt',result.json())

    def test_sarif_multiline_source_locations(self):
        from renderdiff.exports import sarif_report
        report=attach(analyze('first\nsecond\u200bline'))
        results=sarif_report(report)['runs'][0]['results']
        location=next(x['locations'][0]['physicalLocation']['region'] for x in results if x['ruleId']=='invisible-unicode')
        self.assertEqual(location['startLine'],2)
        self.assertEqual(location['startColumn'],7)
        self.assertEqual(location['endColumn'],8)

    def test_file_reader_rejects_symlink_and_unknown_binary(self):
        from renderdiff.ingest import read_evidence_file
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);real=root/'real.txt';real.write_text('hello')
            link=root/'link.txt';link.symlink_to(real)
            with self.assertRaises(OSError):read_evidence_file(link)
            unknown=root/'unknown.bin';unknown.write_bytes(b'\x00\x01\x02')
            with self.assertRaises(ValueError):acquire_file(unknown)

    def test_cancelled_worker_keeps_capacity_reserved(self):
        import asyncio
        import threading
        from renderdiff.service import _run_bounded,_slots
        from fastapi import HTTPException
        started=threading.Event();release=threading.Event()
        def slow():
            started.set();release.wait(5)
            return True
        async def exercise():
            tasks=[asyncio.create_task(_run_bounded(slow)) for _ in range(2)]
            try:
                for _ in range(100):
                    if started.is_set():break
                    await asyncio.sleep(.01)
                self.assertTrue(started.is_set())
                for task in tasks:task.cancel()
                await asyncio.gather(*tasks,return_exceptions=True)
                with self.assertRaises(HTTPException) as cm:
                    await _run_bounded(lambda: None)
                self.assertEqual(cm.exception.status_code,503)
            finally:
                release.set()
                await asyncio.sleep(.1)
        asyncio.run(exercise())
        self.assertTrue(_slots.acquire(False));_slots.release()

    def test_html_export_escapes_and_receipt_rejects_tampering(self):
        from renderdiff.exports import html_report
        report=attach(analyze('<script>alert(1)</script>'))
        output=html_report(report)
        self.assertIn('&lt;script&gt;',output)
        self.assertNotIn('<script>alert(1)</script>',output)
        forged=copy.deepcopy(report);forged['summary']['severity']='forged'
        with self.assertRaises(ValueError):html_report(forged)
