import io, json, sys, unittest, zipfile
from renderdiff import analyze
from renderdiff.assurance import attach
from renderdiff.ingest import acquire_bytes, acquire_url
from renderdiff.modelview import compare_model_views
from renderdiff.semantic import observe_semantics
from renderdiff.receipt import verify,seal,verify_seal
from renderdiff.exports import html_report,sarif_report
from renderdiff.safe_browser import observe_html

class CompletionTests(unittest.TestCase):
    def test_receipt_tampering(self):
        r=attach(analyze('pay\u200bment'))
        self.assertTrue(verify(r))
        r['views']['human_visible']['text']='forged'
        self.assertFalse(verify(r))
        with self.assertRaises(ValueError): html_report(r)
    def test_model_tokens_are_exact_not_semantic_claims(self):
        r=compare_model_views('pay\u200bment','payment',lambda s:list(s.encode()),name='byte-fixture')
        self.assertFalse(r['equal'])
        self.assertIn('not proof',r['interpretation'])
    def test_semantic_observer_evidence_bounds(self):
        f=lambda x:{'claims':[{'boundary':'instruction','materiality':'potentially-material','evidence':[{'view':'machine','start':0,'end':3}]}]}
        self.assertEqual(observe_semantics('abc','abc',f,observer_id='fixture')['authority'],'advisory-only')
        with self.assertRaises(ValueError): observe_semantics('abc','abc',lambda x:{'claims':[{'boundary':'instruction','materiality':'material','evidence':[{'view':'machine','start':0,'end':99}]}]},observer_id='fixture')
    def test_source_hash_and_invalid_utf8(self):
        r=acquire_bytes(b'abc\xff',filename='test.txt')
        self.assertTrue(verify(r))
        self.assertEqual(r['summary']['categories'],['invalid-utf8'])
    def test_ooxml_extraction(self):
        buf=io.BytesIO()
        with zipfile.ZipFile(buf,'w') as z:z.writestr('word/document.xml','<w:document xmlns:w="urn:w"><w:t>pay\u200bment</w:t></w:document>')
        r=acquire_bytes(buf.getvalue(),filename='sample.docx')
        self.assertTrue(verify(r))
        self.assertIn('invisible-unicode',r['summary']['categories'])
        self.assertEqual(r['views']['source_document']['sha256'],r['input']['sha256'] if False else r['views']['lineage']['source_sha256'])
    def test_url_requires_isolated_fetcher(self):
        with self.assertRaises(ValueError):acquire_url('https://example.com')
        with self.assertRaises(ValueError):acquire_url('file:///etc/passwd')
    def test_no_implicit_browser_execution(self):
        self.assertFalse(observe_html('<p>x</p>')['available'])
    def test_html_export_escapes_payload(self):
        r=attach(analyze('<script>alert(1)</script>'))
        h=html_report(r)
        self.assertNotIn('<script>alert(1)</script>',h)
        self.assertIn('&lt;script&gt;',h)
    def test_sarif_schema(self):
        r=attach(analyze('a\u200bb'))
        self.assertEqual(sarif_report(r)['version'],'2.1.0')
    def test_signed_receipt(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        key=Ed25519PrivateKey.generate();r=attach(analyze('hello'))
        signed=seal(r,private_key=key,key_id='fixture')
        self.assertTrue(verify_seal(r,signed,key.public_key()))
        signed['key_id']='forged'
        self.assertFalse(verify_seal(r,signed,key.public_key()))
    def test_assurance_is_deterministic(self):
        a=attach(analyze('a\u200bb'));b=attach(analyze('a\u200bb'))
        self.assertEqual(json.dumps(a,sort_keys=True),json.dumps(b,sort_keys=True))

if __name__=='__main__':unittest.main()
