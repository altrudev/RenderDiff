import unittest, sys
sys.path.insert(0,"src")
from renderdiff import analyze
from renderdiff.browser import chromium_observe_html, find_chromium
from renderdiff.uts39 import UTS39_CONFUSABLES_SHA256, UTS39_VERSION

class ObserverTests(unittest.TestCase):
    def test_full_uts39_default_metadata(self):
        r=analyze("Hello")
        c=r["views"]["confusable"]
        self.assertEqual(c["mapping_scope"],"full-pinned-uts39")
        self.assertEqual(c["uts39_version"],UTS39_VERSION)
        self.assertEqual(c["uts39_confusables_sha256"],UTS39_CONFUSABLES_SHA256)
        self.assertNotIn("confusable-homoglyph",r["summary"]["categories"])

    def test_tokenizer_observer_metadata(self):
        r=analyze("hello world",tokenizer=lambda s:[11,22],tokenizer_name="fixture:v1")
        t=r["views"]["model_facing"]["tokenizer"]
        self.assertTrue(t["available"]); self.assertEqual(t["name"],"fixture:v1")
        self.assertEqual(t["tokens"],[11,22])

    def test_pairwise_divergence_zero_width(self):
        r=analyze("pay\u200bment")
        pairs=r["views"]["pairwise_divergence"]["comparisons"]
        hit=[x for x in pairs if {x["left"],x["right"]}=={"machine","human_projection"}]
        self.assertEqual(len(hit),1); self.assertFalse(hit[0]["equal"])

    @unittest.skipUnless(find_chromium(),"Chromium not installed")
    def test_real_browser_inner_text(self):
        html='<p>Visible</p><div style="display:none">Hidden</div>'
        r=analyze(html,content_type="text/html",browser_observer=chromium_observe_html)
        b=r["views"]["browser_render"]
        self.assertTrue(b["available"],b)
        self.assertIn("Visible",b["text"]); self.assertNotIn("Hidden",b["text"])
        pairs=r["views"]["pairwise_divergence"]["comparisons"]
        self.assertTrue(any(x["left"]=="browser_inner_text" or x["right"]=="browser_inner_text" for x in pairs))

    def test_browser_observer_requires_server_configuration(self):
        from renderdiff import analyze_request
        with self.assertRaises(ValueError):
            analyze_request({"text":"<p>x</p>","content_type":"text/html","browser":True})

    def test_configured_browser_api(self):
        from renderdiff import analyze_request
        fake=lambda page:{"available":True,"observer":"fixture","text":"Rendered"}
        r=analyze_request({"text":"<p>Source</p>","content_type":"text/html","browser":True},browser_observer=fake)
        self.assertEqual(r["views"]["browser_render"]["text"],"Rendered")
        self.assertIn("render-observer-divergence",r["summary"]["categories"])

    def test_tokenizer_rejects_non_json_tokens(self):
        with self.assertRaises(TypeError):
            analyze("x",tokenizer=lambda value:[{1,2}])

if __name__=="__main__": unittest.main()
