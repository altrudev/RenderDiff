import unittest, sys
sys.path.insert(0,"src")
from renderdiff import analyze
from renderdiff.browser import chromium_observe_html, find_chromium
from renderdiff.divergence import compare_text_views
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
        self.assertEqual(len(hit),1)
        edge=hit[0]
        self.assertFalse(edge["equal"])
        self.assertEqual(edge["relation"],"divergence")
        self.assertEqual(edge["first_difference_index"],3)
        self.assertEqual(edge["common_prefix_chars"],3)
        self.assertEqual(edge["common_suffix_chars"],4)
        machine_is_left=edge["left"]=="machine"
        machine_fragment=edge["delta"]["left_fragment" if machine_is_left else "right_fragment"]
        human_fragment=edge["delta"]["right_fragment" if machine_is_left else "left_fragment"]
        self.assertEqual(machine_fragment["text"],"\u200b")
        self.assertEqual(human_fragment["text"],"")

    def test_pairwise_agreement_has_no_delta(self):
        edge=compare_text_views({"a":"same","b":"same"})[0]
        self.assertTrue(edge["equal"])
        self.assertEqual(edge["relation"],"agreement")
        self.assertIsNone(edge["first_difference_index"])
        self.assertNotIn("delta",edge)

    def test_pairwise_delta_is_bounded_for_large_middle(self):
        a="prefix-" + ("A" * 1000) + "-suffix"
        b="prefix-" + ("B" * 1000) + "-suffix"
        edge=compare_text_views({"a":a,"b":b})[0]
        self.assertEqual(edge["common_prefix_chars"],7)
        self.assertEqual(edge["common_suffix_chars"],7)
        self.assertEqual(edge["delta"]["left_fragment"]["char_length"],1000)
        self.assertEqual(edge["delta"]["right_fragment"]["char_length"],1000)
        self.assertTrue(edge["delta"]["left_fragment"]["truncated"])
        self.assertTrue(edge["delta"]["right_fragment"]["truncated"])
        self.assertLessEqual(len(edge["delta"]["left_fragment"]["text"]),97)
        self.assertLessEqual(len(edge["delta"]["right_fragment"]["text"]),97)

    def test_radial_visibility_boundary_is_evidence_backed(self):
        r=analyze("pay\u200bment")
        radial=r["views"]["radial_assessment"]
        edge=next(x for x in radial["edges"] if x["boundary"]=="visibility")
        self.assertEqual(edge["relation"],"divergence")
        self.assertEqual(edge["materiality"],"potentially-material")
        self.assertIn("invisible-unicode",edge["evidence_categories"])
        self.assertEqual(edge["first_difference_index"],3)
        self.assertTrue(radial["material_divergence"])

    def test_radial_benign_ascii_has_no_material_boundary(self):
        r=analyze("hello world")
        radial=r["views"]["radial_assessment"]
        self.assertFalse(radial["material_divergence"])
        self.assertEqual(radial["disposition"],"none")
        self.assertEqual(r["summary"]["radial_boundaries"],[])

    def test_radial_identity_boundary_confusable(self):
        r=analyze("microsоft.com")
        edge=next(x for x in r["views"]["radial_assessment"]["edges"] if x["boundary"]=="identity")
        self.assertEqual(edge["relation"],"divergence")
        self.assertEqual(edge["materiality"],"potentially-material")
        self.assertIn("confusable-homoglyph",edge["evidence_categories"])

    def test_radial_hidden_tag_payload_is_material(self):
        hidden="".join(chr(0xE0000 + ord(c)) for c in " HIDDEN PAYLOAD")
        r=analyze("Invoice attached" + hidden)
        edge=next(x for x in r["views"]["radial_assessment"]["edges"] if x["boundary"]=="hidden-tag")
        self.assertEqual(edge["relation"],"divergence")
        self.assertEqual(edge["materiality"],"material")
        self.assertIn("ascii-smuggling",edge["evidence_categories"])
        self.assertTrue(r["summary"]["radial_material_divergence"])

    def test_radial_standard_flag_tag_stays_context_dependent(self):
        def tags(value):
            return "".join(chr(0xE0000 + ord(c)) for c in value) + chr(0xE007F)
        flag="\U0001F3F4" + tags("gbeng")
        r=analyze(flag)
        edge=next(x for x in r["views"]["radial_assessment"]["edges"] if x["boundary"]=="hidden-tag")
        self.assertEqual(edge["relation"],"divergence")
        self.assertEqual(edge["materiality"],"context-dependent")
        self.assertFalse(r["views"]["radial_assessment"]["material_divergence"])

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
