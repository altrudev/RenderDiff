import hashlib, sys, unittest
sys.path.insert(0, "src")
from renderdiff.uts39 import parse_confusables, uts39_skeleton


class UTS39Tests(unittest.TestCase):
    def test_parse_and_skeleton(self):
        data=(
            b"# tiny fixture\n"
            b"0430 ; 0061 ; MA # CYRILLIC SMALL LETTER A -> LATIN a\n"
            b"03BF ; 006F ; MA # GREEK SMALL LETTER OMICRON -> LATIN o\n"
        )
        digest=hashlib.sha256(data).hexdigest()
        mapping=parse_confusables(data, expected_sha256=digest)
        self.assertEqual(uts39_skeleton("pаy οk", mapping), "pay ok")

    def test_checksum_mismatch_fails_closed(self):
        with self.assertRaises(ValueError):
            parse_confusables(b"0430 ; 0061 ; MA\n", expected_sha256="0"*64)


if __name__ == "__main__":
    unittest.main()
