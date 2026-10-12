import unittest
from scamtrace.models import Result
from scamtrace.output import summarize


class OutputAuditTests(unittest.TestCase):
    def test_manifest_mismatch_is_reported(self):
        result = Result("https://example.com").to_dict()
        self.assertTrue(summarize([result], ["https://other.example"]) ["structural_issues"])

    def test_unsupported_evidence_is_reported(self):
        result = Result("https://example.com", evidence=["invented claim"]).to_dict()
        self.assertTrue(summarize([result])["structural_issues"])

    def test_inaccessible_records_remain_unresolved(self):
        result = Result("https://example.com", status="unreachable").to_dict()
        summary = summarize([result], [result["url"]])
        self.assertEqual(summary["review_required"], 1)
        self.assertEqual(summary["unique_addresses"], 0)
        self.assertFalse(summary["structural_issues"])
