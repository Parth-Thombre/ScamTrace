import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock

from scamtrace.judge import Judge, guarded_verdict
from scamtrace.models import Observation


def observation(text="We publish open source software."):
    return Observation(0, "https://example.com", "Demo", text,
                       [{"id": 0, "label": "Deposit", "href": "/deposit"}], [], "demo.png", "hash")


class JudgeTests(unittest.IsolatedAsyncioTestCase):
    async def test_invented_control_is_rejected(self):
        judge = Judge(None)
        judge.ask = AsyncMock(return_value=SimpleNamespace(control_id=123, reason="invented"))
        self.assertEqual(await judge.choose(observation(), []), -1)

    async def test_unobserved_quote_cannot_support_high_confidence(self):
        judge = Judge(None)
        judge.ask = AsyncMock(return_value=SimpleNamespace(
            classification="SCAM", confidence=0.99, reasoning="Suspicious",
            evidence=["Invented guaranteed profits"], needs_review=False))
        verdict = await judge.classify([observation()])
        self.assertEqual(verdict.evidence, [])
        self.assertLessEqual(verdict.confidence, 0.4)
        self.assertTrue(verdict.needs_review)

    async def test_observed_quote_survives(self):
        judge = Judge(None)
        judge.ask = AsyncMock(return_value=SimpleNamespace(
            classification="SCAM", confidence=0.8, reasoning="Implausible returns",
            evidence=["Guaranteed profits"], needs_review=False))
        verdict = await judge.classify([observation("Guaranteed profits with 20% daily returns")])
        self.assertEqual(verdict.evidence, ["Guaranteed profits"])
        self.assertEqual(judge.verdict_source, "rules")

    async def test_grounded_quote_allows_whitespace_differences(self):
        judge = Judge(None)
        judge.ask = AsyncMock(return_value=SimpleNamespace(
            classification="SCAM", confidence=0.95, reasoning="Implausible returns",
            evidence=["Guaranteed profits"], needs_review=False))
        verdict = await judge.classify(
            [observation("Guaranteed   profits from investment")]
        )
        self.assertEqual(verdict.evidence, ["Guaranteed   profits"])
        self.assertEqual(verdict.confidence, 0.75)
        self.assertTrue(verdict.needs_review)

    async def test_unverified_allegation_is_not_accepted(self):
        verdict = guarded_verdict(
            [observation("We offer online gambling.")],
            SimpleNamespace(
                classification="SCAM",
                confidence=0.99,
                evidence=["online gambling"],
                evidence_kind="insufficient",
            ),
        )
        self.assertEqual(verdict.classification, "NOT_SCAM")
        self.assertEqual(verdict.confidence, 0.4)
        self.assertTrue(verdict.needs_review)

    async def test_observed_contradiction_requires_two_grounded_statements(self):
        first = "The company is headquartered in Australia."
        second = "The company is headquartered in New York."
        verdict = guarded_verdict(
            [observation(first + "\n" + second)],
            SimpleNamespace(
                classification="SCAM",
                confidence=0.9,
                evidence=[first, second],
                evidence_kind="identity_conflict",
            ),
        )
        self.assertEqual(verdict.classification, "SCAM")
        self.assertEqual(verdict.confidence, 0.65)
        self.assertEqual(verdict.evidence, [first, second])
        self.assertTrue(verdict.needs_review)

    async def test_classification_payload_includes_review_date(self):
        judge = Judge(None)
        judge.ask = AsyncMock(return_value=None)
        await judge.classify([observation()])
        review_date = judge.ask.call_args.args[0]["review_date"]
        self.assertRegex(review_date, r"^\d{4}-\d{2}-\d{2}$")

    async def test_refusal_falls_back_without_leaking_exception(self):
        judge = Judge(None)
        parse = AsyncMock(side_effect=RuntimeError("secret API credential must not persist"))
        judge.client = SimpleNamespace(responses=SimpleNamespace(parse=parse))
        verdict = await judge.classify([observation()])
        self.assertTrue(verdict.needs_review)
        self.assertEqual(judge.errors, ["LLM failure: RuntimeError"])
        self.assertEqual(judge.verdict_source, "rules_fallback")
        self.assertNotIn("secret", str(judge.errors))

    async def test_call_budget(self):
        judge = Judge(None, max_calls=0)
        parse = AsyncMock()
        judge.client = SimpleNamespace(responses=SimpleNamespace(parse=parse))
        await judge.classify([observation()])
        parse.assert_not_awaited()
