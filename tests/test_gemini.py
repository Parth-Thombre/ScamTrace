"""Exercise the real SDK against a local HTTP transport; no API calls or keys."""
import json
import unittest
from unittest.mock import patch

import httpx
from openai import AsyncOpenAI

from scamtrace.judge import Judge
from tests.test_judge import observation


class GeminiTests(unittest.IsolatedAsyncioTestCase):
    async def make_judge(self, handler):
        with patch.dict("os.environ", {"GEMINI_API_KEY": "test-only-placeholder"}):
            judge = Judge("gemini-test", provider="gemini")
        await judge.client.close()
        judge.client = AsyncOpenAI(
            api_key="test-only-placeholder",
            base_url="https://generativelanguage.googleapis.com/v1beta/openai/",
            max_retries=0,
            http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        )
        self.addAsyncCleanup(judge.close)
        return judge

    async def test_structured_verdict_and_token_usage(self):
        def handler(request):
            self.assertEqual(request.url.path, "/v1beta/openai/chat/completions")
            body = json.loads(request.content)
            self.assertEqual(body["response_format"]["type"], "json_schema")
            self.assertLessEqual(body["max_tokens"], 4096)
            decision = dict(classification="SCAM", confidence=0.85,
                            reasoning="Implausible offer", evidence=["Guaranteed profits"],
                            needs_review=False, evidence_kind="guaranteed_returns")
            return httpx.Response(200, json={
                "id": "mock", "object": "chat.completion", "created": 0,
                "model": "gemini-test",
                "choices": [{"index": 0, "finish_reason": "stop", "message": {
                    "role": "assistant", "content": json.dumps(decision)}}],
                "usage": {"prompt_tokens": 30, "completion_tokens": 20, "total_tokens": 50},
            })
        judge = await self.make_judge(handler)
        verdict = await judge.classify([observation("Guaranteed profits")])
        self.assertEqual(verdict.classification, "SCAM")
        self.assertEqual(verdict.evidence, ["Guaranteed profits"])
        self.assertEqual((judge.input_tokens, judge.output_tokens), (30, 20))
        self.assertEqual(judge.errors, [])

    async def test_quota_failure_is_redacted_and_reviewed(self):
        judge = await self.make_judge(lambda request: httpx.Response(
            429, json={"error": {"message": "secret-value", "type": "quota", "code": "quota"}}))
        verdict = await judge.classify([observation()])
        self.assertTrue(verdict.needs_review)
        self.assertEqual(judge.errors, ["LLM failure: RateLimitError"])
        self.assertNotIn("secret-value", str(judge.errors))

    async def test_malformed_output_falls_back(self):
        judge = await self.make_judge(lambda request: httpx.Response(200, json={
            "id": "mock", "object": "chat.completion", "created": 0, "model": "gemini-test",
            "choices": [{"index": 0, "finish_reason": "stop", "message": {
                "role": "assistant", "content": '{"classification":"SAFE"}'}}],
        }))
        verdict = await judge.classify([observation()])
        self.assertTrue(verdict.needs_review)
        self.assertEqual(verdict.classification, "NOT_SCAM")
        self.assertTrue(judge.errors)
