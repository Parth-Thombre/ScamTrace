import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

from scamtrace.browser import InvestigatorBrowser


class CaptureTests(unittest.IsolatedAsyncioTestCase):
    async def test_completed_headerless_json_is_captured(self):
        body = '{"deposit_address":"TLa2f6VPqDgRE67v1736s7bJ8Ray5wYjU7"}'
        response = SimpleNamespace(
            all_headers=AsyncMock(return_value={"content-type": "application/json"}),
            request=SimpleNamespace(sizes=AsyncMock(return_value={"responseBodySize": len(body)})),
            text=AsyncMock(return_value=body), url="https://example.com/wallet.json",
        )
        with tempfile.TemporaryDirectory() as directory:
            investigator = InvestigatorBrowser(None, Path(directory))
            await investigator.capture_response(response)
            self.assertEqual(len(investigator.network), 1)
            self.assertEqual(investigator.network[0].network, "TRON")

    async def test_large_transfer_is_skipped_before_decoding(self):
        response = SimpleNamespace(
            all_headers=AsyncMock(return_value={"content-type": "application/json"}),
            request=SimpleNamespace(sizes=AsyncMock(return_value={"responseBodySize": 200000})),
            text=AsyncMock(), url="https://example.com/large.json",
        )
        investigator = InvestigatorBrowser(None, Path("unused"))
        await investigator.capture_response(response)
        response.text.assert_not_awaited()

    async def test_closed_request_is_handled(self):
        investigator = InvestigatorBrowser(None, Path("unused"))
        request = SimpleNamespace(response=AsyncMock(side_effect=RuntimeError("closed")))
        await investigator.capture_request(request)
        self.assertFalse(investigator.network)

    async def test_wallet_login_is_rejected_before_browser_access(self):
        investigator = InvestigatorBrowser(None, Path("unused"))
        with self.assertRaises(ValueError):
            await investigator.click({"label": "Wallet login"})

    async def test_frontier_rejects_a_non_link(self):
        investigator = InvestigatorBrowser(None, Path("unused"))
        with self.assertRaises(ValueError):
            await investigator.follow_observed_link({"tag": "button", "label": "Deposit"})

    async def test_frontier_keeps_the_same_origin(self):
        investigator = InvestigatorBrowser(None, Path("unused"))
        investigator.page = SimpleNamespace(url="https://example.com/login", goto=AsyncMock())
        with self.assertRaises(ValueError):
            await investigator.follow_observed_link({
                "tag": "a", "label": "Deposit", "href": "https://other.example/deposit"})
        investigator.page.goto.assert_not_awaited()
