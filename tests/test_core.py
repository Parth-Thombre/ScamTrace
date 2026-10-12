import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scamtrace.addresses import address_key, extract, validate
from scamtrace.cli import read_urls
from scamtrace.judge import baseline
from scamtrace.models import Address, Observation, Result
from scamtrace.policy import allowed_label, same_origin, validate_url
from scamtrace.report import render
from scamtrace.runner import browser_error, control_key
from security.proxy import public_destination

BTC = "1BoatSLRHtKNngkdXEeobR76b53LETtpyT"
TRON = "TLa2f6VPqDgRE67v1736s7bJ8Ray5wYjU7"


class AddressTests(unittest.TestCase):
    def test_checksums_and_corruption(self):
        self.assertEqual(validate(BTC)[0], "BTC")
        self.assertIsNone(validate(BTC[:-1] + "X"))
        self.assertEqual(validate(TRON)[0], "TRON")
        self.assertIsNone(validate(TRON[:-1] + "X"))

    def test_uri_boundary_and_context(self):
        hits = extract(f"Deposit bitcoin:{BTC}?amount=1", "qr_code", "https://example.com")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].role, "possible_payment")
        self.assertFalse(extract("a" + BTC + "z", "text", "https://example.com"))

    def test_evm_format_not_asset_identity(self):
        value = "0x" + "ab" * 20
        self.assertEqual(validate(value)[0], "EVM")
        self.assertEqual(validate("0x" + "0" * 40)[0], "EVM")
        self.assertEqual(extract("Token contract " + value, "text", "https://example.com")[0].role,
                         "possible_contract")

    def test_market_data_token_address_is_not_a_deposit_wallet(self):
        value = "0x" + "ab" * 20
        hits = extract('{"platform":{"token_address":"' + value + '"}}',
                       "network_json", "https://example.com/market-widget")
        self.assertEqual(hits[0].role, "possible_contract")

    def test_case_sensitive_base58_keys(self):
        address = Address(BTC, "BTC", "checksum", "text", "https://example.com", "")
        self.assertEqual(address_key(address)[1], BTC)

    def test_segwit_vectors(self):
        # Valid mainnet BIP-350 v0 example and invalid checksum.
        valid = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
        self.assertEqual(validate(valid)[0], "BTC")
        self.assertIsNone(validate(valid[:-1] + "q"))
        self.assertIsNone(validate(valid[:6].upper() + valid[6:]))

    def test_eip55_vectors(self):
        self.assertEqual(validate("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed")[1], "EIP-55 checksum")
        self.assertIsNone(validate("0x5AAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"))


class PolicyTests(unittest.TestCase):
    def test_actions(self):
        self.assertTrue(allowed_label("USDT deposit"))
        self.assertFalse(allowed_label("Deposit and buy now"))
        self.assertFalse(allowed_label("Connect wallet"))
        self.assertFalse(allowed_label("Withdraw to wallet"))

    def test_url_validation(self):
        for url in ["file:///etc/passwd", "http://127.0.0.1", "http://169.254.169.254",
                    "http://[::1]", "https://user:secret@example.com", "https://example.com:8080"]:
            with self.assertRaises(ValueError, msg=url):
                validate_url(url)
        validate_url("https://example.com/wap")
        self.assertTrue(same_origin("https://example.com", "https://example.com:443/a"))
        self.assertFalse(same_origin("https://example.com", "https://example.com.attacker.net"))

    def test_proxy_rejects_mixed_public_private_dns(self):
        answers = [(2, 1, 6, "", ("93.184.216.34", 443)), (2, 1, 6, "", ("127.0.0.1", 443))]
        with patch("security.proxy.socket.getaddrinfo", return_value=answers):
            with self.assertRaises(ValueError):
                public_destination("rebind.example", 443)

    def test_proxy_preserves_validated_sockaddr(self):
        answer = (2, 1, 6, "", ("93.184.216.34", 443))
        with patch("security.proxy.socket.getaddrinfo", return_value=[answer]):
            self.assertEqual(public_destination("example.com", 443), answer)


class OutputTests(unittest.TestCase):
    def test_navigation_target_is_remembered_across_pages(self):
        link = {"tag": "a", "href": "https://example.com/login", "frame": 0, "label": "Login"}
        self.assertEqual(control_key("https://example.com/about", link),
                         control_key("https://example.com/contact", link))
        button = dict(link, tag="button", href=None)
        self.assertNotEqual(control_key("https://example.com/about", button),
                            control_key("https://example.com/contact", button))

    def test_return_period_is_bound_to_percentage(self):
        observation = Observation(0, "https://example.com", "", "", [], [], "demo.png", "hash")
        for text in ["4% monthly profit, paid daily", "Save 15% today", "2% daily return"]:
            observation.text = text
            self.assertEqual(baseline([observation]).classification, "NOT_SCAM", text)
        for text in ["15% daily return", "8% after 1 days", "15% after 2 days", "Investment: 40% monthly profit, paid daily"]:
            observation.text = text
            self.assertEqual(baseline([observation]).classification, "SCAM", text)

    def test_browser_error_keeps_code_without_credentials(self):
        error = RuntimeError("net::ERR_TUNNEL_CONNECTION_FAILED at https://user:secret@example.com")
        self.assertEqual(browser_error(error), "RuntimeError (net::ERR_TUNNEL_CONNECTION_FAILED)")
        self.assertNotIn("secret", browser_error(error))

    def test_no_fraud_inference_from_crypto_alone(self):
        observation = Observation(0, "https://example.com", "", "Donate Bitcoin " + BTC,
                                  [], [], "demo.png", "hash")
        verdict = baseline([observation])
        self.assertEqual(verdict.classification, "NOT_SCAM")
        self.assertTrue(verdict.needs_review)
        observation.text = "Guaranteed profits with 15% daily returns"
        self.assertEqual(baseline([observation]).classification, "SCAM")

    def test_report_escapes_hostile_site_content(self):
        result = Result("https://example.com", reasoning="<script>alert(1)</script>")
        with tempfile.TemporaryDirectory() as folder:
            render([result.to_dict()], Path(folder))
            html = (Path(folder) / "report.html").read_text()
            self.assertNotIn("<script>alert", html)
            self.assertIn("&lt;script&gt;", html)

    def test_report_handles_observation_without_screenshot(self):
        result = Result("https://example.com")
        result.observations.append(
            Observation(
                0,
                result.url,
                "Example",
                "Observed text",
                [],
                [],
                "",
                "fingerprint",
            )
        )
        with tempfile.TemporaryDirectory() as folder:
            render([result.to_dict()], Path(folder))
            html = (Path(folder) / "report.html").read_text()
            self.assertIn("Observed text", html)

    def test_manifest_has_160_unique_urls(self):
        self.assertEqual(len(read_urls("targets.txt")), 160)

    def test_result_is_serializable(self):
        self.assertIn("needs_review", json.loads(json.dumps(Result("https://example.com").to_dict())))


if __name__ == "__main__":
    unittest.main()
