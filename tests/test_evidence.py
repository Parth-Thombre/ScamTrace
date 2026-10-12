import socket
import unittest
from unittest.mock import Mock, patch

from scamtrace.connectivity import diagnose
from scamtrace.evidence import investment_return_quotes, relevant_text
from scamtrace.judge import baseline
from scamtrace.models import Observation
from security.proxy import connect_public


class EvidenceTests(unittest.TestCase):
    def test_period_and_investment_context(self):
        cases = [
            ("Investment plan: Return 70 %\nWeekly", True),
            ("Investment Plans\nGold - 13%\nMin: $10,000\nDuration: 1 Week", True),
            ("Investment: 40% monthly profit, paid daily", True),
            ("Save 40% monthly on groceries", False),
            ("BTC +7% weekly", False),
            ("Historical return: 30% after 365 days", False),
            ("Investment plan: 3% after 30 days", False),
        ]
        for text, expected in cases:
            with self.subTest(text=text):
                quotes = investment_return_quotes(text)
                self.assertEqual(bool(quotes), expected)
                self.assertTrue(all(quote in text for quote in quotes))

    def test_daily_payout_does_not_change_monthly_period(self):
        quotes = investment_return_quotes("Investment: 40% monthly profit, paid daily")
        self.assertEqual(quotes, ["40% monthly"])

    def test_long_page_keeps_bottom_evidence(self):
        text = "Menu item\n" * 3000 + "Guaranteed investment return of 15% daily."
        self.assertIn("15% daily", relevant_text(text))
        self.assertLessEqual(len(relevant_text(text)), 12000)

    def test_negated_claim_is_not_positive_evidence(self):
        for text in ["We offer no guaranteed profits.", "Never enter your seed phrase."]:
            observation = Observation(0, "https://example.com", "", text, [], [], "x.png", "hash")
            self.assertEqual(baseline([observation]).classification, "NOT_SCAM")


class ConnectivityTests(unittest.TestCase):
    def test_dns_failure_explains_tunnel_error(self):
        with patch("scamtrace.connectivity.socket.getaddrinfo", side_effect=socket.gaierror()):
            self.assertEqual(diagnose("https://example.com", "net::ERR_TUNNEL_CONNECTION_FAILED"),
                             "dns_resolution_failed")

    def test_tls_failure_does_not_need_a_network_lookup(self):
        with patch("scamtrace.connectivity.socket.getaddrinfo") as lookup:
            self.assertEqual(diagnose("https://example.com", "net::ERR_CERT_DATE_INVALID"),
                             "tls_certificate_rejected")
            lookup.assert_not_called()

    def test_proxy_tries_second_validated_address(self):
        answers = [(2, 1, 6, "", ("93.184.216.34", 443)),
                   (2, 1, 6, "", ("93.184.216.35", 443))]
        first, second = Mock(), Mock()
        first.connect.side_effect = OSError("Unavailable")
        with patch("security.proxy.socket.getaddrinfo", return_value=answers), \
             patch("security.proxy.socket.socket", side_effect=[first, second]):
            self.assertIs(connect_public("example.com", 443), second)
            first.close.assert_called_once()
            second.connect.assert_called_once_with(("93.184.216.35", 443))

    def test_proxy_never_connects_when_one_dns_answer_is_private(self):
        answers = [(2, 1, 6, "", ("93.184.216.34", 443)),
                   (2, 1, 6, "", ("127.0.0.1", 443))]
        with patch("security.proxy.socket.getaddrinfo", return_value=answers), \
             patch("security.proxy.socket.socket") as create_socket:
            with self.assertRaises(ValueError):
                connect_public("example.com", 443)
            create_socket.assert_not_called()
