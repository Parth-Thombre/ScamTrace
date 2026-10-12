"""Exercise real navigation against local synthetic fixtures, without paid calls.

This is the ONLY local-browser path. It never visits challenge targets.
"""
import asyncio
import io
import json
from pathlib import Path
from urllib.parse import urlsplit
from PIL import Image
import zxingcpp

from playwright.async_api import async_playwright
from scamtrace.runner import investigate, save_json
from scamtrace.report import render


class FixtureBrowser:
    def __init__(self, browser):
        self.browser = browser

    async def new_context(self, **options):
        context = await self.browser.new_context(**options)
        async def serve(route):
            parsed = urlsplit(route.request.url)
            name = parsed.path.strip("/")
            if parsed.hostname != "fixture.example":
                await route.abort()
                return
            if name == "qr.png":
                qr = zxingcpp.write_barcode(zxingcpp.BarcodeFormat.QRCode,
                                           "bitcoin:1BoatSLRHtKNngkdXEeobR76b53LETtpyT", width=240, height=240)
                buffer = io.BytesIO()
                Image.fromarray(qr).save(buffer, format="PNG")
                await route.fulfill(content_type="image/png", body=buffer.getvalue())
                return
            if name in {"wallet.json", "headerless-wallet.json"}:
                body = json.dumps({"deposit_address": "TLa2f6VPqDgRE67v1736s7bJ8Ray5wYjU7"})
                headers = {"content-length": str(len(body))} if name == "wallet.json" else {}
                await route.fulfill(content_type="application/json", body=body, headers=headers)
                return
            if name not in {"index.html", "deposit.html", "legitimate.html", "login.html",
                            "qr.html", "qr-below.html", "networks.html", "api.html", "headerless-api.html", "spa.html", "frontier.html", "deadend.html", "deposit-faq.html"}:
                await route.fulfill(status=404, body="Fixture not found")
                return
            await route.fulfill(content_type="text/html", body=(Path("tests/fixtures") / name).read_text())
        await context.route("**/*", serve)
        return context


async def main():
    # Every browser request is fulfilled from fixtures. Nothing leaves this demo.
    origin = "https://fixture.example"
    output = Path("outputs/demo")
    results = []
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        try:
            for name in ["index", "legitimate", "login", "qr", "networks", "api", "missing", "qr-below", "headerless-api", "spa", "frontier"]:
                account = None
                if name == "login":
                    account = {"origin": origin, "username": "researcher@example.invalid", "password": "fixture-only"}
                result = await investigate(FixtureBrowser(browser), origin + "/" + name + ".html",
                                           output / "evidence" / name, None, steps=4,
                                           credentials=account)
                results.append(result.to_dict())
        finally:
            await browser.close()
    save_json(output / "results.json", results)
    render(results, output)
    expected = ["SCAM", "NOT_SCAM", "SCAM", "SCAM", "SCAM", "SCAM", "NOT_SCAM", "SCAM", "SCAM", "SCAM", "SCAM"]
    actual = [r["classification"] for r in results]
    assert actual == expected, (actual, expected)
    assert results[0]["crypto_addresses"], "Hidden deposit was missed"
    assert results[2]["crypto_addresses"], "Login-gated address was missed"
    assert any(a["source"] == "qr_code" for a in results[3]["crypto_addresses"]), "QR-only address was missed"
    assert {a["network"] for a in results[4]["crypto_addresses"]} == {"BTC", "TRON", "EVM"}, "Network select coverage incomplete"
    assert any(a["source"] == "network_json" for a in results[5]["crypto_addresses"]), "Observed JSON address missed"
    assert results[6]["status"] == "http_error" and results[6]["needs_review"], "Unavailable fixture handled incorrectly"
    assert any(a["source"] == "qr_code" for a in results[7]["crypto_addresses"]), "Offscreen QR missed"
    assert any(a["source"] == "network_json" for a in results[8]["crypto_addresses"]), "Headerless JSON missed"
    assert results[9]["crypto_addresses"], "Plain SPA recharge control was missed"
    assert any(a["role"] == "possible_payment" for a in results[9]["crypto_addresses"])
    assert results[10]["crypto_addresses"], "Previously observed branch was not revisited"
    assert any(a.get("action") == "follow_observed_link" for a in results[10]["actions"])
    print("Synthetic demo passed; outputs/demo/report.html")


if __name__ == "__main__":
    asyncio.run(main())
