import hashlib
import io
import json
import re
from pathlib import Path

from .addresses import deduplicate, extract
from .models import Observation
from .policy import allowed_label, same_origin, validate_url

# Control indices are assigned to observed elements, not selectors invented by an LLM.
CONTROL_SELECTOR = "a,button,[role=button],select,[onclick],input[type=button],input[type=submit],div,span,uni-view,uni-text"
SNAPSHOT = r"""() => {
  const visible = e => !!(e.getClientRects().length) && getComputedStyle(e).visibility !== 'hidden';
  const elements = [...document.querySelectorAll('a,button,[role=button],select,[onclick],input[type=button],input[type=submit],div,span,uni-view,uni-text')];
  const label = e => (e.innerText || e.getAttribute('aria-label') || e.getAttribute('title') ||
    ((e.type === 'button' || e.type === 'submit') ? e.value : '') || '').trim().slice(0,120);
  const permittedElement = e => {
    if (e.matches('a,button,[role=button],select,input[type=button],input[type=submit]')) return true;
    if (e.closest('a,button,[role=button]') || e.childElementCount) return false;
    // Some SPAs render safe navigation as plain div/span elements.
    return /^(recharge|deposit|receive|funding|log\s*in|sign\s*in|network|currency|bank\s*issue|btc|eth|usdt|usdc|充值|入金|充幣|充币|登录|登入)$/i.test(label(e));
  };
  return {
    text: (document.body?.innerText || '').slice(0, 60000),
    values: [...document.querySelectorAll('input:not([type=password]),textarea')]
      .filter(visible).map(e => e.value).join('\n').slice(0, 20000),
    attributes: [...document.querySelectorAll('a,img,[data-address],[data-clipboard-text]')]
      .slice(0, 1000).map(e => ['href','src','data-address','data-clipboard-text']
        .map(a => e.getAttribute(a) || '').join(' ')).join('\n').slice(0, 60000),
    scripts: [...document.querySelectorAll('script:not([src])')]
      .map(e => e.textContent).join('\n').slice(0, 100000),
    controls: elements.map((e, index) => ({index, tag: e.tagName.toLowerCase(),
      label: label(e), form_action: e.tagName !== 'A' && (!!e.closest('form') || !!document.querySelector('input[type=password]')),
      href: e.tagName === 'A' ? e.href : null,
      options: e.tagName === 'SELECT' ? [...e.options].map(o => ({value:o.value, label:o.label})).slice(0,30) : [],
      visible: visible(e) && permittedElement(e), disabled: !!e.disabled})).filter(e => e.visible && !e.disabled).slice(0,300)
  };
}"""


class InvestigatorBrowser:
    def __init__(self, context, folder: Path):
        self.context = context
        self.folder = folder
        self.page = None
        self.network = []
        self.pending = set()
        self.warnings = []
        self.http_status = None
        self.visuals_seen = set()

    async def start(self, url: str):
        import asyncio

        self.page = await self.context.new_page()
        self.page.set_default_timeout(6000)
        self.page.on("dialog", lambda dialog: dialog.dismiss())
        self.context.on("page", lambda page: page.close() if page != self.page else None)
        self.context.on("requestfinished", lambda request: self.schedule_response(request, asyncio))
        self.page.on("response", self.track_status)
        response = await self.page.goto(url, wait_until="domcontentloaded", timeout=25000)
        self.http_status = response.status if response else None
        await self.settle()

    def track_status(self, response):
        if response.request.is_navigation_request() and response.frame == self.page.main_frame:
            self.http_status = response.status

    def schedule_response(self, request, asyncio):
        task = asyncio.create_task(self.capture_request(request))
        self.pending.add(task)
        task.add_done_callback(self.pending.discard)

    async def capture_request(self, request):
        try:
            response = await request.response()
            if response:
                await self.capture_response(response)
        except Exception:
            return

    async def capture_response(self, response):
        # Observe only responses the site actually requested. No endpoint guessing.
        if len(self.network) >= 40:
            return
        try:
            headers = await response.all_headers()
            size = int(headers.get("content-length", "0"))
            if "json" not in headers.get("content-type", ""):
                return
            if not size:
                size = (await response.request.sizes())["responseBodySize"]
            if not 0 < size <= 128000:
                return
            content = await response.text()
            if len(content.encode("utf-8")) > 128000:
                return
            hits = extract(content, "network_json", response.url)
            if hits:
                self.network.extend(hits[:40 - len(self.network)])
        except Exception:
            return

    async def settle(self):
        # Network-idle is bounded: scam sites may keep connections open forever.
        try:
            await self.page.wait_for_load_state("networkidle", timeout=2500)
        except Exception:
            pass
        try:
            await self.page.wait_for_function(
                "() => (document.body?.innerText || '').trim().length > 20",
                timeout=4000,
            )
        except Exception:
            pass

    async def observe(self, step: int) -> Observation:
        import asyncio
        from PIL import Image
        import zxingcpp

        self.folder.mkdir(parents=True, exist_ok=True)
        image_path = self.folder / f"step-{step:02}.png"
        screenshot = await self.page.screenshot(path=str(image_path), timeout=6000)
        sources = []
        text_parts = []
        controls = []
        for frame_index, frame in enumerate(self.page.frames[:12]):
            try:
                snapshot = await frame.evaluate(SNAPSHOT)
                text_parts.append(snapshot["text"])
                for source, key in [("visible_text", "text"), ("input_value", "values"),
                                    ("dom_attribute", "attributes"), ("inline_script", "scripts")]:
                    sources.extend(extract(snapshot[key], source, frame.url,
                                           str(image_path) if source == "visible_text" else None))
                for control in snapshot["controls"]:
                    if not allowed_label(control["label"]):
                        continue
                    if "@" in control["label"]:
                        continue
                    if control.get("form_action") and re.search(r"log\s*in|sign\s*in|register|sign\s*up|登录|登入|注册|註冊", control["label"], re.I):
                        continue
                    if control["href"]:
                        try:
                            validate_url(control["href"])
                            if not same_origin(self.page.url, control["href"]):
                                continue
                        except ValueError:
                            continue
                    control.update(id=len(controls), frame=frame_index)
                    controls.append(control)
            except Exception as exc:
                self.warnings.append("Frame observation: " + type(exc).__name__)
        try:
            for qr in zxingcpp.read_barcodes(Image.open(io.BytesIO(screenshot))):
                sources.extend(extract(qr.text, "qr_code", self.page.url, str(image_path)))
        except Exception as exc:
            self.warnings.append("QR decode: " + type(exc).__name__)
        # QR codes may be below the viewport. Inspect a bounded set of rendered
        # image/canvas elements and retain an unedited contextual screenshot.
        for frame_index, frame in enumerate(self.page.frames[:12]):
            try:
                elements = (await frame.locator("img,canvas").all())[:20]
            except Exception:
                continue
            for index, element in enumerate(elements):
                try:
                    key = (frame.url, index, await element.get_attribute("src"))
                    canvas = await element.evaluate("e => e.tagName === 'CANVAS'")
                    if (not canvas and key in self.visuals_seen) or not await element.is_visible():
                        continue
                    self.visuals_seen.add(key)
                    box = await element.bounding_box()
                    if not box or not (48 <= box["width"] <= 1000 and 48 <= box["height"] <= 1000):
                        continue
                    # Logos and banners need not cost a separate browser action.
                    if not 0.65 <= box["width"] / box["height"] <= 1.5:
                        continue
                    pixels = await element.screenshot(timeout=1500)
                    hits = []
                    for qr in zxingcpp.read_barcodes(Image.open(io.BytesIO(pixels))):
                        hits.extend(extract(qr.text, "qr_code", frame.url))
                    if hits:
                        path = self.folder / f"step-{step:02}-qr-{frame_index}-{index}.png"
                        await self.page.screenshot(path=str(path), timeout=4000)
                        for hit in hits:
                            hit.screenshot = str(path)
                        sources.extend(hits)
                except Exception:
                    continue
        if self.pending:
            # Bounded wait; exceptions were handled inside capture_response.
            await asyncio.wait(list(self.pending), timeout=1)
        sources.extend(self.network)
        self.network = []
        text = "\n\n".join(text_parts)
        addresses = deduplicate(sources)
        # Address screenshots show the real page, never an edited reconstruction.
        for index, address in enumerate(addresses[:6]):
            if address.source not in {"visible_text", "input_value"}:
                continue
            for frame in self.page.frames[:12]:
                try:
                    locator = frame.get_by_text(address.value, exact=False).first
                    if address.source == "input_value":
                        locator = None
                        for field in await frame.locator("input,textarea").all():
                            if address.value in await field.input_value() and await field.is_visible():
                                locator = field
                                break
                        if locator is None:
                            continue
                    if await locator.count() and await locator.is_visible():
                        await locator.scroll_into_view_if_needed(timeout=1500)
                        path = self.folder / f"step-{step:02}-address-{index}.png"
                        await self.page.screenshot(path=str(path), timeout=4000)
                        address.screenshot = str(path)
                        break
                except Exception:
                    continue
        fingerprint = hashlib.sha256(" ".join(text.lower().split()).encode()).hexdigest()
        observation = Observation(step, self.page.url, await self.page.title(), text, controls,
                                  addresses, str(image_path), fingerprint, self.http_status)
        from dataclasses import asdict
        (self.folder / f"step-{step:02}.json").write_text(json.dumps(asdict(observation), indent=2))
        return observation

    async def click(self, control: dict):
        if not allowed_label(control["label"]):
            raise ValueError("Action rejected by policy")
        frame = self.page.frames[control["frame"]]
        locator = frame.locator(CONTROL_SELECTOR).nth(control["index"])
        # Recheck the label and href in case the DOM changed after observation.
        current = await locator.evaluate("e => ({label:(e.innerText || e.getAttribute('aria-label') || e.getAttribute('title') || ((e.type==='button'||e.type==='submit')?e.value:'') || '').trim().slice(0,120), href:e.tagName==='A'?e.href:null})")
        if current["label"] != control["label"] or current["href"] != control["href"]:
            raise ValueError("Stale control; refused click")
        if current["href"] and not same_origin(self.page.url, current["href"]):
            raise ValueError("Cross-origin action blocked")
        if control["tag"] == "select":
            raise ValueError("Select controls need an explicit network option")
        self.http_status = None
        await locator.click(timeout=6000)
        await self.settle()

    async def follow_observed_link(self, control: dict):
        """Return to a link captured on an earlier page, without guessing URLs."""
        if control.get("tag") != "a" or not allowed_label(control["label"]):
            raise ValueError("Unapproved navigation")
        target = validate_url(control["href"])
        if not same_origin(self.page.url, target):
            raise ValueError("Cross-origin action blocked")
        self.http_status = None
        response = await self.page.goto(target, wait_until="domcontentloaded", timeout=25000)
        self.http_status = response.status if response else None
        await self.settle()

    async def select_network(self, control: dict, value: str):
        if value not in {o["value"] for o in control["options"] if allowed_label(o["label"])}:
            raise ValueError("Unobserved or unsupported network option")
        frame = self.page.frames[control["frame"]]
        locator = frame.locator(CONTROL_SELECTOR).nth(control["index"])
        if await locator.evaluate("e => e.tagName") != "SELECT":
            raise ValueError("Stale select")
        await locator.select_option(value)
        await self.settle()

    async def login(self, credentials: dict) -> bool:
        # Existing disposable research accounts only; never create an account or accept terms.
        if not same_origin(credentials["origin"], self.page.url):
            return False
        for frame in self.page.frames[:12]:
            for form in await frame.locator("form").all():
                password = form.locator('input[type="password"]')
                if await password.count() != 1 or not await password.is_visible():
                    continue
                if await form.locator('input[type="checkbox"],input[type="file"]').count():
                    continue
                username = form.locator('input[type="email"],input[autocomplete="username"],input[name="username"],input[name="email"]')
                buttons = form.get_by_role("button", name=re.compile(r"^(log\s*in|sign\s*in|登录|登入)$", re.I))
                if await username.count() != 1 or await buttons.count() != 1:
                    continue
                await username.fill(credentials["username"])
                await password.fill(credentials["password"])
                await buttons.click()
                await self.settle()
                return True  # Submission, not proof of authentication success.
        return False

    async def close(self):
        import asyncio
        for task in self.pending:
            task.cancel()
        await asyncio.gather(*self.pending, return_exceptions=True)
        await self.context.close()
