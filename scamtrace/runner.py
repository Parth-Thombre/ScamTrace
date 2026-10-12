import asyncio
import hashlib
import json
import re
import time
from pathlib import Path

from .addresses import deduplicate
from .browser import InvestigatorBrowser
from .judge import Judge, RequestPacer, baseline
from .models import Result
from .policy import same_origin
from .connectivity import diagnose


def browser_error(exc):
    # Preserve Chromium's diagnostic code without storing URLs, form values,
    # credentials, or the full exception/call log.
    code = re.search(r"net::ERR_[A-Z0-9_]+", str(exc))
    suffix = f" ({code.group()})" if code else ""
    return type(exc).__name__ + suffix


def save_json(path: Path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(data, indent=2, ensure_ascii=False))
    temporary.replace(path)


def control_key(url, control):
    # The same navigation link can appear on several pages. Try its target
    # once; buttons and network selectors still depend on their source page.
    if control["tag"] == "a" and control.get("href"):
        return ("link", control["href"])
    return (url, control["frame"], control["label"], control["href"])


async def investigate(browser, url, folder, model, steps=8, timeout=120, credentials=None,
                      provider="openai", llm_navigation=False, pacer=None):
    result = Result(url=url, analysis_mode="not_observed")
    judge = Judge(model, max_calls=steps + 1 if llm_navigation else 1,
                  provider=provider, navigation=llm_navigation, pacer=pacer)
    context = await browser.new_context(accept_downloads=False, service_workers="block",
                                        viewport={"width": 1280, "height": 900}, permissions=[])
    investigator = InvestigatorBrowser(context, folder)
    attempted = set()
    visited = set()
    frontier = {}
    login_attempted = False
    try:
        async with asyncio.timeout(timeout):
            await investigator.start(url)
            for step in range(steps):
                observation = await investigator.observe(step)
                visited.add(observation.url)
                result.observations.append(observation)
                result.address_candidates.extend(observation.addresses)
                if observation.status_code and observation.status_code >= 400:
                    result.status = "http_error"
                    break
                if credentials and not login_attempted:
                    submitted = await investigator.login(credentials)
                    if submitted:
                        login_attempted = True
                        result.actions.append({"step": step, "action": "login", "status": "submitted"})
                        continue
                for control in observation.controls:
                    key = control_key(observation.url, control)
                    if control["tag"] == "a" and control.get("href"):
                        frontier.setdefault(control["href"], {**control, "observed_from": observation.url})
                    if control["tag"] == "select":
                        control["options"] = [o for o in control["options"]
                                              if (key, o["value"]) not in attempted]
                    control["attempted"] = (key in attempted
                        or (control["tag"] == "a" and control.get("href") in visited)
                        or (control["tag"] == "select" and not control["options"]))
                chosen = await judge.choose(observation, result.actions)
                if chosen == -1:
                    remaining = [c for href, c in frontier.items()
                                 if href not in visited and ("link", href) not in attempted
                                 and same_origin(observation.url, href)]
                    if not remaining:
                        break
                    target = min(remaining, key=lambda c: (
                        not bool(re.search(r"deposit|recharge|充值|入金", c["label"], re.I)),
                        not bool(re.search(r"plans?|pricing|investment", c["label"], re.I))))
                    attempted.add(("link", target["href"]))
                    action = {"step": step, "action": "follow_observed_link",
                              "label": target["label"], "from_url": observation.url,
                              "observed_from": target["observed_from"], "to_url": target["href"]}
                    try:
                        await investigator.follow_observed_link(target)
                        action["status"] = "completed"
                    except Exception as exc:
                        action["status"] = "failed"
                        action["error"] = type(exc).__name__
                    result.actions.append(action)
                    continue
                control = observation.controls[chosen]
                key = control_key(observation.url, control)
                action = {"step": step, "label": control["label"], "from_url": observation.url}
                try:
                    if control["tag"] == "select":
                        from .policy import allowed_label
                        options = [o for o in control["options"] if allowed_label(o["label"])]
                        if not options:
                            attempted.add(key)
                            continue
                        option = options[0]
                        attempted.add((key, option["value"]))
                        action["option"] = option["label"]
                        await investigator.select_network(control, option["value"])
                    else:
                        attempted.add(key)
                        await investigator.click(control)
                    action["status"] = "completed"
                except Exception as exc:
                    action["status"] = "failed"
                    action["error"] = type(exc).__name__
                result.actions.append(action)
            else:
                # Capture the last action's result, even if the step budget is exhausted.
                observation = await investigator.observe(steps)
                result.observations.append(observation)
                result.address_candidates.extend(observation.addresses)
            if result.status == "pending":
                result.status = "analyzed"
    except TimeoutError:
        result.status = "timeout"
        result.errors.append("Per-site time budget exhausted")
    except Exception as exc:
        result.status = "unreachable" if not result.observations else "partial"
        error = browser_error(exc)
        result.errors.append("Browser failure: " + error)
        try:
            async with asyncio.timeout(6):
                result.access_diagnostic = await asyncio.to_thread(diagnose, url, error)
        except TimeoutError:
            result.access_diagnostic = "diagnostic_timeout"
    finally:
        try:
            await investigator.close()
        except Exception as exc:
            result.errors.append("Browser cleanup: " + type(exc).__name__)
    if result.observations:
        try:
            async with asyncio.timeout(45):
                verdict = await judge.classify(result.observations)
        except TimeoutError:
            verdict = baseline(result.observations)
            judge.verdict_source = "rules_fallback"
            result.errors.append("Final classification timed out; used rule baseline")
        result.analysis_mode = judge.verdict_source
        result.classification = verdict.classification
        result.confidence = verdict.confidence
        result.reasoning = verdict.reasoning
        result.evidence = verdict.evidence
        result.needs_review = verdict.needs_review or result.status != "analyzed"
    else:
        result.reasoning = "Site could not be observed. Binary placeholder is NOT_SCAM; legitimacy is unknown."
    result.address_candidates = deduplicate(result.address_candidates)
    if result.classification == "SCAM":
        result.crypto_addresses = result.address_candidates
    result.errors.extend(judge.errors + investigator.warnings)
    result.input_tokens, result.output_tokens = judge.input_tokens, judge.output_tokens
    await judge.close()
    return result


async def run(urls, output: Path, endpoint, model=None, steps=8, concurrency=3,
              timeout=120, resume=False, credentials=None, provider="openai",
              llm_navigation=False, llm_interval=15):
    from playwright.async_api import async_playwright

    semaphore = asyncio.Semaphore(concurrency)
    pacer = RequestPacer(llm_interval) if model else None
    run_config = {"version": 3, "model": model, "steps": steps, "timeout": timeout,
                  "authentication": bool(credentials)}
    if model:
        run_config["provider"] = provider
        run_config["llm_navigation"] = llm_navigation
        run_config["llm_interval"] = llm_interval
    config_path = output / "run-config.json"
    if resume and config_path.exists() and json.loads(config_path.read_text()) != run_config:
        raise ValueError("Resume configuration differs; use a fresh output directory")
    save_json(config_path, run_config)
    async with async_playwright() as playwright:
        browser = await playwright.chromium.connect(endpoint, timeout=30000)
        async def worker(url):
            identifier = hashlib.sha256(url.encode()).hexdigest()[:16]
            folder = output / "evidence" / identifier
            checkpoint = output / "checkpoints" / f"{identifier}.json"
            if resume and checkpoint.exists():
                cached = json.loads(checkpoint.read_text())
                if cached["url"] == url and cached["status"] == "analyzed":
                    return cached
            async with semaphore:
                started = time.monotonic()
                account = next((c for c in (credentials or []) if same_origin(c["origin"], url)), None)
                try:
                    result = await investigate(browser, url, folder, model, steps, timeout,
                                               account, provider, llm_navigation, pacer)
                    data = result.to_dict()
                except Exception as exc:
                    data = Result(url=url, status="error", errors=[type(exc).__name__]).to_dict()
                data["elapsed_seconds"] = round(time.monotonic() - started, 2)
                save_json(checkpoint, data)
                print(f"{data['classification']:8} {data['status']:12} {url}", flush=True)
                return data
        try:
            results = await asyncio.gather(*(worker(url) for url in urls))
        finally:
            await browser.close()
    save_json(output / "results.json", results)
    return results
