"""A portable, escaped HTML report. No JS, CDN, or live requests to scam sites."""
from collections import defaultdict
from html import escape
from pathlib import Path
import os


def render(results: list[dict], output: Path):
    wallets = defaultdict(set)
    roles = defaultdict(set)
    for result in results:
        for address in result["address_candidates"]:
            value = address["value"]
            if address["network"] == "EVM" or value.lower().startswith("bc1"):
                value = value.lower()
            key = (address["network"], value)
            wallets[key].add(result["url"])
            roles[key].add(address["role"])
    shared = [(key, urls) for key, urls in wallets.items() if len(urls) > 1]
    scam_count = sum(r["classification"] == "SCAM" for r in results)
    review_count = sum(r["needs_review"] for r in results)
    content = [f"""<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src 'self' file:; style-src 'unsafe-inline'">
<title>ScamTrace · Investigation report</title><style>
body{{margin:0;background:#f4f5f7;color:#17202e;font:16px/1.6 system-ui,sans-serif}}
main{{max-width:1100px;margin:auto;padding:48px 24px}}h1{{font-size:40px;margin:0}}
.subtitle{{color:#596474}}.stats{{display:flex;gap:16px;flex-wrap:wrap;margin:24px 0}}
.stat,article{{background:white;border:1px solid #dce0e5;border-radius:12px;padding:20px}}
.stat strong{{font-size:28px;display:block}}article{{margin:20px 0}}summary{{cursor:pointer}}
.SCAM{{color:#a22c35}}.NOT_SCAM{{color:#37636d}}code{{overflow-wrap:anywhere}}
td,th{{padding:10px;text-align:left;border-bottom:1px solid #ddd;vertical-align:top}}
table{{width:100%;border-collapse:collapse}}img{{max-width:100%;border:1px solid #ddd}}
.tag{{font-size:13px;border:1px solid #ccc;border-radius:6px;padding:2px 6px}}
blockquote{{border-left:3px solid #9cabbc;margin-left:0;padding-left:16px}}
</style><main><p>TRM CHALLENGE / EVIDENCE REPORT</p><h1>ScamTrace</h1>
<p class="subtitle">Observed evidence, bounded exploration, and leads for human review.</p>
<div class="stats"><div class="stat"><strong>{len(results)}</strong>sites processed</div>
<div class="stat"><strong>{scam_count}</strong>flagged scams</div>
<div class="stat"><strong>{review_count}</strong>need review</div>
<div class="stat"><strong>{len(shared)}</strong>shared address leads</div></div>
<p>NOT_SCAM with low confidence or an inaccessible status means unresolved, not verified safe.
Confidence is subjective. Shared addresses do not prove common ownership; token contracts and
shared service infrastructure can appear on unrelated sites.</p><h2>Shared address leads</h2>"""]
    for (network, value), urls in shared:
        content.append(f"<article><code>{escape(value)}</code> <span class='tag'>{escape(network)}</span>"
                       f"<p>Observed roles: {escape(', '.join(sorted(roles[(network, value)])))}</p><ul>"
                       + "".join(f"<li>{escape(url)}</li>" for url in sorted(urls)) + "</ul></article>")
    if not shared:
        content.append("<p>No repeated validated addresses observed.</p>")
    content.append("<h2>Site investigations</h2>")
    # Surface unresolved cases first: the report doubles as a review queue.
    for result in sorted(results, key=lambda r: (not r["needs_review"], r["confidence"])):
        label = escape(result["classification"])
        content.append(f"<article><h3>{escape(result['url'])}</h3><p><strong class='{label}'>{label}</strong>"
                       f" · confidence {result['confidence']:.0%} · {escape(result['status'])}"
                       + (" · REVIEW REQUIRED" if result["needs_review"] else "") + "</p>"
                       f"<p>{escape(result['reasoning'])}</p>")
        if result.get("access_diagnostic"):
            content.append(f"<p>Access diagnostic: {escape(result['access_diagnostic'])}</p>")
        for quote in result.get("evidence", []):
            content.append(f"<blockquote>{escape(quote)}</blockquote>")
        content.append("<details><summary>Address evidence and exploration history</summary>")
        for address in result["address_candidates"]:
            content.append(f"<p><code>{escape(address['value'])}</code><br>"
                           f"{escape(address['network'])} · {escape(address['validation'])} · "
                           f"{escape(address['role'])} · {escape(address['source'])}<br>"
                           f"Source: {escape(address['page_url'])}</p><blockquote>{escape(address['context'])}</blockquote>")
            path = address.get("screenshot")
            if path:
                relative = os.path.relpath(path, output).replace(os.sep, "/")
                content.append(f'<a href="{escape(relative, quote=True)}">Open contextual screenshot</a>')
        content.append("<ol>")
        for action in result["actions"]:
            content.append(f"<li>{escape(str(action))}</li>")
        content.append("</ol>")
        if result["observations"] and result["observations"][0].get("screenshot"):
            relative = os.path.relpath(result["observations"][0]["screenshot"], output).replace(os.sep, "/")
            content.append(f'<img loading="lazy" alt="First observed page" src="{escape(relative, quote=True)}">')
        for observation in result["observations"]:
            content.append("<details><summary>Observed text</summary>"
                           f"<p>{escape(observation['url'])}</p>"
                           f"<pre style='white-space:pre-wrap'>{escape(observation['text'][:12000])}</pre>"
                           "</details>")
        for error in result["errors"]:
            content.append(f"<p>{escape(error)}</p>")
        content.append("</details></article>")
    content.append("</main></html>")
    output.mkdir(parents=True, exist_ok=True)
    (output / "report.html").write_text("\n".join(content))
