"""Create a compact submission and an auditable coverage summary."""
from collections import Counter
from pathlib import Path

from .addresses import validate


def summarize(results: list[dict], targets: list[str] | None = None) -> dict:
    urls = [r["url"] for r in results]
    issues = []
    if len(urls) != len(set(urls)):
        issues.append("Duplicate result URLs")
    if targets is not None and set(urls) != set(targets):
        issues.append("Results do not match the target manifest")
    addresses = set()
    for result in results:
        if result["classification"] not in {"SCAM", "NOT_SCAM"}:
            issues.append(f"Invalid classification: {result['url']}")
        corpus = "\n".join(o["text"] for o in result.get("observations", []))
        if any(quote not in corpus for quote in result.get("evidence", [])):
            issues.append(f"Unsupported evidence quote: {result['url']}")
        for address in result.get("address_candidates", []):
            checked = validate(address["value"])
            if not checked or checked[0] != address["network"]:
                issues.append(f"Invalid address candidate: {result['url']}")
            value = address["value"]
            if address["network"] == "EVM" or value.lower().startswith("bc1"):
                value = value.lower()
            addresses.add((address["network"], value))
    return {
        "sites_processed": len(results),
        "statuses": dict(Counter(r["status"] for r in results)),
        "classifications": dict(Counter(r["classification"] for r in results)),
        "analysis_modes": dict(Counter(r.get("analysis_mode", "rules") for r in results)),
        "access_diagnostics": dict(Counter(r.get("access_diagnostic") for r in results
                                          if r.get("access_diagnostic"))),
        "review_required": sum(r["needs_review"] for r in results),
        "address_sightings": sum(len(r.get("address_candidates", [])) for r in results),
        "unique_addresses": len(addresses),
        "scam_address_sightings": sum(len(r.get("crypto_addresses", [])) for r in results),
        "scam_address_roles": dict(Counter(a["role"] for r in results for a in r.get("crypto_addresses", []))),
        "input_tokens": sum(r.get("input_tokens", 0) for r in results),
        "output_tokens": sum(r.get("output_tokens", 0) for r in results),
        "structural_issues": issues,
        "accuracy": "Unmeasured: no independent ground-truth labels supplied",
        "interpretation": "Inaccessible and low-confidence NOT_SCAM records are unresolved, not verified safe",
    }


def write_outputs(results: list[dict], output: Path, targets=None):
    from .runner import save_json
    save_json(output / "summary.json", summarize(results, targets))
    submission = []
    for result in results:
        unique = {}
        for address in result.get("crypto_addresses", []):
            value = address["value"]
            key = value.lower() if address["network"] == "EVM" or value.lower().startswith("bc1") else value
            unique.setdefault((address["network"], key), address)
        submission.append({
            "url": result["url"],
            "classification": result["classification"],
            "crypto_addresses": list(unique.values()),
            "confidence": result["confidence"],
            "reasoning": result["reasoning"],
            "status": result["status"],
            "needs_review": result["needs_review"],
        })
    save_json(output / "submission.json", submission)
    save_json(output / "review_queue.json", [
        {"url": r["url"], "status": r["status"], "reasoning": r["reasoning"],
         "access_diagnostic": r.get("access_diagnostic"), "errors": r["errors"]}
        for r in results if r["needs_review"]
    ])
