"""Review saved evidence without visiting websites again."""

import argparse
import asyncio
import copy
import hashlib
import json
import os
import shutil
from dataclasses import fields
from pathlib import Path
from types import SimpleNamespace

from .addresses import infer_role
from .judge import Judge, RequestPacer, guarded_verdict
from .models import Address, Observation
from .output import summarize, write_outputs
from .report import render
from .runner import save_json

ASSESSMENT_FIELDS = (
    "classification",
    "confidence",
    "reasoning",
    "evidence",
    "needs_review",
    "analysis_mode",
    "errors",
    "input_tokens",
    "output_tokens",
)


def load_observations(record):
    allowed = {field.name for field in fields(Observation)}
    observations = []

    for page in record.get("observations", []):
        values = {
            key: value
            for key, value in page.items()
            if key in allowed
        }
        values["addresses"] = [
            Address(**address)
            for address in page.get("addresses", [])
        ]
        observations.append(Observation(**values))

    return observations


def fix_roles(record):
    groups = [record.get("address_candidates", [])]
    groups.extend(
        page.get("addresses", [])
        for page in record.get("observations", [])
    )

    for group in groups:
        for address in group:
            address["role"] = infer_role(
                address["value"],
                address.get("context", ""),
            )

    record["crypto_addresses"] = [
        copy.deepcopy(address)
        for address in record.get("address_candidates", [])
        if record["classification"] == "SCAM"
    ]


def portable_screenshots(record, source_folder, output):
    """Copy referenced screenshots from within the original run folder."""
    items = (
        record.get("address_candidates", [])
        + record.get("crypto_addresses", [])
    )

    for page in record.get("observations", []):
        items.append(page)
        items.extend(page.get("addresses", []))

    missing = set()
    source_root = source_folder.resolve()

    for item in items:
        screenshot = item.get("screenshot")
        if not screenshot:
            continue

        path = Path(screenshot).resolve()

        try:
            relative = path.relative_to(source_root)
        except ValueError:
            item["screenshot"] = None
            missing.add(
                "Screenshot path was outside the original run folder"
            )
            continue

        if not path.is_file():
            item["screenshot"] = None
            missing.add("Referenced screenshot file was unavailable")
            continue

        destination = output / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, destination)
        item["screenshot"] = str(destination)

    return sorted(missing)


async def repair(
    source,
    output,
    use_llm=False,
    provider="gemini",
    interval=6,
):
    source = Path(source)
    output = Path(output)

    if output.resolve() == source.parent.resolve():
        raise ValueError(
            "Choose a different output folder to preserve the original run"
        )

    if (output / "results.json").exists():
        raise ValueError(
            "Output already contains results; choose a fresh folder"
        )

    original = json.loads(source.read_text())

    if not isinstance(original, list) or not original:
        raise ValueError("Expected a nonempty list of saved results")

    urls = [record["url"] for record in original]
    if len(urls) != len(set(urls)):
        raise ValueError("Duplicate input URLs")

    model = None

    if use_llm:
        if provider not in {"gemini", "openai"}:
            raise ValueError("Unsupported LLM provider")
        if not 0 <= interval <= 60:
            raise ValueError("Interval must be 0–60 seconds")

        prefix = provider.upper()
        if not os.environ.get(prefix + "_API_KEY"):
            raise ValueError(f"Set {prefix}_API_KEY locally")

        default = (
            "gemini-3.1-flash-lite"
            if provider == "gemini"
            else "gpt-4.1-mini"
        )
        model = os.environ.get(prefix + "_MODEL") or default

    pacer = RequestPacer(interval) if use_llm else None

    output.mkdir(parents=True, exist_ok=True)
    save_json(output / "original-results.json", original)
    save_json(
        output / "repair-config.json",
        {
            "source_sha256": hashlib.sha256(
                source.read_bytes()
            ).hexdigest(),
            "model": model,
            "provider": provider if use_llm else None,
            "llm_interval": interval,
            "recrawled": False,
        },
    )

    revised = []

    for original_record in original:
        record = copy.deepcopy(original_record)
        record["previous_assessment"] = {
            key: original_record.get(key)
            for key in ASSESSMENT_FIELDS
        }
        observations = load_observations(record)

        if not observations:
            record.update(
                classification="NOT_SCAM",
                confidence=0.0,
                evidence=[],
                reasoning=(
                    "No site evidence was captured. "
                    "Legitimacy is unresolved."
                ),
                needs_review=True,
                analysis_mode="not_observed",
                input_tokens=0,
                output_tokens=0,
            )

        elif use_llm:
            judge = Judge(
                model,
                max_calls=1,
                provider=provider,
                navigation=False,
                pacer=pacer,
            )

            try:
                verdict = await judge.classify(observations)
                record["analysis_mode"] = judge.verdict_source

                record["errors"] = [
                    error
                    for error in record.get("errors", [])
                    if not error.startswith("LLM failure:")
                    and not error.startswith(
                        "Final classification timed out"
                    )
                ] + judge.errors

                record["input_tokens"] = judge.input_tokens
                record["output_tokens"] = judge.output_tokens

            finally:
                await judge.close()

            record.update(
                classification=verdict.classification,
                confidence=verdict.confidence,
                reasoning=verdict.reasoning,
                evidence=verdict.evidence,
                needs_review=True,
            )

        else:
            answer = SimpleNamespace(
                classification=record["classification"],
                confidence=record["confidence"],
                evidence=record.get("evidence", []),
                evidence_kind="insufficient",
            )
            verdict = guarded_verdict(observations, answer)

            record.update(
                classification=verdict.classification,
                confidence=verdict.confidence,
                reasoning=verdict.reasoning,
                evidence=verdict.evidence,
                needs_review=True,
                analysis_mode="offline_guarded",
                input_tokens=0,
                output_tokens=0,
            )

        fix_roles(record)
        record["quality_notes"] = portable_screenshots(
            record,
            source.parent,
            output,
        )

        revised.append(record)
        save_json(output / "results.json", revised)

        print(
            f"{len(revised)}/{len(original)} "
            f"{record['classification']} "
            f"{record['analysis_mode']} "
            f"{record['url']}",
            flush=True,
        )

    summary = summarize(revised, urls)

    if summary["structural_issues"]:
        raise ValueError(
            "Revised results failed structural validation"
        )

    write_outputs(revised, output, urls)
    render(revised, output)

    print(json.dumps(summary, indent=2))
    print("Original scan preserved. Reviewed output:", output)
    print(
        "All revised decisions require review; "
        "this does not establish accuracy."
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--llm", action="store_true")
    parser.add_argument(
        "--provider",
        choices=["gemini", "openai"],
        default="gemini",
    )
    parser.add_argument("--interval", type=float, default=6)
    args = parser.parse_args()

    if not 0 <= args.interval <= 60:
        parser.error("Interval must be 0–60 seconds")

    try:
        asyncio.run(
            repair(
                args.results,
                args.output,
                args.llm,
                args.provider,
                args.interval,
            )
        )
    except (ValueError, OSError, KeyError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
