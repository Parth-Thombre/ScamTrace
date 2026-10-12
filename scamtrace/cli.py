import argparse
import asyncio
import json
import os
from pathlib import Path

from .output import summarize, write_outputs
from .policy import validate_url
from .report import render


def read_urls(path):
    urls = []

    for line in Path(path).read_text().splitlines():
        value = line.strip()

        if value and not value.startswith("#"):
            validate_url(value)
            if value not in urls:
                urls.append(value)

    if not urls:
        raise ValueError("Target file is empty")

    return urls


def main():
    parser = argparse.ArgumentParser(
        description="ScamTrace: evidence-first website analysis"
    )
    commands = parser.add_subparsers(
        dest="command",
        required=True,
    )

    analyze = commands.add_parser("run")
    analyze.add_argument("--targets", default="targets.txt")
    analyze.add_argument(
        "--output",
        type=Path,
        default=Path("outputs/run"),
    )
    analyze.add_argument("--limit", type=int)
    analyze.add_argument("--steps", type=int, default=8)
    analyze.add_argument("--concurrency", type=int, default=3)
    analyze.add_argument("--timeout", type=int, default=120)
    analyze.add_argument(
        "--llm",
        action="store_true",
        help="Enable LLM API calls (may incur charges)",
    )
    analyze.add_argument(
        "--provider",
        choices=["openai", "gemini"],
        default="openai",
    )
    analyze.add_argument(
        "--llm-navigation",
        action="store_true",
        help=(
            "Also ask the model to choose browser actions "
            "(uses more requests)"
        ),
    )
    analyze.add_argument(
        "--llm-interval",
        type=float,
        default=15,
        help=(
            "Minimum seconds between model request starts, "
            "0–30 (default 15)"
        ),
    )
    analyze.add_argument("--resume", action="store_true")
    analyze.add_argument(
        "--credentials",
        type=Path,
        help="Explicitly authorized disposable research accounts",
    )

    report = commands.add_parser("report")
    report.add_argument("results", type=Path)
    report.add_argument("--output", type=Path)

    audit = commands.add_parser(
        "audit",
        help=(
            "Check saved results and summarize coverage "
            "without browsing or API calls"
        ),
    )
    audit.add_argument("results", type=Path)
    audit.add_argument("--targets", default="targets.txt")
    audit.add_argument("--output", type=Path)

    args = parser.parse_args()

    try:
        if args.command == "audit":
            results = json.loads(args.results.read_text())
            targets = read_urls(args.targets)
            summary = summarize(results, targets)

            write_outputs(
                results,
                args.output or args.results.parent,
                targets,
            )

            print(json.dumps(summary, indent=2))

            if summary["structural_issues"]:
                raise ValueError(
                    "Saved results failed structural validation"
                )

            return

        if args.command == "report":
            output = args.output or args.results.parent
            render(json.loads(args.results.read_text()), output)
            print(f"Report: {output / 'report.html'}")
            return

        if not (
            1 <= args.steps <= 30
            and 1 <= args.concurrency <= 8
            and 20 <= args.timeout <= 600
        ):
            raise ValueError(
                "Steps must be 1–30, concurrency 1–8, "
                "timeout 20–600 seconds"
            )

        if args.limit is not None and args.limit < 1:
            raise ValueError("Limit must be positive")

        if not 0 <= args.llm_interval <= 30:
            raise ValueError(
                "LLM interval must be 0–30 seconds"
            )

        urls = read_urls(args.targets)
        if args.limit:
            urls = urls[:args.limit]

        model = None

        if args.llm:
            prefix = args.provider.upper()

            if not os.environ.get(prefix + "_API_KEY"):
                raise ValueError(
                    f"Set {prefix}_API_KEY in your environment, "
                    "never in source code"
                )

            default_model = (
                "gemini-3.1-flash-lite"
                if args.provider == "gemini"
                else "gpt-4.1-mini"
            )

            model = (
                os.environ.get(prefix + "_MODEL")
                or default_model
            )

        endpoint = os.environ.get("BROWSER_WS_ENDPOINT")

        if not endpoint:
            raise ValueError(
                "Use Docker Compose: the scanner requires "
                "the isolated browser service"
            )

        credentials = (
            json.loads(args.credentials.read_text())
            if args.credentials
            else None
        )

        if credentials:
            if not isinstance(credentials, list):
                raise ValueError(
                    "Credentials must be a list of research account objects"
                )

            for account in credentials:
                validate_url(account["origin"])

                if not all(
                    isinstance(account[key], str)
                    for key in ("origin", "username", "password")
                ):
                    raise ValueError("Invalid research account")

        from .runner import run

        results = asyncio.run(
            run(
                urls,
                args.output,
                endpoint,
                model,
                args.steps,
                args.concurrency,
                args.timeout,
                args.resume,
                credentials,
                args.provider,
                args.llm_navigation,
                args.llm_interval,
            )
        )

        render(results, args.output)
        write_outputs(results, args.output, urls)

        print(
            f"Saved {len(results)} results and report to {args.output}"
        )

    except (ValueError, OSError, KeyError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()