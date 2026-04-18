#!/usr/bin/env python3
"""Fetch a URL with the same defended ``WebFetchTool`` the agent uses (monkey-patch applied).

Run from the repo root with the package importable, for example::

    python scripts/defended_web_fetch.py https://example.com/
    python scripts/defended_web_fetch.py https://example.com/ --pretty

Defense must be enabled (``patchEnabled`` in ``web-fetch-defense.json`` next to your
``config.json``, or ``NANOBOT_WEB_FETCH_DEFENSE=1``). Otherwise this prints a warning
and uses the vanilla tool.

Withheld pages match other ``web_fetch`` errors: JSON with ``error``, ``url``, and
``reason`` set to ``content_blocked`` (no page body). Domain tier blocks still use
``reason: domain_blocked``.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys


def _print_output(out: object, *, pretty: bool) -> None:
    if isinstance(out, list):
        text = json.dumps(out, ensure_ascii=False, indent=2 if pretty else None)
        print(text)
        return
    if isinstance(out, str):
        if pretty:
            try:
                obj = json.loads(out)
            except json.JSONDecodeError:
                print(out)
            else:
                print(json.dumps(obj, ensure_ascii=False, indent=2))
        else:
            print(out)
        return
    print(out)


def _exit_code_for_result(out: object) -> int:
    if isinstance(out, str):
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            return 0
        if isinstance(data, dict) and data.get("error"):
            return 1
    return 0


async def _run(
    url: str,
    *,
    extract_mode: str,
    max_chars: int | None,
    proxy: str | None,
) -> object:
    from nanobot.agent.tools.web import WebFetchTool

    tool = WebFetchTool(proxy=proxy)
    return await tool.execute(url, extractMode=extract_mode, maxChars=max_chars)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run nanobot web_fetch after applying the defended-tool monkey-patch.",
    )
    parser.add_argument("url", help="http(s) URL to fetch")
    parser.add_argument(
        "--max-chars",
        type=int,
        default=None,
        metavar="N",
        help="Max characters for extracted text (default: 50000)",
    )
    parser.add_argument(
        "--extract-mode",
        choices=("markdown", "text"),
        default="markdown",
        help="Readability fallback mode when Jina is unavailable",
    )
    parser.add_argument("--proxy", default=None, metavar="URL", help="HTTP(S) proxy for fetches")
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON responses (no effect on non-JSON output)",
    )
    args = parser.parse_args()

    # Import order: bootstrap replaces ``WebFetchTool`` on the web module before we bind it.
    from nanobot.security.bootstrap_web_fetch import apply

    apply()

    from nanobot.agent.tools.web import WebFetchTool

    if not getattr(WebFetchTool, "__nanobot_defended_web_fetch__", False):
        print(
            "Warning: defended monkey-patch is not active. "
            "Enable patchEnabled in web-fetch-defense.json (next to config.json) "
            "or set NANOBOT_WEB_FETCH_DEFENSE=1, then retry.\n"
            "Continuing with the current (vanilla) WebFetchTool.",
            file=sys.stderr,
        )

    out = asyncio.run(
        _run(
            args.url,
            extract_mode=args.extract_mode,
            max_chars=args.max_chars,
            proxy=args.proxy,
        )
    )
    _print_output(out, pretty=args.pretty)
    return _exit_code_for_result(out)


if __name__ == "__main__":
    raise SystemExit(main())
