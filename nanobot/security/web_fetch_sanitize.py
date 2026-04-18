"""Stage-2 structural sanitization for web_fetch (Fireclaw InputSanitizer port)."""

from __future__ import annotations

import json
import re
import unicodedata
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources
from typing import Any, Literal

from loguru import logger

TrustTier = Literal["trusted", "neutral", "suspicious", "blocked"]

_RE_GIM = re.IGNORECASE | re.MULTILINE
_RE_GIS = re.IGNORECASE | re.DOTALL


@dataclass
class WebFetchSanitizeResult:
    sanitized: str
    severity: int
    detection_count: int
    skipped: bool = False


class PatternMatcher:
    """Compiles Fireclaw patterns.json regex categories."""

    def __init__(self, patterns: dict[str, Any]) -> None:
        self.patterns = patterns
        self._compiled: dict[str, dict[str, re.Pattern[str]]] = {
            "structural": {},
            "injection_signatures": {},
            "output_signatures": {},
            "exfiltration": {},
            "canary_patterns": {},
        }
        skip = frozenset({"severity_weights", "metadata"})
        for category, pattern_map in patterns.items():
            if category in skip or not isinstance(pattern_map, dict):
                continue
            bucket = self._compiled.get(category)
            if bucket is None:
                continue
            for name, pattern in pattern_map.items():
                if not isinstance(pattern, str):
                    continue
                try:
                    bucket[name] = re.compile(pattern, _RE_GIM)
                except re.error:
                    continue

    def scan(self, text: str, categories: list[str]) -> list[dict[str, Any]]:
        matches: list[dict[str, Any]] = []
        weights = self.patterns.get("severity_weights") or {}
        for category in categories:
            weight = int(weights.get(category, 1)) if isinstance(weights.get(category), (int, float)) else 1
            for name, regex in self._compiled.get(category, {}).items():
                for m in regex.finditer(text):
                    matches.append(
                        {
                            "category": category,
                            "name": name,
                            "match": m.group(0),
                            "position": m.start(),
                            "severity": weight,
                        }
                    )
        return matches

    @staticmethod
    def calculate_severity(matches: list[dict[str, Any]]) -> int:
        return sum(int(m.get("severity", 0)) for m in matches)


class UnicodeNormalizer:
    def __init__(self) -> None:
        self._homoglyphs: dict[str, str] = {
            "а": "a",
            "е": "e",
            "о": "o",
            "р": "p",
            "с": "c",
            "у": "y",
            "х": "x",
            "А": "A",
            "В": "B",
            "Е": "E",
            "К": "K",
            "М": "M",
            "Н": "H",
            "О": "O",
            "Р": "P",
            "С": "C",
            "Т": "T",
            "Х": "X",
            "α": "a",
            "β": "b",
            "γ": "y",
            "ε": "e",
            "ι": "i",
            "ο": "o",
            "υ": "u",
            "Α": "A",
            "Β": "B",
            "Ε": "E",
            "Ι": "I",
            "Κ": "K",
            "Μ": "M",
            "Ν": "N",
            "Ο": "O",
            "Ρ": "P",
            "Τ": "T",
            "Υ": "Y",
            "Ζ": "Z",
        }

    def normalize(self, text: str) -> str:
        s = unicodedata.normalize("NFD", text)
        s = re.sub(r"[\u0300-\u036F]", "", s)
        s = unicodedata.normalize("NFC", s)
        s = re.sub(r"[\u200B\u200C\u200D\uFEFF\u2060\u2062\u2063\u2064]", "", s)
        s = re.sub(r"[\u202A-\u202E\u2066-\u2069]", "", s)
        s = re.sub(r"[\u00AD\u00A0]", " ", s)
        s = "".join(self._homoglyphs.get(c, c) for c in s)
        s = re.sub(r"[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]", "", s)
        s = s.replace("\uFFFD", "")
        return s


class HTMLAnalyzer:
    def __init__(self) -> None:
        self._hidden_patterns: dict[str, re.Pattern[str]] = {
            "display": re.compile(r"display:\s*none", _RE_GIM),
            "visibility": re.compile(r"visibility:\s*hidden", _RE_GIM),
            "opacity": re.compile(r"opacity:\s*0", _RE_GIM),
            "fontSize": re.compile(r"font-size:\s*0(px|pt|em|rem)?", _RE_GIM),
            "color": re.compile(
                r"color:\s*rgba?\(\s*\d+\s*,\s*\d+\s*,\s*\d+\s*,\s*0\s*\)", _RE_GIM
            ),
            "positionLeft": re.compile(r"left:\s*-\d+", _RE_GIM),
            "positionTop": re.compile(r"top:\s*-\d+", _RE_GIM),
            "overflow": re.compile(r"overflow:\s*hidden", _RE_GIM),
            "clip": re.compile(r"clip:\s*rect\(0,?\s*0,?\s*0,?\s*0\)", _RE_GIM),
        }

    def analyze_hidden(self, html: str) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        for name, pat in self._hidden_patterns.items():
            m = pat.findall(html)
            if m:
                findings.append(
                    {
                        "type": "hidden_css",
                        "technique": name,
                        "count": len(m),
                        "severity": 2,
                    }
                )
        comment_match = re.findall(r"<!--(.*?)-->", html, flags=_RE_GIS)
        if comment_match:
            suspicious = [
                c
                for c in comment_match
                if any(
                    k in c.lower()
                    for k in ("instruction", "system", "command", "prompt")
                )
            ]
            if suspicious:
                findings.append(
                    {
                        "type": "hidden_comment",
                        "technique": "suspicious_html_comments",
                        "count": len(suspicious),
                        "severity": 3,
                    }
                )
        data_uri_match = re.findall(r"data:[^,]+,", html)
        if len(data_uri_match) > 3:
            findings.append(
                {
                    "type": "data_uri",
                    "technique": "excessive_data_uris",
                    "count": len(data_uri_match),
                    "severity": 2,
                }
            )
        return findings

    def strip_html(self, html: str) -> str:
        text = re.sub(r"<script[^>]*>.*?</script>", "", html, flags=_RE_GIS)
        text = re.sub(r"<style[^>]*>.*?</style>", "", text, flags=_RE_GIS)
        text = re.sub(r"<[^>]+>", " ", text)
        text = text.replace("&lt;", "<")
        text = text.replace("&gt;", ">")
        text = text.replace("&amp;", "&")
        text = text.replace("&quot;", '"')
        text = text.replace("&#39;", "'")
        text = text.replace("&nbsp;", " ")

        def _num_entity(m: re.Match[str]) -> str:
            try:
                return chr(int(m.group(1)))
            except (ValueError, OverflowError):
                return m.group(0)

        text = re.sub(r"&#(\d+);", _num_entity, text)
        return text


@lru_cache(maxsize=1)
def _pattern_matcher() -> PatternMatcher:
    raw = resources.files("nanobot.data").joinpath("web_fetch_patterns.json").read_bytes()
    data = json.loads(raw.decode("utf-8"))
    return PatternMatcher(data)


def _preview_for_log(raw: str, max_len: int = 120) -> str:
    one_line = raw.replace("\n", "\\n").replace("\r", "\\r")
    if len(one_line) > max_len:
        return f"{one_line[:max_len]}…"
    return one_line


def _debug_log_pattern_hits(
    url: str | None,
    phase: str,
    hits: list[dict[str, Any]],
) -> None:
    u = url if url else "-"
    for h in hits:
        match = h.get("match", "")
        preview = _preview_for_log(match) if isinstance(match, str) else repr(match)
        logger.debug(
            "web_fetch_defense pattern_hit url={} phase={} category={} name={} "
            "severity={} position={} match_preview={}",
            u,
            phase,
            h.get("category"),
            h.get("name"),
            h.get("severity"),
            h.get("position"),
            preview,
        )


def sanitize_web_fetch_text(
    text: str,
    trust_tier: TrustTier,
    max_chars: int,
    *,
    url: str | None = None,
) -> WebFetchSanitizeResult:
    """Run Fireclaw-style InputSanitizer pipeline.

    Structural regex categories are scored on the **raw** input; ``injection_signatures``
    (and ``exfiltration`` when trust intensity is high) are scored only on the **final**
    sanitized string (post strip, cleanup, truncation, and terminal redaction).
    """
    if trust_tier == "trusted":
        return WebFetchSanitizeResult(sanitized=text, severity=0, detection_count=0, skipped=True)
    if trust_tier == "blocked":
        return WebFetchSanitizeResult(sanitized=text, severity=0, detection_count=0, skipped=True)

    intensity = {"trusted": 0.3, "neutral": 1.0, "suspicious": 1.5, "blocked": 2.0}.get(
        trust_tier, 1.0
    )

    matcher = _pattern_matcher()
    normalizer = UnicodeNormalizer()
    html_analyzer = HTMLAnalyzer()
    detections: list[dict[str, Any]] = []

    # Structural patterns (HTML layout, hidden markup, etc.) score on the raw input.
    raw_structural_hits = matcher.scan(text, ["structural"])
    _debug_log_pattern_hits(url, "raw_input", raw_structural_hits)
    detections.extend(raw_structural_hits)

    sanitized = text
    if "<" in sanitized:
        sanitized = html_analyzer.strip_html(sanitized)

    if intensity >= 1.0:
        sanitized = normalizer.normalize(sanitized)

    sanitized = re.sub(r"<!--.*?-->", "", sanitized, flags=_RE_GIS)
    sanitized = re.sub(
        r"data:[^,]+;base64,[A-Za-z0-9+/=]+", "[BASE64_REMOVED]", sanitized
    )
    sanitized = re.sub(
        r"[A-Za-z0-9+/]{100,}={0,2}", "[LONG_BASE64_REMOVED]", sanitized
    )
    sanitized = re.sub(r"[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]", "", sanitized)

    ws_threshold = 3 if intensity <= 1.0 else 2
    sanitized = re.sub(rf"[ \t]{{{ws_threshold},}}", "  ", sanitized)
    sanitized = re.sub(r"\n{4,}", "\n\n\n", sanitized)

    if intensity > 1.0:
        sanitized = re.sub(r"%[0-9a-fA-F]{2}", "", sanitized)

    truncated = False
    if len(sanitized) > max_chars:
        sanitized = sanitized[:max_chars] + "\n\n[... truncated ...]"
        truncated = True

    if intensity > 1.5:
        sanitized = re.sub(
            r"\b(function|lambda|eval|exec)\s*\(", "[CODE_REMOVED]", sanitized, flags=re.I
        )

    # Injection (and exfiltration for higher trust intensity) score on final sanitized text only.
    injection_categories = ["injection_signatures"]
    if intensity > 1.0:
        injection_categories.append("exfiltration")
    post_sanitize_hits = matcher.scan(sanitized, injection_categories)
    _debug_log_pattern_hits(url, "sanitized_input", post_sanitize_hits)
    detections.extend(post_sanitize_hits)

    if truncated:
        trunc_hit = {
            "category": "structural",
            "name": "truncation",
            "match": f"Content truncated to {max_chars} chars",
            "position": 0,
            "severity": 0,
        }
        _debug_log_pattern_hits(url, "sanitized_input", [trunc_hit])
        detections.append(trunc_hit)

    severity = PatternMatcher.calculate_severity(detections)
    return WebFetchSanitizeResult(
        sanitized=sanitized,
        severity=severity,
        detection_count=len(detections),
        skipped=False,
    )
