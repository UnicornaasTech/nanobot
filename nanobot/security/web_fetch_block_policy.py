"""Pass vs block rules for defended ``web_fetch`` (stages 2 and 3).

Rating rules (machine-enforced)
==============================

**A — Domain tier (handled in ``web_fetch_defended_tool`` before postprocess)**
If ``domainTrustEnabled`` and the URL hostname resolves to tier ``blocked``, the fetch
is rejected with ``reason: domain_blocked``. No page body is returned.

**B — Stage-2 structural (pattern + HTML sanitizer)**
After ``sanitize_web_fetch_text``, if the result is **not** ``skipped`` (i.e. the tier was
scanned: not ``trusted`` / sanitizer-blocked-skip for ``blocked`` tier body path), then:

- **BLOCK** if ``severity >= structuralBlockMinSeverity`` **OR**
  ``detection_count >= structuralBlockMinDetectionCount``
  (OR semantics; both thresholds come from ``blockPolicy`` in ``web-fetch-defense.json``).

When ``skipped`` is True (trusted tier, or blocked-tier skip), stage B does not block.

Defaults: ``structuralBlockMinSeverity = 9``, ``structuralBlockMinDetectionCount = 3``
(roughly “several weighted injection-style hits”).

**C — Stage-3 LLM classifier**
Only if ``safetyScan.enabled`` **and** the classifier is **invokable** (non-empty effective
API key after env fallback, non-empty ``baseUrl``, non-empty ``model``). If not invokable,
stage C is skipped entirely (structural rules still apply); log at info that the LLM gate
was skipped.

When invokable, after a real HTTP round-trip:

- **BLOCK** if ``verdict == "unsafe"``.
- **BLOCK** if ``verdict == "suspicious"`` **and** (
  ``classifier severity >= suspiciousBlockMinSeverity`` **OR** ``confidence == "high"`` ).
- **PASS** if ``verdict == "safe"``.
- **BLOCK** on unusable or failed classifier output: ``scanFailed`` is True, or the scan
  dict indicates parse/HTTP failure (same as ``unknown_scan(..., scan_failed=True)``).

``verdict == "unknown"`` without ``scanFailed`` (e.g. safety enabled in JSON but no API key,
so the HTTP client was never used) does **not** trigger stage C blocking.

Block codes (for logs only; tool output uses ``reason: content_blocked`` except domain).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from nanobot.security.web_fetch_defense_env import WebFetchBlockPolicySettings
from nanobot.security.web_fetch_sanitize import WebFetchSanitizeResult

# Log / internal codes (domain_blocked uses tool JSON reason domain_blocked).
STRUCTURAL_SCORE = "structural_score"
LLM_UNSAFE = "llm_unsafe"
LLM_SUSPICIOUS = "llm_suspicious"
LLM_UNUSABLE_OR_FAILED = "llm_unusable_or_failed"


@dataclass(frozen=True)
class BlockPolicyOutcome:
    """Whether fetch content may be returned to the agent."""

    blocked: bool
    code: str = ""

    @staticmethod
    def allow() -> BlockPolicyOutcome:
        return BlockPolicyOutcome(blocked=False)

    @staticmethod
    def block(code: str) -> BlockPolicyOutcome:
        return BlockPolicyOutcome(blocked=True, code=code)


def structural_outcome(
    sr: WebFetchSanitizeResult,
    policy: WebFetchBlockPolicySettings,
) -> BlockPolicyOutcome:
    """Stage B: block on pattern/HTML sanitizer score when scanning ran."""
    if sr.skipped:
        return BlockPolicyOutcome.allow()
    if sr.severity >= policy.structural_block_min_severity:
        return BlockPolicyOutcome.block(STRUCTURAL_SCORE)
    if sr.detection_count >= policy.structural_block_min_detection_count:
        return BlockPolicyOutcome.block(STRUCTURAL_SCORE)
    return BlockPolicyOutcome.allow()


def llm_classifier_outcome(
    scan: dict[str, Any],
    policy: WebFetchBlockPolicySettings,
) -> BlockPolicyOutcome:
    """Stage C: block on classifier verdict (caller must only pass scans from an invoked call)."""
    if scan.get("scanFailed"):
        return BlockPolicyOutcome.block(LLM_UNUSABLE_OR_FAILED)
    verdict = scan.get("verdict")
    if verdict == "unsafe":
        return BlockPolicyOutcome.block(LLM_UNSAFE)
    if verdict == "suspicious":
        sev = scan.get("severity")
        conf = scan.get("confidence")
        bad_sev = isinstance(sev, int) and sev >= policy.suspicious_block_min_severity
        high_conf = conf == "high"
        if bad_sev or high_conf:
            return BlockPolicyOutcome.block(LLM_SUSPICIOUS)
        return BlockPolicyOutcome.allow()
    if verdict == "safe":
        return BlockPolicyOutcome.allow()
    # Unknown without scanFailed: treat as pass (e.g. classifier not invoked).
    return BlockPolicyOutcome.allow()
