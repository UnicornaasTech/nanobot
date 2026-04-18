"""Unit tests for ``web_fetch_block_policy`` (no network)."""

from __future__ import annotations

from nanobot.security.web_fetch_block_policy import (
    llm_classifier_outcome,
    structural_outcome,
)
from nanobot.security.web_fetch_defense_env import WebFetchBlockPolicySettings
from nanobot.security.web_fetch_sanitize import WebFetchSanitizeResult


def test_structural_skipped_always_passes() -> None:
    policy = WebFetchBlockPolicySettings(
        structural_block_min_severity=1,
        structural_block_min_detection_count=1,
    )
    sr = WebFetchSanitizeResult(sanitized="x", severity=999, detection_count=999, skipped=True)
    assert not structural_outcome(sr, policy).blocked


def test_structural_blocks_on_severity() -> None:
    policy = WebFetchBlockPolicySettings(
        structural_block_min_severity=5,
        structural_block_min_detection_count=100,
    )
    sr = WebFetchSanitizeResult(sanitized="x", severity=5, detection_count=1, skipped=False)
    assert structural_outcome(sr, policy).blocked


def test_structural_blocks_on_detection_count() -> None:
    policy = WebFetchBlockPolicySettings(
        structural_block_min_severity=1000,
        structural_block_min_detection_count=2,
    )
    sr = WebFetchSanitizeResult(sanitized="x", severity=0, detection_count=2, skipped=False)
    assert structural_outcome(sr, policy).blocked


def test_llm_scan_failed_blocks() -> None:
    policy = WebFetchBlockPolicySettings()
    scan = {"verdict": "unknown", "scanFailed": True}
    assert llm_classifier_outcome(scan, policy).blocked


def test_llm_unsafe_blocks() -> None:
    policy = WebFetchBlockPolicySettings()
    scan = {"verdict": "unsafe", "severity": 2, "confidence": "low"}
    assert llm_classifier_outcome(scan, policy).blocked


def test_llm_safe_passes() -> None:
    policy = WebFetchBlockPolicySettings()
    scan = {"verdict": "safe", "severity": 1, "confidence": "high"}
    assert not llm_classifier_outcome(scan, policy).blocked


def test_llm_suspicious_low_severity_medium_conf_passes() -> None:
    policy = WebFetchBlockPolicySettings(suspicious_block_min_severity=4)
    scan = {"verdict": "suspicious", "severity": 2, "confidence": "medium"}
    assert not llm_classifier_outcome(scan, policy).blocked


def test_llm_suspicious_high_conf_blocks() -> None:
    policy = WebFetchBlockPolicySettings(suspicious_block_min_severity=4)
    scan = {"verdict": "suspicious", "severity": 2, "confidence": "high"}
    assert llm_classifier_outcome(scan, policy).blocked


def test_llm_suspicious_severity_at_threshold_blocks() -> None:
    policy = WebFetchBlockPolicySettings(suspicious_block_min_severity=4)
    scan = {"verdict": "suspicious", "severity": 4, "confidence": "low"}
    assert llm_classifier_outcome(scan, policy).blocked
