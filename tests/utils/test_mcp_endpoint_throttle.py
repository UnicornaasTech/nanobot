"""Tests for MCP endpoint repeat / non-retryable guards."""

from __future__ import annotations

from nanobot.utils.runtime import (
    is_non_retryable_mcp_4xx,
    mark_non_retryable_mcp_attempt,
    non_retryable_mcp_error,
    non_retryable_mcp_preblock,
    repeated_mcp_endpoint_error,
)


def _notion_404(page_id: str = "abc") -> str:
    return (
        '{"object":"error","status":404,"code":"object_not_found",'
        f'"message":"Could not find page with ID {page_id}."}}'
    )


def test_non_retryable_mcp_4xx_detects_object_not_found() -> None:
    assert is_non_retryable_mcp_4xx(_notion_404()) is True
    assert is_non_retryable_mcp_4xx('{"status":500,"code":"internal"}') is False


def test_non_retryable_mcp_error_payload_for_mcp_tools_only() -> None:
    assert non_retryable_mcp_error("read_file", _notion_404()) is None
    blocked = non_retryable_mcp_error("mcp_notion_pages_retrieve", _notion_404())
    assert blocked is not None
    assert "non-retryable" in blocked
    assert "Do NOT call this same MCP tool" in blocked


def test_repeated_mcp_endpoint_blocks_third_identical_failure() -> None:
    tool = "mcp_notion_pages_retrieve"
    args = {"page_id": "abc"}
    err = _notion_404()
    state: dict = {}

    assert repeated_mcp_endpoint_error(tool, args, err, state) is None
    assert repeated_mcp_endpoint_error(tool, args, err, state) is None
    blocked = repeated_mcp_endpoint_error(tool, args, err, state)
    assert blocked is not None
    assert "repeated MCP endpoint call blocked" in blocked


def test_repeated_mcp_endpoint_resets_when_signature_changes() -> None:
    tool = "mcp_notion_pages_retrieve"
    state: dict = {}
    assert repeated_mcp_endpoint_error(tool, {"page_id": "a"}, _notion_404("a"), state) is None
    assert repeated_mcp_endpoint_error(tool, {"page_id": "a"}, _notion_404("a"), state) is None
    # Different args → streak resets
    assert repeated_mcp_endpoint_error(tool, {"page_id": "b"}, _notion_404("b"), state) is None
    assert repeated_mcp_endpoint_error(tool, {"page_id": "b"}, _notion_404("b"), state) is None
    blocked = repeated_mcp_endpoint_error(tool, {"page_id": "b"}, _notion_404("b"), state)
    assert blocked is not None


def test_non_retryable_preblock_after_mark() -> None:
    tool = "mcp_notion_pages_retrieve"
    args = {"page_id": "abc"}
    attempts: set[str] = set()
    assert non_retryable_mcp_preblock(tool, args, attempts) is None
    mark_non_retryable_mcp_attempt(tool, args, attempts)
    blocked = non_retryable_mcp_preblock(tool, args, attempts)
    assert blocked is not None
    assert "already returned a non-retryable" in blocked
