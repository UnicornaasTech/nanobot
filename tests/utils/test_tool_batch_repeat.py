"""Tests for repeated tool-call batch detection."""

from __future__ import annotations

from nanobot.providers.base import ToolCallRequest
from nanobot.utils.runtime import (
    REPEATED_TOOL_BATCH_PROMPT,
    build_repeated_tool_batch_message,
    repeated_tool_batch_should_inject,
    tool_call_batch_fingerprint,
)


def test_batch_fingerprint_is_order_independent() -> None:
    batch_a = [
        ToolCallRequest(id="1", name="web_search", arguments={"query": "tallinn"}),
        ToolCallRequest(id="2", name="web_search", arguments={"query": "tartu"}),
    ]
    batch_b = list(reversed(batch_a))
    assert tool_call_batch_fingerprint(batch_a) == tool_call_batch_fingerprint(batch_b)


def test_batch_fingerprint_differs_for_different_args() -> None:
    one = [ToolCallRequest(id="1", name="web_search", arguments={"query": "tallinn"})]
    two = [ToolCallRequest(id="2", name="web_search", arguments={"query": "tartu"})]
    assert tool_call_batch_fingerprint(one) != tool_call_batch_fingerprint(two)


def test_batch_inject_after_three_identical_batches() -> None:
    batch = [
        ToolCallRequest(id="1", name="grep", arguments={"pattern": "foo"}),
        ToolCallRequest(id="2", name="read_file", arguments={"path": "a.txt"}),
    ]
    state: dict = {}
    assert repeated_tool_batch_should_inject(batch, state) is False
    assert repeated_tool_batch_should_inject(batch, state) is False
    assert repeated_tool_batch_should_inject(batch, state) is True
    assert repeated_tool_batch_should_inject(batch, state) is True


def test_batch_streak_resets_when_batch_changes() -> None:
    batch_a = [ToolCallRequest(id="1", name="web_search", arguments={"query": "a"})]
    batch_b = [ToolCallRequest(id="2", name="web_search", arguments={"query": "b"})]
    state: dict = {}
    assert repeated_tool_batch_should_inject(batch_a, state) is False
    assert repeated_tool_batch_should_inject(batch_a, state) is False
    assert repeated_tool_batch_should_inject(batch_b, state) is False
    assert repeated_tool_batch_should_inject(batch_a, state) is False


def test_build_repeated_tool_batch_message() -> None:
    msg = build_repeated_tool_batch_message()
    assert msg["role"] == "user"
    assert msg["content"] == REPEATED_TOOL_BATCH_PROMPT
