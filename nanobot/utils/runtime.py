"""Runtime-specific helper functions and constants."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, cast

from loguru import logger

from nanobot.utils.helpers import stringify_text_blocks

_MAX_REPEAT_EXTERNAL_LOOKUPS = 2

# Third identical failing MCP endpoint call in a turn is blocked.
_MAX_REPEAT_MCP_ENDPOINT_ATTEMPTS = 2

# Third same-target workspace violation in a turn escalates to "stop retrying".
_MAX_REPEAT_WORKSPACE_VIOLATIONS = 2
_LENGTH_RECOVERY_TAIL_CHARS = 64

_NON_RETRYABLE_MCP_STATUS_CODES = frozenset({400, 404})
_NON_RETRYABLE_MCP_ERROR_CODES = frozenset({
    "validation_error",
    "object_not_found",
})


_REPEAT_STATE_LAST_KEY = "__last_signature"
_REPEAT_STATE_STREAK_KEY = "__streak"

_BATCH_REPEAT_LAST_KEY = "__batch_last_fingerprint"
_BATCH_REPEAT_STREAK_KEY = "__batch_streak"
_MAX_REPEAT_TOOL_BATCH_STREAK = 3

EMPTY_FINAL_RESPONSE_MESSAGE = (
    "I completed the tool steps but couldn't produce a final answer. "
    "Please try again or narrow the task."
)

FINALIZATION_RETRY_PROMPT = (
    "Please provide your response to the user based on the conversation above."
)

BUDGET_EXHAUSTED_FINALIZATION_PROMPT = (
    "The tool-call budget for this turn is exhausted. Based only on the "
    "conversation and tool results above, provide a concise final response to "
    "the user. Do not call or request tools. Do not claim the task is complete "
    "unless the evidence above clearly shows it is complete. State what was "
    "done, what remains, and the best next step if anything is incomplete."
)

LENGTH_RECOVERY_PROMPT = (
    "The previous assistant response was cut off. Continue the same response from its "
    "exact endpoint. Output only new continuation text in the same language and style. "
    "Do not acknowledge this instruction, restart the response, repeat its title or any "
    "existing text, recap, or apologize."
)

SUSTAINED_GOAL_CONTINUE_PROMPT = (
    "You have an active sustained goal. Please continue working toward the "
    "objective using your tools, or call update_goal with action='complete' "
    "if the work is truly finished."
)

REPEATED_TOOL_BATCH_PROMPT = (
    "You have already run these exact tool calls with the same arguments and received results. "
    "Do not call these tool calls with the same arguments any more. Either change your strategy "
    "or answer the user with what you have."
)


def empty_tool_result_message(tool_name: str) -> str:
    """Short prompt-safe marker for tools that completed without visible output."""
    return f"({tool_name} completed with no output)"


def ensure_nonempty_tool_result(tool_name: str, content: Any) -> Any:
    """Replace semantically empty tool results with a short marker string."""
    if content is None:
        return empty_tool_result_message(tool_name)
    if isinstance(content, str) and not content.strip():
        return empty_tool_result_message(tool_name)
    if isinstance(content, list):
        if not content:
            return empty_tool_result_message(tool_name)
        text_payload = stringify_text_blocks(cast(list[Any], content))
        if text_payload is not None and not text_payload.strip():
            return empty_tool_result_message(tool_name)
    return cast(Any, content)


def is_blank_text(content: str | None) -> bool:
    """True when *content* is missing or only whitespace."""
    return content is None or not content.strip()


def build_finalization_retry_message() -> dict[str, str]:
    """A short no-tools-allowed prompt for final answer recovery."""
    return {"role": "user", "content": FINALIZATION_RETRY_PROMPT}


def build_budget_exhausted_finalization_message() -> dict[str, str]:
    """Prompt the model for a no-tools final response after budget exhaustion."""
    return {"role": "user", "content": BUDGET_EXHAUSTED_FINALIZATION_PROMPT}


def build_length_recovery_message(content: str) -> dict[str, str]:
    """Prompt the model to continue after hitting output token limit."""
    tail = content[-_LENGTH_RECOVERY_TAIL_CHARS:]
    prompt = (
        f"{LENGTH_RECOVERY_PROMPT}\n\n"
        "The following tail was already delivered to the user. Treat it as immutable "
        "context and do not output it again:\n"
        "<already_delivered_tail>\n"
        f"{tail}\n"
        "</already_delivered_tail>\n"
        "Begin with the text that belongs immediately after this tail."
    )
    return {"role": "user", "content": prompt}


def build_goal_continue_message(custom: str | None = None) -> dict[str, str]:
    """Prompt the model to continue when a sustained goal is still active."""
    return {"role": "user", "content": custom or SUSTAINED_GOAL_CONTINUE_PROMPT}


def build_repeated_tool_batch_message() -> dict[str, str]:
    """Prompt the model to stop re-issuing an identical tool-call batch."""
    return {"role": "user", "content": REPEATED_TOOL_BATCH_PROMPT}


def external_lookup_signature(tool_name: str, arguments: Any) -> str | None:
    """Stable signature for repeated external lookups we want to throttle."""
    if not isinstance(arguments, dict):
        return None
    arguments = cast(dict[str, Any], arguments)
    if tool_name == "web_fetch":
        url = str(arguments.get("url") or "").strip()
        if url:
            return f"web_fetch:{url.lower()}"
    if tool_name == "web_search":
        query = str(arguments.get("query") or arguments.get("search_term") or "").strip()
        if query:
            return f"web_search:{query.lower()}"
    if tool_name == "grep":
        # Treat repeated identical grep payloads as the same lookup target.
        try:
            normalized = json.dumps(arguments, sort_keys=True, ensure_ascii=False, default=str)
        except (TypeError, ValueError):
            normalized = repr(arguments)
        digest = hashlib.sha256(normalized.encode()).hexdigest()[:16]
        return f"grep:{digest}"
    return None


def repeated_external_lookup_error(
    tool_name: str,
    arguments: Any,
    seen_counts: dict[str, int],
) -> str | None:
    """Block repeated external lookups after a small retry budget."""
    signature = external_lookup_signature(tool_name, arguments)
    if signature is None:
        return None
    count = seen_counts.get(signature, 0) + 1
    seen_counts[signature] = count
    if count <= _MAX_REPEAT_EXTERNAL_LOOKUPS:
        return None
    logger.warning(
        "Blocking repeated external lookup {} on attempt {}",
        signature[:160],
        count,
    )
    return (
        "Error: repeated external lookup blocked. "
        "Use the results you already have to answer, or try a meaningfully different source."
    )


# Workspace-boundary violations are soft errors, with per-target throttling.

_OUTSIDE_PATH_PATTERN = re.compile(r"(?:^|[\s|>'\"])((?:/[^\s\"'>;|<]+)|(?:~[^\s\"'>;|<]+))")


def workspace_violation_signature(
    tool_name: str,
    arguments: dict[str, Any],
) -> str | None:
    """Return a stable cross-tool signature for the outside-workspace target."""
    if not isinstance(arguments, dict):
        return None
    arguments = cast(dict[str, Any], arguments)
    for key in ("path", "file_path", "target", "source", "destination"):
        val = arguments.get(key)
        if isinstance(val, str) and val.strip():
            return _normalize_violation_target(val.strip())

    if tool_name in {"exec", "shell"}:
        cmd = str(arguments.get("command") or "").strip()
        if cmd:
            match = _OUTSIDE_PATH_PATTERN.search(cmd)
            if match:
                return _normalize_violation_target(match.group(1))
        cwd = str(arguments.get("working_dir") or "").strip()
        if cwd:
            return _normalize_violation_target(cwd)

    return None


def _normalize_violation_target(raw: str) -> str:
    """Normalize *raw* path so that equivalent spellings collide on the same key."""
    try:
        normalized = Path(raw).expanduser().resolve().as_posix()
    except Exception:
        normalized = raw.replace("\\", "/")
    return f"violation:{normalized}".lower()


def repeated_workspace_violation_error(
    tool_name: str,
    arguments: dict[str, Any],
    seen_counts: dict[str, int],
) -> str | None:
    """Return an escalated error after repeated bypass attempts."""
    signature = workspace_violation_signature(tool_name, arguments)
    if signature is None:
        return None
    count = seen_counts.get(signature, 0) + 1
    seen_counts[signature] = count
    if count <= _MAX_REPEAT_WORKSPACE_VIOLATIONS:
        return None
    logger.warning(
        "Escalating repeated workspace bypass attempt {} (attempt {})",
        signature[:160],
        count,
    )
    target = signature.split("violation:", 1)[1] if "violation:" in signature else signature
    return (
        "Error: refusing repeated workspace-bypass attempts.\n"
        f"You have tried to access '{target}' (or an equivalent path) "
        f"{count} times in this turn. This is a hard policy boundary -- "
        "switching tools, shell tricks, working_dir overrides, symlinks, "
        "or base64 piping will NOT change the answer. Stop retrying. "
        "If the user genuinely needs this resource, tell them you cannot "
        "access it and ask how they want to proceed (e.g. copy the file "
        "into the workspace, or disable restrict_to_workspace for this run)."
    )


def _is_mcp_tool(tool_name: str) -> bool:
    return tool_name.startswith("mcp_")


def _normalize_mcp_arguments(arguments: dict[str, Any]) -> str:
    try:
        return json.dumps(arguments, sort_keys=True, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        return repr(arguments)


def _hash_mcp_arguments(arguments: dict[str, Any]) -> str:
    normalized = _normalize_mcp_arguments(arguments)
    return hashlib.sha256(normalized.encode()).hexdigest()[:16]


def parse_mcp_error_payload(result_text: str) -> dict[str, Any] | None:
    """Try to parse structured MCP/HTTP error JSON from tool result text."""
    text = (result_text or "").strip()
    if not text.startswith("{") or "}" not in text:
        return None
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def extract_mcp_error_signature(result_text: str) -> str:
    """Extract a stable error signature from MCP tool result text."""
    text = (result_text or "").strip()
    if not text:
        return "empty"

    data = parse_mcp_error_payload(text)
    if data is not None:
        parts: list[str] = []
        status = data.get("status")
        if status is not None:
            parts.append(f"status:{status}")
        code = data.get("code")
        if isinstance(code, str) and code.strip():
            parts.append(f"code:{code.strip().lower()}")
        message = data.get("message")
        if isinstance(message, str) and message.strip():
            parts.append(f"msg:{message.strip().lower()[:120]}")
        if parts:
            return "|".join(parts)

    lowered = text.lower().replace("\n", " ")
    return lowered[:200]


def mcp_attempt_signature(tool_name: str, arguments: dict[str, Any]) -> str | None:
    """Stable signature for MCP tool + arguments (without error text)."""
    if not _is_mcp_tool(tool_name):
        return None
    return f"mcp_attempt:{tool_name}:{_hash_mcp_arguments(arguments)}"


def mcp_endpoint_signature(
    tool_name: str,
    arguments: dict[str, Any],
    result_text: str,
) -> str | None:
    """Stable signature for repeated failing MCP endpoint calls (includes error)."""
    attempt = mcp_attempt_signature(tool_name, arguments)
    if attempt is None:
        return None
    error_sig = extract_mcp_error_signature(result_text)
    return f"{attempt}:{error_sig}"


def is_non_retryable_mcp_4xx(result_text: str) -> bool:
    """True when *result_text* looks like a non-retryable MCP 4xx client error."""
    data = parse_mcp_error_payload(result_text)
    if data is not None:
        try:
            status = int(data.get("status", 0))
        except (TypeError, ValueError):
            status = 0
        code = str(data.get("code") or "").strip().lower()
        if status in _NON_RETRYABLE_MCP_STATUS_CODES and code in _NON_RETRYABLE_MCP_ERROR_CODES:
            return True

    lowered = (result_text or "").lower()
    if not any(str(code) in lowered for code in _NON_RETRYABLE_MCP_ERROR_CODES):
        return False
    return any(
        f'"status":{status}' in lowered.replace(" ", "")
        or f'"status": {status}' in lowered
        for status in _NON_RETRYABLE_MCP_STATUS_CODES
    )


def is_mcp_tool_failure_result(tool_name: str, result: Any) -> bool:
    """True when an MCP tool returned a failure payload (not a successful body)."""
    if not _is_mcp_tool(tool_name) or not isinstance(result, str):
        return False
    text = result.strip()
    if not text:
        return False
    if text.startswith("Error"):
        return True
    if text.startswith("(") and "mcp" in text.lower():
        return True

    data = parse_mcp_error_payload(text)
    if data is None:
        return False
    if data.get("object") == "error":
        return True
    try:
        status = int(data.get("status", 0))
    except (TypeError, ValueError):
        return False
    return status >= 400


def non_retryable_mcp_error(tool_name: str, result_text: str) -> str | None:
    """Return a stop-retrying payload for non-retryable MCP 4xx failures."""
    if not _is_mcp_tool(tool_name) or not is_non_retryable_mcp_4xx(result_text):
        return None

    data = parse_mcp_error_payload(result_text) or {}
    message = str(data.get("message") or "").strip()
    code = str(data.get("code") or "").strip()
    status = str(data.get("status") or "").strip()
    detail = message or result_text.strip()[:500]

    return (
        f"Error: MCP endpoint {tool_name} returned a non-retryable "
        f"{status or '4xx'} error ({code or 'client_error'}).\n"
        f"{detail}\n\n"
        "This is a hard policy boundary for this endpoint in this turn. "
        "Do NOT call this same MCP tool with the same intent again. "
        "Use a different supported MCP tool or endpoint, ask the user to fix "
        "permissions or sharing (for 404/object_not_found), or explain the "
        "API/schema mismatch (for 400/validation_error) and propose a manual workaround."
    )


def repeated_mcp_endpoint_error(
    tool_name: str,
    arguments: dict[str, Any],
    result_text: str,
    state: dict[str, Any],
) -> str | None:
    """Block repeated consecutive identical failing MCP endpoint calls."""
    signature = mcp_endpoint_signature(tool_name, arguments, result_text)
    if signature is None:
        state[_REPEAT_STATE_LAST_KEY] = None
        state[_REPEAT_STATE_STREAK_KEY] = 0
        return None
    if state.get(_REPEAT_STATE_LAST_KEY) == signature:
        count = int(state.get(_REPEAT_STATE_STREAK_KEY, 0)) + 1
    else:
        count = 1
    state[_REPEAT_STATE_LAST_KEY] = signature
    state[_REPEAT_STATE_STREAK_KEY] = count
    if count <= _MAX_REPEAT_MCP_ENDPOINT_ATTEMPTS:
        return None
    logger.warning(
        "Blocking repeated consecutive MCP endpoint {} on attempt {}",
        signature[:160],
        count,
    )
    return (
        f"Error: repeated MCP endpoint call blocked for {tool_name} "
        f"(same arguments and error seen {count} times this turn).\n"
        "Stop retrying this endpoint. Use results you already have, try a "
        "different MCP tool or approach, or ask the user for missing access "
        "or configuration."
    )


def mark_non_retryable_mcp_attempt(
    tool_name: str,
    arguments: dict[str, Any],
    non_retryable_attempts: set[str],
) -> None:
    """Remember tool+args that hit a non-retryable MCP 4xx this turn."""
    signature = mcp_attempt_signature(tool_name, arguments)
    if signature is not None:
        non_retryable_attempts.add(signature)


def non_retryable_mcp_preblock(
    tool_name: str,
    arguments: dict[str, Any],
    non_retryable_attempts: set[str],
) -> str | None:
    """Block before execute when this MCP endpoint already returned non-retryable 4xx."""
    signature = mcp_attempt_signature(tool_name, arguments)
    if signature is None or signature not in non_retryable_attempts:
        return None
    return (
        f"Error: MCP endpoint {tool_name} already returned a non-retryable client error "
        "for these arguments this turn.\n"
        "Do NOT call this same MCP tool with the same intent again. "
        "Use a different supported MCP tool or endpoint, or explain the blocker "
        "to the user and propose a manual workaround."
    )


def repeated_tool_call_signature(tool_name: str, arguments: dict[str, Any]) -> str:
    """Return a stable signature for tool name + normalized arguments."""
    try:
        normalized = json.dumps(arguments, sort_keys=True, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        normalized = repr(arguments)
    digest = hashlib.sha256(normalized.encode()).hexdigest()[:16]
    return f"{tool_name}:{digest}"


def tool_call_batch_fingerprint(tool_calls: list[Any]) -> str:
    """Stable fingerprint for a batch of tool calls (order-independent)."""
    if not tool_calls:
        return ""
    parts: list[str] = []
    for tool_call in tool_calls:
        name = getattr(tool_call, "name", None) or ""
        raw_args = getattr(tool_call, "arguments", None)
        arguments = raw_args if isinstance(raw_args, dict) else {}
        parts.append(repeated_tool_call_signature(name, arguments))
    parts.sort()
    digest = hashlib.sha256("\n".join(parts).encode()).hexdigest()[:32]
    return digest


def repeated_tool_batch_should_inject(
    tool_calls: list[Any],
    state: dict[str, Any],
    *,
    max_streak: int = _MAX_REPEAT_TOOL_BATCH_STREAK,
) -> bool:
    """Return True when the same tool-call batch repeats *max_streak* times in a row."""
    fingerprint = tool_call_batch_fingerprint(tool_calls)
    if not fingerprint:
        return False
    if state.get(_BATCH_REPEAT_LAST_KEY) == fingerprint:
        streak = int(state.get(_BATCH_REPEAT_STREAK_KEY, 0)) + 1
    else:
        streak = 1
    state[_BATCH_REPEAT_LAST_KEY] = fingerprint
    state[_BATCH_REPEAT_STREAK_KEY] = streak
    if streak >= max_streak:
        logger.warning(
            "Blocking repeated tool batch (streak={}/{}): {}",
            streak,
            max_streak,
            fingerprint,
        )
        return True
    return False


def repeated_consecutive_tool_call_error(
    tool_name: str,
    arguments: dict[str, Any],
    state: dict[str, Any],
    *,
    max_attempts: int = 2,
) -> str | None:
    """Block consecutive identical tool calls after a small retry budget."""
    signature = repeated_tool_call_signature(tool_name, arguments)
    if state.get(_REPEAT_STATE_LAST_KEY) == signature:
        count = int(state.get(_REPEAT_STATE_STREAK_KEY, 0)) + 1
    else:
        count = 1
    state[_REPEAT_STATE_LAST_KEY] = signature
    state[_REPEAT_STATE_STREAK_KEY] = count
    if count <= max_attempts:
        return None
    return (
        f"Error: repeated identical tool call blocked for {tool_name} "
        f"(same arguments repeated {count} times in a row).\n"
        "Stop repeating this exact call. Use previous results, refine arguments, "
        "or switch to a different tool."
    )
