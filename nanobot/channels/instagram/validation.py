"""Instagram setup validation owned by the channel package."""

from typing import Any

from nanobot.channels.contracts import ChannelValidationContext, channel_value_present
from nanobot.channels.validation import (
    check,
    required_checks,
    status_from_checks,
    string_value,
    truthy,
)


def validate(values: dict[str, Any], _context: ChannelValidationContext) -> dict[str, Any]:
    checks, missing = required_checks("instagram", values)

    if truthy(values.get("consentGranted")):
        checks.append(
            check("consent", "Instagram consent", "pass", "Consent is enabled for Instagram DMs.")
        )
    else:
        checks.append(
            check(
                "consent",
                "Instagram consent",
                "fail",
                "Grant consent before nanobot reads Instagram DMs.",
            )
        )

    accounts = values.get("accounts")
    # required_checks stringifies lists, so an empty [] can look "present"; enforce here.
    if isinstance(accounts, list) and channel_value_present(accounts):
        checks.append(
            check(
                "accounts",
                "Instagram accounts",
                "pass",
                f"{len(accounts)} account(s) configured.",
            )
        )
    else:
        if "accounts" not in missing:
            missing.append("accounts")
        checks.append(
            check(
                "accounts",
                "Instagram accounts",
                "fail",
                "Add at least one entry under accounts[].",
            )
        )

    draft_channel = string_value(values.get("slackDraftChannel"))
    if draft_channel:
        checks.append(
            check(
                "slack_draft",
                "Slack draft channel",
                "pass",
                f"Drafts will post to {draft_channel}.",
            )
        )

    checks.append(
        check(
            "manual_review",
            "Meta / Slack wiring",
            "skipped",
            "Webhook verify tokens, page tokens, and Socket Mode are checked when the channel starts.",
        )
    )
    return status_from_checks("instagram", checks, list(dict.fromkeys(missing)))


__all__ = ["validate"]
