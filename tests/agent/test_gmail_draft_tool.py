"""CreateGmailDraftTool registration and enabled gate."""

import pytest

from nanobot.agent.tools.context import ToolContext
from nanobot.agent.tools.gmail_auth import GmailDraftToolConfig
from nanobot.agent.tools.gmail_draft import CreateGmailDraftTool
from nanobot.config.schema import ToolsConfig


def _gmail_libs_available() -> bool:
    try:
        import google.auth  # noqa: F401
        import googleapiclient  # noqa: F401
    except ImportError:
        return False
    return True


@pytest.mark.skipif(not _gmail_libs_available(), reason="[gmail] extra not installed")
def test_enabled_false_when_gmail_draft_empty() -> None:
    tools = ToolsConfig()
    ctx = ToolContext(config=tools, workspace="/tmp")
    assert CreateGmailDraftTool.enabled(ctx) is False


@pytest.mark.skipif(not _gmail_libs_available(), reason="[gmail] extra not installed")
def test_enabled_true_when_configured() -> None:
    tools = ToolsConfig(
        gmail_draft=GmailDraftToolConfig(
            client_id="a",
            client_secret="b",
            refresh_token="c",
        )
    )
    ctx = ToolContext(config=tools, workspace="/tmp")
    assert CreateGmailDraftTool.enabled(ctx) is True
