"""tools.gmailDraft config schema."""

from nanobot.agent.tools.gmail_auth import GmailDraftToolConfig
from nanobot.config.schema import ToolsConfig


def test_gmail_draft_nested_under_tools() -> None:
    tools = ToolsConfig.model_validate(
        {
            "gmailDraft": {
                "clientId": "cid",
                "clientSecret": "sec",
                "refreshToken": "ref",
            }
        }
    )
    assert tools.gmail_draft == GmailDraftToolConfig(
        client_id="cid",
        client_secret="sec",
        refresh_token="ref",
    )
