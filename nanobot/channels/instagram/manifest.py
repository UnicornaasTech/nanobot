"""Instagram management contract."""

from nanobot.channels._manifest import field, required_fields
from nanobot.channels.contracts import ChannelSetupSpec
from nanobot.channels.instagram.validation import validate
from nanobot.channels.plugin import ChannelPlugin

SETUP_SPEC = ChannelSetupSpec(
    fields={
        "consentGranted": field("bool", default=False),
        "useWebhook": field("bool", default=True),
        "pollFallbackEnabled": field("bool", default=True),
        "pollIntervalSeconds": field("int", default=60),
        "slackBotToken": field("secret"),
        "slackDraftChannel": field(),
        "slackAppToken": field("secret"),
        "webhookHost": field(default="0.0.0.0"),
        "webhookPort": field("int", default=5005),
        "allowFrom": field("list"),
        "accounts": field("list"),
    },
    required=required_fields(
        "consentGranted",
        "slackBotToken",
        "slackDraftChannel",
        "slackAppToken",
        "accounts",
    ),
    official_url="https://developers.facebook.com/docs/messenger-platform/instagram",
    validator=validate,
)

PLUGIN = ChannelPlugin(
    name="instagram",
    display_name="Instagram",
    runtime=f"{__package__}.runtime:InstagramChannel",
    setup=SETUP_SPEC,
    dependencies=("flask>=3.0.0,<4.0.0",),
)
