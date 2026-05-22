## Prospr fork customizations

This is our fork of the official nanobot repo.
IMPORTANT: Thus, when creating changes, **always attempt to minimize overlap with original public upstream code to avoid merge conflicts**.

Our extensions:

- **Reference doc:** [`docs/prospr-custom-implementations.md`](docs/prospr-custom-implementations.md) — lists fork-only code changes and config keys (verified against source).
- **When you add or change fork behavior** (new channel options, tools, send policies, config fields, or agent-facing workflows), update that doc in the same change so it stays accurate. Do not duplicate long setup runbooks there; link to vendor/Meta/Google docs instead.
