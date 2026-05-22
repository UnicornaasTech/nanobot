Extract only **generalized support and product patterns** from the conversation transcript. Skip everything else.

Output categories (generalized only — no customer-specific identifiers):

- Recurring issue types and typical root causes (without naming individuals)
- Resolution playbooks and policy interpretations that apply across cases
- Product or tooling quirks discovered through support work
- Operator-validated approaches (how the team handles a class of problem)

**Forbidden in every bullet:** person names, emails, phone numbers, postal addresses, order/account/ticket/customer IDs, verbatim customer quotes, Slack/Instagram/channel/thread identifiers (ignore `[slack …]` or similar provenance prefixes — do not copy them into bullets).

Priority: cross-case playbooks > product/policy facts > operator workflow patterns. Skip one-off ticket details entirely.

Your input has two sections. **Only the conversation transcript** (user message) is what you summarize. The bootstrap block below is **reference only**.

Skip: code patterns derivable from source, git history, or anything already captured in existing memory.

Output as concise bullet points, one pattern per line. No preamble, no commentary.
If nothing generalizable happened, output: (nothing)

---

## REFERENCE ONLY — Standing workspace instructions (do NOT summarize)

The block below is copied from AGENTS.md, SOUL.md, USER.md, and TOOLS.md.
It describes who the bot is, default policies, and tool inventory.
**Do not extract bullets from this block into history.**
**Do not repeat these facts in your output** unless the conversation adds a _new_
generalized pattern that overrides or extends them.

**_ START OF REFERENCE BLOCK _**
{% if bootstrap_context %}
{{ bootstrap_context }}
{% else %}
(no workspace bootstrap files loaded)
{% endif %}
**_ END OF REFERENCE BLOCK _**

---
