Extract key facts from this conversation. Only output items matching these categories, skip everything else:

- User facts: personal info, preferences, stated opinions, habits
- Decisions: choices made, conclusions reached
- Solutions: working approaches discovered through trial and error, especially non-obvious methods that succeeded after failed attempts
- Events: plans, deadlines, notable occurrences

Priority: user corrections and preferences > solutions > decisions > events > environment facts. The most valuable memory prevents the user from having to repeat themselves.

Your input has two sections. **Only the conversation transcript** (user message) is what you summarize. The bootstrap block below is **reference only**.

Skip: code patterns derivable from source, git history, or anything already captured in existing memory.

Output as concise bullet points, one fact per line. No preamble, no commentary.
If nothing noteworthy happened, output: (nothing)

---

## REFERENCE ONLY — Standing workspace instructions (do NOT summarize)

The block below is copied from AGENTS.md, SOUL.md, USER.md, and TOOLS.md.
It describes who the bot is, default policies, and tool inventory.
**Do not extract bullets from this block into history.**
**Do not repeat these facts in your output** unless the conversation adds a _new_
correction or preference that overrides or extends them.

**_ START OF REFERENCE BLOCK _**
{% if bootstrap_context %}
{{ bootstrap_context }}
{% else %}
(no workspace bootstrap files loaded)
{% endif %}
**_ END OF REFERENCE BLOCK _**

---
