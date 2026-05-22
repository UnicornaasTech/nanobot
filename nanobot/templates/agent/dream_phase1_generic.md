You have TWO equally important tasks:

1. Extract **generalized** facts from conversation history (patterns and playbooks only — never end-customer PII)
2. Deduplicate existing memory files — find and flag redundant, overlapping, or stale content even if NOT mentioned in history

Output one line per finding:
[FILE] atomic generalized fact (not already in memory)
[FILE-REMOVE] reason for removal
[SKILL] kebab-case-name: one-line description of the reusable cross-customer procedure

File roles (customer-support mode):

- **USER** — operator/team identity and preferences only (NOT end-customer profiles)
- **SOUL** — bot behavior and tone (non-customer-specific)
- **MEMORY** — durable generalized phenomena: recurring issues, playbooks, product/policy context

Rules:

- Atomic generalized facts: "refund requests within 30 days need receipt photo" not "customer Jane asked for refund"
- **Never store:** customer names, emails, phones, addresses, order/account/ticket IDs, verbatim quotes, channel/thread IDs
- Corrections apply to operator or product facts only: [USER] team prefers Slack cards, not [USER] customer lives in Ohio
- Capture only approaches the **operator team** validated as reusable across customers

Deduplication — scan ALL memory files for these redundancy patterns:

- Same generalized fact in multiple places
- Overlapping sections covering the same topic
- MEMORY.md duplicating operator facts already in USER.md or SOUL.md
- Verbose entries that can be condensed without losing information
  For each duplicate, output [FILE-REMOVE] for the less authoritative copy

Staleness — MEMORY.md lines may have a `← Nd` suffix showing days since last modification:

- SOUL.md and USER.md have no age annotations — permanent operator/style facts only
- Only prune objectively outdated content: superseded policies, retired product flows
- Lines with `← Nd` (N>{{ stale_threshold_days }}) deserve closer review but are NOT automatically removable
- When removing: prefer deleting individual items over entire sections

Skill discovery — flag [SKILL] only when ALL are true:

- A **cross-customer** repeatable procedure appeared 2+ times (not one ticket workflow)
- Clear steps (not vague preferences)
- Substantial enough for its own instruction set
- Do not worry about duplicates — phase 2 dedupes against existing skills

Do not add: current weather, transient status, temporary errors, conversational filler, customer-specific cases.

[SKIP] if nothing needs updating.
