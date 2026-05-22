Update memory files based on the analysis below (generic-memory mode: patterns and playbooks only).

- [FILE] entries: add the described content to the appropriate file
- [FILE-REMOVE] entries: delete the corresponding content from memory files
- [SKILL] entries: create a new skill under skills/<name>/SKILL.md using write_file

## Privacy (generic memory)

- **Never** write end-customer identifiers: names, emails, phones, addresses, order/account/ticket IDs, verbatim customer quotes, channel/thread IDs
- **USER.md** is for operator/team preferences only — not customer profiles
- **MEMORY.md** holds cross-customer phenomena and playbooks only
- Skills must describe generic procedures reusable across customers — skip one-off ticket workflows

## File paths (relative to workspace root)

- SOUL.md
- USER.md
- memory/MEMORY.md
- skills/<name>/SKILL.md (for [SKILL] entries only)

Do NOT guess paths.

## Editing rules

- The file contents provided below are the starting snapshot, but files may change after
  that snapshot or after your own edits.
- Use exact text as old_text, include surrounding blank lines for unique match
- Batch changes to the same file into one edit_file call
- After any successful edit_file call, read_file that file before making another edit to it
- After any edit_file error, read_file that file, retry at most once with exact current text,
  then stop trying that file if it still fails
- For deletions: section header + all bullets as old_text, new_text empty
- Surgical edits only — never rewrite entire files
- If nothing to update, stop without calling tools

## Skill creation rules (for [SKILL] entries)

- **Default: create no skills.** Skip any `[SKILL]` entry that does not clearly meet the phase-1 bar (cross-customer repeatable procedure).
- One-off ticket workflows and customer-specific facts belong nowhere — omit them.
- Use write_file to create skills/<name>/SKILL.md
- Before writing, read_file `{{ skill_creator_path }}` for format reference (frontmatter structure, naming conventions, quality standards)
- **Dedup check**: read existing skills listed below to verify the new skill is not functionally redundant. Skip creation if an existing skill already covers the same workflow.
- Include YAML frontmatter with name and description fields
- Keep SKILL.md under 2000 words — concise and actionable
- Include: when to use, steps, output format, at least one example
- Do NOT overwrite existing skills — skip if the skill directory already exists
- Reference specific tools the agent has access to (read_file, write_file, exec, web_search, etc.)
- Skills are instruction sets, not code — do not include implementation code

## Quality

- Every line must carry standalone value as a **generalized** fact
- Concise bullets under clear headers
- When reducing (not deleting): keep essential patterns, drop verbose details
- If uncertain whether to delete, keep but add "(verify currency)"
