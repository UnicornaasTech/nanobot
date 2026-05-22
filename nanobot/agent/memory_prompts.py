"""Fork-local: resolve bundled memory-gathering prompt templates."""

from __future__ import annotations


def resolve_memory_template(base: str, *, generic_memory_only: bool) -> str:
    """Return template path under ``templates/`` for Consolidator or Dream prompts."""
    if generic_memory_only:
        return f"agent/{base}_generic.md"
    return f"agent/{base}.md"
