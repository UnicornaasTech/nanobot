import pytest

from nanobot.config.schema import AgentDefaults


def test_generic_memory_only_defaults_false() -> None:
    cfg = AgentDefaults()
    assert cfg.generic_memory_only is False


def test_generic_memory_only_accepts_camel_case_alias() -> None:
    cfg = AgentDefaults.model_validate({"genericMemoryOnly": True})
    assert cfg.generic_memory_only is True


def test_generic_memory_only_rejects_eager_knowledge_enabled() -> None:
    with pytest.raises(ValueError, match="genericMemoryOnly"):
        AgentDefaults.model_validate(
            {
                "genericMemoryOnly": True,
                "eagerKnowledge": {"enabled": True},
            }
        )


def test_generic_memory_only_allows_eager_knowledge_disabled() -> None:
    cfg = AgentDefaults.model_validate(
        {
            "genericMemoryOnly": True,
            "eagerKnowledge": {"enabled": False},
        }
    )
    assert cfg.generic_memory_only is True
    assert cfg.eager_knowledge.enabled is False
