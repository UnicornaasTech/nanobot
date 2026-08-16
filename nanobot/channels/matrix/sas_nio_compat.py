"""matrix-nio SAS interop shims (fork-only).

matrix-nio 0.26.0 (vodozemac) hashes SAS commitments with ``sha256().hexdigest()``.
The spec and Element expect unpadded base64 (what libolm ``sha256`` returned).
See https://github.com/matrix-nio/matrix-nio/issues/570
"""

from __future__ import annotations

from hashlib import sha256
from typing import Any

from unpaddedbase64 import encode_base64

_PATCHED = False


def sas_commitment_digest(data: bytes) -> str:
    """SHA-256 of *data* as unpadded base64 (Matrix SAS commitment wire format)."""
    return encode_base64(sha256(data).digest())


def apply_nio_sas_commitment_patch() -> None:
    """Rewrite nio's SAS commitment encode/check to unpadded base64. Idempotent."""
    global _PATCHED
    if _PATCHED:
        return

    from nio.api import Api
    from nio.crypto.sas import Sas

    orig_from_start = Sas.from_key_verification_start
    orig_check = Sas._check_commitment

    @classmethod  # type: ignore[misc]
    def from_key_verification_start(cls, *args: Any, **kwargs: Any):
        obj = orig_from_start(*args, **kwargs)
        event = args[4] if len(args) >= 5 else kwargs.get("event")
        if obj is None or getattr(obj, "canceled", False) or event is None:
            return obj
        source = getattr(event, "source", None) or {}
        content = source.get("content")
        if not isinstance(content, dict):
            return obj
        pubkey = getattr(obj, "pubkey", None)
        if not pubkey:
            return obj
        canonical = Api.to_canonical_json(content)
        obj.commitment = sas_commitment_digest(pubkey.encode() + canonical.encode())
        return obj

    def _check_commitment(self, key: str) -> bool:
        if not self.commitment:
            return orig_check(self, key)
        canonical = Api.to_canonical_json(self.start_verification().content)
        calculated = sas_commitment_digest(key.encode() + canonical.encode())
        return self.commitment == calculated

    Sas.from_key_verification_start = from_key_verification_start  # type: ignore[method-assign]
    Sas._check_commitment = _check_commitment  # type: ignore[method-assign]
    _PATCHED = True
