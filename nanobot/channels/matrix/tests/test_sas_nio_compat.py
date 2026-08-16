"""Tests for matrix-nio SAS commitment encoding shim."""

from hashlib import sha256

from unpaddedbase64 import encode_base64

from nanobot.channels.matrix.sas_nio_compat import (
    apply_nio_sas_commitment_patch,
    sas_commitment_digest,
)


def test_sas_commitment_digest_is_unpadded_base64_not_hex() -> None:
    # libolm sha256("abc") / spec unpadded base64 (matrix-nio#570)
    assert sas_commitment_digest(b"abc") == "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0"
    assert sas_commitment_digest(b"abc") != sha256(b"abc").hexdigest()
    assert encode_base64(sha256(b"abc").digest()) == sas_commitment_digest(b"abc")


def test_apply_nio_sas_commitment_patch_is_idempotent() -> None:
    apply_nio_sas_commitment_patch()
    apply_nio_sas_commitment_patch()
    from nio.crypto.sas import Sas

    assert Sas.from_key_verification_start is not None
    assert Sas._check_commitment is not None
