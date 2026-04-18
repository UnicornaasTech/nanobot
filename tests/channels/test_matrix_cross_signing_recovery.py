"""Tests for Matrix Secret Storage recovery + cross-signing signature upload."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import os
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import olm
import pytest
from unpaddedbase64 import encode_base64

import nanobot.channels.matrix_cross_signing_recovery as mcr


def _key_desc_from_secret_key(secret_key: bytes) -> dict[str, Any]:
    iv = os.urandom(16)
    ivb = bytearray(iv)
    ivb[8] &= 0x7F
    iv = bytes(ivb)
    aes_mac = mcr.hkdf_sha256_element_secret_storage(ikm=secret_key, info=b"", length=64)
    aes_key, mac_key = aes_mac[:32], aes_mac[32:]
    ct = mcr._aes_ctr256_encrypt(key=aes_key, iv=iv, plaintext=b"\x00" * 32)
    mac = hmac.new(mac_key, ct, hashlib.sha256).digest()
    return {
        "algorithm": "m.secret_storage.v1.aes-hmac-sha2",
        "iv": encode_base64(iv),
        "mac": encode_base64(mac),
    }


def _encrypt_secret_blob(secret_name: str, secret_key: bytes, plaintext: bytes) -> dict[str, str]:
    iv = os.urandom(16)
    ivb = bytearray(iv)
    ivb[8] &= 0x7F
    iv = bytes(ivb)
    aes_mac = mcr.hkdf_sha256_element_secret_storage(ikm=secret_key, info=secret_name.encode("utf-8"), length=64)
    aes_key, mac_key = aes_mac[:32], aes_mac[32:]
    ct = mcr._aes_ctr256_encrypt(key=aes_key, iv=iv, plaintext=plaintext)
    mac = hmac.new(mac_key, ct, hashlib.sha256).digest()
    return {
        "iv": encode_base64(iv),
        "ciphertext": encode_base64(ct),
        "mac": encode_base64(mac),
    }


@pytest.mark.parametrize("n", range(8))
def test_recovery_key_encode_decode_roundtrip(n: int) -> None:
    raw = os.urandom(32)
    encoded = mcr.encode_matrix_recovery_key(raw)
    assert mcr.decode_matrix_recovery_key(encoded) == raw


def test_decode_recovery_key_rejects_invalid_chars() -> None:
    with pytest.raises(ValueError, match="invalid base58"):
        mcr.decode_matrix_recovery_key("0OIl")  # O and I are not in Matrix base58 alphabet


def test_bootstrap_uploads_self_signing_signature(monkeypatch: pytest.MonkeyPatch) -> None:
    secret_key = os.urandom(32)
    recovery_key = mcr.encode_matrix_recovery_key(secret_key)
    self_seed = olm.PkSigning.generate_seed()
    pk = olm.PkSigning(self_seed)
    self_pub = pk.public_key
    user_id = "@bot:example.org"
    device_id = "NANOBOT1"

    key_desc = _key_desc_from_secret_key(secret_key)
    plain = encode_base64(self_seed).encode("utf-8")
    enc = _encrypt_secret_blob("m.cross_signing.self_signing", secret_key, plain)

    device_obj: dict[str, Any] = {
        "user_id": user_id,
        "device_id": device_id,
        "algorithms": ["m.olm.v1.curve25519-aes-sha256", "m.megolm.v1.aes-sha2"],
        "keys": {
            f"curve25519:{device_id}": encode_base64(os.urandom(32)),
            f"ed25519:{device_id}": encode_base64(os.urandom(32)),
        },
        "signatures": {},
    }

    kq = {
        "device_keys": {user_id: {device_id: device_obj}},
        "self_signing_keys": {
            user_id: {
                "user_id": user_id,
                "usage": ["self_signing"],
                "keys": {f"ed25519:{self_pub}": self_pub},
            }
        },
    }

    uploads: list[dict[str, Any]] = []

    async def fake_get(
        session: Any, homeserver: str, access_token: str, path: str
    ) -> tuple[int, Any]:
        assert access_token == "tok"
        if path.endswith("/account_data/m.secret_storage.default_key"):
            return 200, {"key": "kid"}
        if "/account_data/m.secret_storage.key." in path:
            return 200, key_desc
        if path.endswith("/account_data/m.cross_signing.self_signing"):
            return 200, {"encrypted": {"kid": enc}}
        return 404, None

    async def fake_post(
        session: Any, homeserver: str, access_token: str, path: str, body: dict[str, Any]
    ) -> tuple[int, Any]:
        if path.endswith("/keys/query"):
            return 200, kq
        if path.endswith("/keys/signatures/upload"):
            uploads.append(body)
            return 200, {"failures": {}}
        return 500, {"err": path}

    monkeypatch.setattr(mcr, "_get_json", fake_get)
    monkeypatch.setattr(mcr, "_post_json", fake_post)

    async def _run() -> None:
        await mcr._bootstrap_cross_signing_from_recovery_impl(
            homeserver="https://matrix.example.org",
            access_token="tok",
            user_id=user_id,
            device_id=device_id,
            recovery_key=recovery_key,
            recovery_passphrase="",
        )

    asyncio.run(_run())

    assert len(uploads) == 1
    body = uploads[0]
    dev = body[user_id][device_id]
    sigs = dev["signatures"][user_id]
    assert f"ed25519:{self_pub}" in sigs

    canonical = mcr._canonical_json_for_signing(device_obj)
    olm.ed25519_verify(self_pub, canonical, sigs[f"ed25519:{self_pub}"])


def test_bootstrap_skips_when_already_signed(monkeypatch: pytest.MonkeyPatch) -> None:
    secret_key = os.urandom(32)
    recovery_key = mcr.encode_matrix_recovery_key(secret_key)
    self_seed = olm.PkSigning.generate_seed()
    pk = olm.PkSigning(self_seed)
    self_pub = pk.public_key
    user_id = "@bot:example.org"
    device_id = "NANOBOT1"

    key_desc = _key_desc_from_secret_key(secret_key)
    plain = encode_base64(self_seed).encode("utf-8")
    enc = _encrypt_secret_blob("m.cross_signing.self_signing", secret_key, plain)

    device_unsigned = {
        "user_id": user_id,
        "device_id": device_id,
        "algorithms": ["m.olm.v1.curve25519-aes-sha256", "m.megolm.v1.aes-sha2"],
        "keys": {
            f"curve25519:{device_id}": encode_base64(os.urandom(32)),
            f"ed25519:{device_id}": encode_base64(os.urandom(32)),
        },
    }
    canonical = mcr._canonical_json_for_signing(device_unsigned)
    sig = pk.sign(canonical)
    device_obj = {
        **device_unsigned,
        "signatures": {user_id: {f"ed25519:{self_pub}": sig}},
    }

    kq = {
        "device_keys": {user_id: {device_id: device_obj}},
        "self_signing_keys": {
            user_id: {
                "user_id": user_id,
                "usage": ["self_signing"],
                "keys": {f"ed25519:{self_pub}": self_pub},
            }
        },
    }

    uploads: list[dict[str, Any]] = []

    async def fake_get(
        session: Any, homeserver: str, access_token: str, path: str
    ) -> tuple[int, Any]:
        if path.endswith("/account_data/m.secret_storage.default_key"):
            return 200, {"key": "kid"}
        if "/account_data/m.secret_storage.key." in path:
            return 200, key_desc
        if path.endswith("/account_data/m.cross_signing.self_signing"):
            return 200, {"encrypted": {"kid": enc}}
        return 404, None

    async def fake_post(
        session: Any, homeserver: str, access_token: str, path: str, body: dict[str, Any]
    ) -> tuple[int, Any]:
        if path.endswith("/keys/query"):
            return 200, kq
        if path.endswith("/keys/signatures/upload"):
            uploads.append(body)
            return 200, {"failures": {}}
        return 500, {}

    monkeypatch.setattr(mcr, "_get_json", fake_get)
    monkeypatch.setattr(mcr, "_post_json", fake_post)

    async def _run() -> None:
        await mcr._bootstrap_cross_signing_from_recovery_impl(
            homeserver="https://matrix.example.org",
            access_token="tok",
            user_id=user_id,
            device_id=device_id,
            recovery_key=recovery_key,
            recovery_passphrase="",
        )

    asyncio.run(_run())
    assert uploads == []


def test_bootstrap_from_client_calls_impl(monkeypatch: pytest.MonkeyPatch) -> None:
    impl = AsyncMock()
    monkeypatch.setattr(mcr, "_bootstrap_cross_signing_from_recovery_impl", impl)

    cfg = MagicMock()
    cfg.recovery_key = " Es3 "
    cfg.recovery_passphrase = ""

    client = MagicMock()
    client.homeserver = "https://h"
    client.access_token = "t"
    client.user_id = "@u:h"
    client.device_id = "D"

    async def _run() -> None:
        await mcr.bootstrap_cross_signing_from_recovery(client, cfg)  # type: ignore[arg-type]

    asyncio.run(_run())
    impl.assert_awaited_once()
    _, kwargs = impl.call_args
    assert kwargs["recovery_key"] == "Es3"


def test_bootstrap_noop_without_secrets() -> None:
    cfg = MagicMock()
    cfg.recovery_key = ""
    cfg.recovery_passphrase = "   "
    client = MagicMock()

    async def _run() -> None:
        await mcr.bootstrap_cross_signing_from_recovery(client, cfg)  # type: ignore[arg-type]

    asyncio.run(_run())
