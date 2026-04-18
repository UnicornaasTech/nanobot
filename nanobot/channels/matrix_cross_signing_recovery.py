"""
Cross-signing device verification using Element / Matrix Secret Storage (SSSS).

matrix-nio does not implement cross-signing; this module performs the minimal
server flow: recover the self-signing seed from account data using a security
key or passphrase, then POST /keys/signatures/upload so the current device is
signed by the self-signing key (Element "verified" shield).

Spec: https://spec.matrix.org/v1.14/client-server-api/#secret-storage
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import TYPE_CHECKING, Any, Protocol
from urllib.parse import quote, urljoin

import aiohttp
import olm
from loguru import logger
from unpaddedbase64 import decode_base64

_MATRIX_HTTP_TIMEOUT = aiohttp.ClientTimeout(total=60)

if TYPE_CHECKING:
    from nio import AsyncClient


class _MatrixRecoveryConfig(Protocol):
    recovery_key: str
    recovery_passphrase: str

# Matrix "cryptographic key representation" + base58 (appendix)
_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {c: i for i, c in enumerate(_B58_ALPHABET)}
# Element / matrix-js-sdk use 8 zero bytes as HKDF salt for Secret Storage (not the spec's 32).
_ZERO_SALT_8 = bytes(8)


def _b58decode_compact(s: str) -> bytes:
    s = "".join(s.split())
    if not s:
        raise ValueError("empty recovery key")
    acc = 0
    for ch in s:
        if ch not in _B58_INDEX:
            raise ValueError("invalid base58 character in recovery key")
        acc = acc * 58 + _B58_INDEX[ch]
    pad = 0
    for ch in s:
        if ch == "1":
            pad += 1
        else:
            break
    out: list[int] = []
    n = acc
    while n > 0:
        out.append(n % 256)
        n //= 256
    body = bytes(reversed(out))
    return b"\x00" * pad + body


def decode_matrix_recovery_key(recovery_key: str) -> bytes:
    """Decode Element security key / Matrix cryptographic key representation -> 32-byte secret storage key."""
    raw = _b58decode_compact(recovery_key)
    if len(raw) != 35:
        raise ValueError("recovery key decodes to wrong length (expected 35 bytes including header and parity)")
    if raw[0] != 0x8B or raw[1] != 0x01:
        raise ValueError("recovery key has invalid header bytes")
    parity = 0
    for b in raw[:-1]:
        parity ^= b
    if parity != raw[-1]:
        raise ValueError("recovery key parity check failed")
    return raw[2:34]


def encode_matrix_recovery_key(raw_key: bytes) -> str:
    """Encode 32-byte Secret Storage key as Element security key string (for tests / tooling)."""
    if len(raw_key) != 32:
        raise ValueError("raw secret storage key must be 32 bytes")
    body = bytes([0x8B, 0x01]) + raw_key
    parity = 0
    for b in body:
        parity ^= b
    body = body + bytes([parity])
    n = int.from_bytes(body, "big")
    out: list[str] = []
    while n > 0:
        n, r = divmod(n, 58)
        out.append(_B58_ALPHABET[r])
    enc = "".join(reversed(out))
    pad = 0
    for byte in body:
        if byte == 0:
            pad += 1
        else:
            break
    return "1" * pad + enc if enc else "1" * pad


def hkdf_sha256_element_secret_storage(*, ikm: bytes, info: bytes, length: int) -> bytes:
    """HKDF-SHA256 matching matrix-js-sdk Secret Storage (salt = 8 zero bytes)."""
    prk = hmac.new(_ZERO_SALT_8, ikm, hashlib.sha256).digest()
    t = b""
    okm = b""
    i = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
        i += 1
    return okm[:length]


def _aes_ctr256_decrypt(*, key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """AES-CTR-256 matching matrix-js-sdk (WebCrypto: 128-bit block, 64-bit counter)."""
    from Crypto.Cipher import AES
    from Crypto.Util import Counter

    if len(key) != 32:
        raise ValueError("AES key must be 32 bytes")
    if len(iv) != 16:
        raise ValueError("IV must be 16 bytes")
    ivb = bytearray(iv)
    ivb[8] &= 0x7F
    prefix = bytes(ivb[:8])
    ctr_init = int.from_bytes(ivb[8:], "big")
    ctr = Counter.new(64, prefix=prefix, initial_value=ctr_init, little_endian=False)
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    return cipher.decrypt(ciphertext)


def _aes_ctr256_encrypt(*, key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    from Crypto.Cipher import AES
    from Crypto.Util import Counter

    ivb = bytearray(iv)
    ivb[8] &= 0x7F
    prefix = bytes(ivb[:8])
    ctr_init = int.from_bytes(ivb[8:], "big")
    ctr = Counter.new(64, prefix=prefix, initial_value=ctr_init, little_endian=False)
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    return cipher.encrypt(plaintext)


def _validate_secret_storage_key(secret_key: bytes, key_desc: dict[str, Any]) -> None:
    """Raise if secret_key does not match the key description (iv/mac check)."""
    if key_desc.get("algorithm") != "m.secret_storage.v1.aes-hmac-sha2":
        raise ValueError(f"unsupported secret storage algorithm: {key_desc.get('algorithm')!r}")
    iv = decode_base64(key_desc["iv"])
    expected_mac = decode_base64(key_desc["mac"])
    aes_mac = hkdf_sha256_element_secret_storage(ikm=secret_key, info=b"", length=64)
    aes_key, mac_key = aes_mac[:32], aes_mac[32:]
    ct = _aes_ctr256_encrypt(key=aes_key, iv=iv, plaintext=b"\x00" * 32)
    mac = hmac.new(mac_key, ct, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, expected_mac):
        raise ValueError("recovery key / passphrase does not match Secret Storage (MAC check failed)")


def _derive_secret_key_from_passphrase(passphrase: str, key_desc: dict[str, Any]) -> bytes:
    pp = key_desc.get("passphrase") or {}
    if pp.get("algorithm") != "m.pbkdf2":
        raise ValueError("Secret Storage key requires a passphrase but no m.pbkdf2 parameters were found")
    salt = decode_base64(pp["salt"])
    iterations = int(pp["iterations"])
    if iterations < 1:
        raise ValueError("invalid PBKDF2 iterations")
    bits = int(pp.get("bits", 256))
    if bits != 256:
        raise ValueError(f"unsupported PBKDF2 bits: {bits}")
    dk = hashlib.pbkdf2_hmac("sha512", passphrase.encode("utf-8"), salt, iterations, dklen=32)
    return dk


def _decrypt_secret(
    *,
    secret_name: str,
    secret_key: bytes,
    encrypted_blob: dict[str, Any],
) -> bytes:
    """Decrypt one AesHmacSha2EncryptedData block (iv, ciphertext, mac)."""
    iv = decode_base64(encrypted_blob["iv"])
    ciphertext = decode_base64(encrypted_blob["ciphertext"])
    expected_mac = decode_base64(encrypted_blob["mac"])
    aes_mac = hkdf_sha256_element_secret_storage(ikm=secret_key, info=secret_name.encode("utf-8"), length=64)
    aes_key, mac_key = aes_mac[:32], aes_mac[32:]
    mac = hmac.new(mac_key, ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, expected_mac):
        raise ValueError(f"HMAC mismatch decrypting {secret_name}")
    return _aes_ctr256_decrypt(key=aes_key, iv=iv, ciphertext=ciphertext)


def _matrix_api_url(homeserver: str, path: str) -> str:
    base = homeserver.rstrip("/") + "/"
    return urljoin(base, path.lstrip("/"))


async def _get_json(
    session: aiohttp.ClientSession,
    homeserver: str,
    access_token: str,
    path: str,
) -> tuple[int, Any]:
    url = _matrix_api_url(homeserver, path)
    headers = {"Authorization": f"Bearer {access_token}"}
    async with session.get(url, headers=headers, timeout=_MATRIX_HTTP_TIMEOUT) as resp:
        text = await resp.text()
        if resp.status == 404:
            return resp.status, None
        try:
            data = json.loads(text) if text else None
        except json.JSONDecodeError:
            data = text
        return resp.status, data


async def _post_json(
    session: aiohttp.ClientSession,
    homeserver: str,
    access_token: str,
    path: str,
    body: dict[str, Any],
) -> tuple[int, Any]:
    url = _matrix_api_url(homeserver, path)
    headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}
    async with session.post(
        url, headers=headers, json=body, timeout=_MATRIX_HTTP_TIMEOUT
    ) as resp:
        text = await resp.text()
        try:
            data = json.loads(text) if text else None
        except json.JSONDecodeError:
            data = text
        return resp.status, data


def _canonical_json_for_signing(obj: dict[str, Any]) -> str:
    from nio.api import Api

    signing = {k: v for k, v in obj.items() if k not in ("signatures", "unsigned")}
    return Api.to_canonical_json(signing)


def _device_has_self_signing_sig(device: dict[str, Any], user_id: str, self_signing_pub: str) -> bool:
    sigs = device.get("signatures") or {}
    user_sigs = sigs.get(user_id) or {}
    return f"ed25519:{self_signing_pub}" in user_sigs


async def bootstrap_cross_signing_from_recovery(
    client: AsyncClient, matrix_config: _MatrixRecoveryConfig
) -> None:
    """
    If recoveryKey or recoveryPassphrase is set, ensure this device is signed by the
    self-signing key (idempotent). Never logs secrets.
    """
    recovery_key = getattr(matrix_config, "recovery_key", "") or ""
    recovery_passphrase = getattr(matrix_config, "recovery_passphrase", "") or ""
    if not recovery_key.strip() and not recovery_passphrase.strip():
        return

    homeserver = client.homeserver
    access_token = client.access_token
    user_id = client.user_id
    device_id = client.device_id
    if not homeserver or not access_token or not user_id or not device_id:
        logger.error("Matrix cross-signing bootstrap skipped: client not fully logged in")
        return

    try:
        await _bootstrap_cross_signing_from_recovery_impl(
            homeserver=homeserver,
            access_token=access_token,
            user_id=user_id,
            device_id=device_id,
            recovery_key=recovery_key.strip(),
            recovery_passphrase=recovery_passphrase,
        )
    except Exception as e:
        logger.error("Matrix cross-signing recovery failed (channel continues): {}", e)


async def _bootstrap_cross_signing_from_recovery_impl(
    *,
    homeserver: str,
    access_token: str,
    user_id: str,
    device_id: str,
    recovery_key: str,
    recovery_passphrase: str,
) -> None:
    async with aiohttp.ClientSession() as session:
        # --- default Secret Storage key id ---
        uid_q = quote(user_id, safe="")
        st, default_key = await _get_json(
            session,
            homeserver,
            access_token,
            f"_matrix/client/v3/user/{uid_q}/account_data/m.secret_storage.default_key",
        )
        if st != 200:
            raise RuntimeError(
                f"failed to fetch m.secret_storage.default_key: HTTP {st}"
                + (f" ({default_key!r})" if isinstance(default_key, (dict, str)) else "")
            )
        if not isinstance(default_key, dict) or "key" not in default_key:
            raise RuntimeError(
                "no m.secret_storage.default_key in account data — set up "
                "Encryption / Secure Backup in Element once, then retry"
            )

        key_id = str(default_key["key"])
        st, key_desc = await _get_json(
            session,
            homeserver,
            access_token,
            f"_matrix/client/v3/user/{uid_q}/account_data/m.secret_storage.key.{quote(key_id, safe='')}",
        )
        if st != 200:
            raise RuntimeError(
                f"failed to fetch secret storage key description {key_id!r}: HTTP {st}"
                + (f" ({key_desc!r})" if isinstance(key_desc, (dict, str)) else "")
            )
        if not isinstance(key_desc, dict):
            raise RuntimeError(f"secret storage key description {key_id!r} is not a JSON object")

        secret_key: bytes
        if recovery_key:
            secret_key = decode_matrix_recovery_key(recovery_key)
        else:
            secret_key = _derive_secret_key_from_passphrase(recovery_passphrase, key_desc)

        _validate_secret_storage_key(secret_key, key_desc)

        # --- encrypted self-signing seed ---
        st, ss_event = await _get_json(
            session,
            homeserver,
            access_token,
            f"_matrix/client/v3/user/{uid_q}/account_data/m.cross_signing.self_signing",
        )
        if st != 200:
            if st == 404:
                raise RuntimeError(
                    "no m.cross_signing.self_signing in account data — enable cross-signing in Element first"
                )
            raise RuntimeError(
                f"failed to fetch m.cross_signing.self_signing: HTTP {st}"
                + (f" ({ss_event!r})" if isinstance(ss_event, (dict, str)) else "")
            )
        if not isinstance(ss_event, dict):
            raise RuntimeError("m.cross_signing.self_signing response is not a JSON object")

        enc_map = ss_event.get("encrypted") or {}
        if key_id not in enc_map:
            raise RuntimeError(
                f"self-signing secret is not encrypted with default key {key_id!r}; cannot decrypt"
            )
        blob = enc_map[key_id]
        if not isinstance(blob, dict):
            raise RuntimeError(f"encrypted self-signing payload for key {key_id!r} is not an object")
        plaintext = _decrypt_secret(
            secret_name="m.cross_signing.self_signing",
            secret_key=secret_key,
            encrypted_blob=blob,
        )
        inner = plaintext.decode("utf-8").strip().strip('"')
        try:
            seed = decode_base64(inner)
        except (ValueError, UnicodeDecodeError) as e:
            raise ValueError("self-signing secret is not valid base64 text") from e

        if len(seed) != 32:
            raise ValueError("decoded self-signing seed is not 32 bytes")

        pk = olm.PkSigning(seed)
        self_pub = pk.public_key

        # --- keys/query for device + published self-signing public key ---
        st, kq = await _post_json(
            session,
            homeserver,
            access_token,
            "_matrix/client/v3/keys/query",
            {"device_keys": {user_id: []}},
        )
        if st != 200 or not isinstance(kq, dict):
            raise RuntimeError(f"keys/query failed: HTTP {st}")

        self_block = (kq.get("self_signing_keys") or {}).get(user_id)
        if not isinstance(self_block, dict):
            raise RuntimeError("keys/query response missing self_signing_keys for this user")

        published = (self_block.get("keys") or {}).get(f"ed25519:{self_pub}")
        if published != self_pub:
            raise RuntimeError(
                "recovered self-signing seed does not match the self-signing key on the server — "
                "Secret Storage may be out of sync with uploaded cross-signing keys"
            )

        dev_map = (kq.get("device_keys") or {}).get(user_id) or {}
        device = dev_map.get(device_id)
        if not isinstance(device, dict):
            raise RuntimeError(f"keys/query did not return keys for device {device_id!r}")

        if _device_has_self_signing_sig(device, user_id, self_pub):
            logger.info("Matrix device {} already has self-signing signature; skipping upload", device_id)
            return

        canonical = _canonical_json_for_signing(device)
        sig = pk.sign(canonical)
        olm.ed25519_verify(self_pub, canonical, sig)

        new_sigs_user = dict((device.get("signatures") or {}).get(user_id, {}))
        new_sigs_user[f"ed25519:{self_pub}"] = sig
        new_signatures = dict(device.get("signatures") or {})
        new_signatures[user_id] = new_sigs_user

        upload_device = dict(device)
        upload_device["signatures"] = new_signatures

        body = {user_id: {device_id: upload_device}}
        st, resp = await _post_json(
            session,
            homeserver,
            access_token,
            "_matrix/client/v3/keys/signatures/upload",
            body,
        )
        if st != 200:
            raise RuntimeError(f"keys/signatures/upload failed: HTTP {st}: {resp!r}")

        failures = (resp or {}).get("failures") or {}
        user_fail = failures.get(user_id) or {}
        if device_id in user_fail:
            raise RuntimeError(f"keys/signatures/upload rejected signature: {user_fail[device_id]!r}")
        if failures:
            logger.warning("Matrix keys/signatures/upload reported unrelated failures: {}", failures)

        logger.info(
            "Matrix cross-signing: uploaded self-signing signature for device {} (you may remove recoveryKey from config)",
            device_id,
        )
