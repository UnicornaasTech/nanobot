"""Unit tests for Matrix MSC3245 voice message helpers."""

from pathlib import Path

from nanobot.channels.matrix.voice import (
    build_voice_message_content,
    default_waveform,
    parse_matrix_voice_metadata,
    resolve_voice_duration_ms,
    resolve_voice_waveform,
    voice_mime_for_path,
)


def test_parse_matrix_voice_metadata_true_marks_all_paths(tmp_path) -> None:
    first = tmp_path / "a.ogg"
    second = tmp_path / "b.ogg"
    voice_paths, hints = parse_matrix_voice_metadata({"_matrix_voice": True}, [first, second])
    assert len(voice_paths) == 2
    assert hints == {}


def test_parse_matrix_voice_metadata_paths_subset(tmp_path) -> None:
    first = tmp_path / "a.ogg"
    second = tmp_path / "b.ogg"
    voice_paths, hints = parse_matrix_voice_metadata(
        {"_matrix_voice": {"paths": [str(first)], "duration_ms": 500}},
        [first, second],
    )
    assert len(voice_paths) == 1
    assert hints["duration_ms"] == 500


def test_build_voice_message_content_includes_msc3245_fields() -> None:
    content = build_voice_message_content(
        mime="audio/ogg",
        size_bytes=42,
        duration_ms=1500,
        waveform=default_waveform(3),
        mxc_url="mxc://example.org/abc",
    )
    assert content["msgtype"] == "m.audio"
    assert content["body"] == "Voice message"
    assert content["org.matrix.msc3245.voice"] == {}
    assert content["org.matrix.msc1767.audio"]["duration"] == 1500


def test_build_voice_message_content_encrypted_uses_file_block() -> None:
    encryption_info = {
        "v": "v2",
        "iv": "iv",
        "hashes": {"sha256": "hash"},
        "key": {"alg": "A256CTR", "k": "key"},
    }
    content = build_voice_message_content(
        mime="audio/ogg",
        size_bytes=42,
        duration_ms=1500,
        waveform=[0, 1, 2],
        mxc_url="mxc://example.org/abc",
        encryption_info=encryption_info,
    )
    assert "url" not in content
    assert content["file"]["url"] == "mxc://example.org/abc"
    assert "url" not in content["org.matrix.msc1767.file"]
    assert content["org.matrix.msc1767.file"]["file"]["url"] == "mxc://example.org/abc"


def test_voice_mime_for_path_prefers_ogg() -> None:
    assert voice_mime_for_path(Path("x.ogg"), "application/octet-stream") == "audio/ogg"


def test_resolve_voice_duration_ms_prefers_hint(tmp_path) -> None:
    path = tmp_path / "x.ogg"
    path.write_bytes(b"x")
    assert resolve_voice_duration_ms(path, {"duration_ms": 3210}) == 3210


def test_resolve_voice_waveform_clamps_values() -> None:
    waveform = resolve_voice_waveform({"waveform": [-5, 512, 9999]})
    assert waveform == [0, 512, 1024]
