import pytest
from mnemo_vault.cli import MnemoEnvelope, MAGIC


class TestMnemoEnvelope:
    def test_roundtrip(self):
        env = MnemoEnvelope(
            kind="zip",
            filename="test.zip",
            meta_json=b'{"key":"val"}',
            payload=b"hello world",
        )
        raw = env.to_bytes()
        restored = MnemoEnvelope.from_bytes(raw)
        assert restored.kind == "zip"
        assert restored.filename == "test.zip"
        assert restored.meta_json == b'{"key":"val"}'
        assert restored.payload == b"hello world"

    def test_roundtrip_raw_kind(self):
        env = MnemoEnvelope(
            kind="raw",
            filename="data.bin",
            meta_json=b"{}",
            payload=b"\x00\xff" * 100,
        )
        restored = MnemoEnvelope.from_bytes(env.to_bytes())
        assert restored.kind == "raw"
        assert restored.filename == "data.bin"
        assert restored.payload == b"\x00\xff" * 100

    def test_empty_meta_serialized_as_braces(self):
        env = MnemoEnvelope(kind="raw", filename="f", meta_json=b"", payload=b"x")
        raw = env.to_bytes()
        restored = MnemoEnvelope.from_bytes(raw)
        assert restored.meta_json == b"{}"

    def test_bad_magic_raises(self):
        with pytest.raises(ValueError, match="bad magic"):
            MnemoEnvelope.from_bytes(b"XXXX" + b"\x00" * 20)

    def test_too_short_raises(self):
        with pytest.raises(ValueError):
            MnemoEnvelope.from_bytes(b"WZ")

    def test_truncated_payload_raises(self):
        env = MnemoEnvelope(kind="raw", filename="f", meta_json=b"{}", payload=b"data")
        raw = env.to_bytes()
        # Truncate the last few bytes so payload_len doesn't match
        with pytest.raises(ValueError, match="Truncated"):
            MnemoEnvelope.from_bytes(raw[:-2])

    def test_starts_with_magic(self):
        env = MnemoEnvelope(kind="zip", filename="f", meta_json=b"{}", payload=b"")
        raw = env.to_bytes()
        assert raw[:4] == MAGIC

    def test_empty_payload(self):
        env = MnemoEnvelope(kind="raw", filename="empty.bin", meta_json=b"{}", payload=b"")
        restored = MnemoEnvelope.from_bytes(env.to_bytes())
        assert restored.payload == b""
