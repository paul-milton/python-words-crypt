import pytest
from words_crypt.cli import WordZipEnvelope, MAGIC


class TestWordZipEnvelope:
    def test_roundtrip(self):
        env = WordZipEnvelope(
            kind="zip",
            filename="test.zip",
            meta_json=b'{"key":"val"}',
            payload=b"hello world",
        )
        raw = env.to_bytes()
        restored = WordZipEnvelope.from_bytes(raw)
        assert restored.kind == "zip"
        assert restored.filename == "test.zip"
        assert restored.meta_json == b'{"key":"val"}'
        assert restored.payload == b"hello world"

    def test_roundtrip_raw_kind(self):
        env = WordZipEnvelope(
            kind="raw",
            filename="data.bin",
            meta_json=b"{}",
            payload=b"\x00\xff" * 100,
        )
        restored = WordZipEnvelope.from_bytes(env.to_bytes())
        assert restored.kind == "raw"
        assert restored.filename == "data.bin"
        assert restored.payload == b"\x00\xff" * 100

    def test_empty_meta_serialized_as_braces(self):
        env = WordZipEnvelope(kind="raw", filename="f", meta_json=b"", payload=b"x")
        raw = env.to_bytes()
        restored = WordZipEnvelope.from_bytes(raw)
        assert restored.meta_json == b"{}"

    def test_bad_magic_raises(self):
        with pytest.raises(ValueError, match="bad magic"):
            WordZipEnvelope.from_bytes(b"XXXX" + b"\x00" * 20)

    def test_too_short_raises(self):
        with pytest.raises(ValueError):
            WordZipEnvelope.from_bytes(b"WZ")

    def test_truncated_payload_raises(self):
        env = WordZipEnvelope(kind="raw", filename="f", meta_json=b"{}", payload=b"data")
        raw = env.to_bytes()
        # Truncate the last few bytes so payload_len doesn't match
        with pytest.raises(ValueError, match="Truncated"):
            WordZipEnvelope.from_bytes(raw[:-2])

    def test_starts_with_magic(self):
        env = WordZipEnvelope(kind="zip", filename="f", meta_json=b"{}", payload=b"")
        raw = env.to_bytes()
        assert raw[:4] == MAGIC

    def test_empty_payload(self):
        env = WordZipEnvelope(kind="raw", filename="empty.bin", meta_json=b"{}", payload=b"")
        restored = WordZipEnvelope.from_bytes(env.to_bytes())
        assert restored.payload == b""
