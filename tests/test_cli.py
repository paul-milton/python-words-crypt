import hashlib
import zipfile
import pytest
from unittest.mock import patch
from pathlib import Path
from click.testing import CliRunner

from words_crypt.cli import (
    cli,
    SALT_LEN,
    NONCE_LEN,
    KEY_LEN,
)


FIXED_SALT = b"\x11" * SALT_LEN
FIXED_NONCE = b"\x22" * NONCE_LEN


def _mock_urandom(n):
    if n == SALT_LEN:
        return FIXED_SALT
    if n == NONCE_LEN:
        return FIXED_NONCE
    return b"\x00" * n


def _fast_scrypt(password, *, salt, n, r, p, dklen):
    """Fast KDF mock: sha256 instead of real scrypt."""
    return hashlib.sha256(password + salt).digest()[:dklen]


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture(autouse=True)
def mock_crypto():
    """Mock urandom + scrypt for all CLI tests."""
    with patch("words_crypt.cli.os.urandom", side_effect=_mock_urandom), \
         patch("words_crypt.cli.hashlib.scrypt", side_effect=_fast_scrypt):
        yield


# ── enc-file ──────────────────────────────────────────────────

class TestEncFile:
    def test_stdout(self, runner, tmp_path, fake_wordlist_path):
        src = tmp_path / "secret.txt"
        src.write_text("secret data", encoding="utf-8")

        result = runner.invoke(cli, [
            "--wordlist", fake_wordlist_path,
            "--passphrase", "testpass",
            "enc-file", str(src),
        ])
        assert result.exit_code == 0
        assert len(result.output.strip().split()) > 0

    def test_to_file_zip_default(self, runner, tmp_path, fake_wordlist_path):
        """--out creates a zip by default."""
        src = tmp_path / "input.bin"
        src.write_bytes(b"\x00\x01\x02\x03")
        out = tmp_path / "phrase.txt"

        result = runner.invoke(cli, [
            "--wordlist", fake_wordlist_path,
            "--passphrase", "pass",
            "enc-file", str(src), "--out", str(out),
        ])
        assert result.exit_code == 0
        zip_path = tmp_path / "phrase.txt.zip"
        assert zip_path.exists()
        assert zipfile.is_zipfile(zip_path)

    def test_to_file_no_zip(self, runner, tmp_path, fake_wordlist_path):
        """--no-zip writes plain text."""
        src = tmp_path / "input.bin"
        src.write_bytes(b"\x00\x01\x02\x03")
        out = tmp_path / "phrase.txt"

        result = runner.invoke(cli, [
            "--wordlist", fake_wordlist_path,
            "--passphrase", "pass",
            "enc-file", str(src), "--out", str(out), "--no-zip",
        ])
        assert result.exit_code == 0
        assert out.exists()
        assert len(out.read_text(encoding="utf-8").strip()) > 0

    def test_to_file_dot_zip_no_double_ext(self, runner, tmp_path, fake_wordlist_path):
        """--out phrase.zip doesn't create phrase.zip.zip."""
        src = tmp_path / "input.bin"
        src.write_bytes(b"data")
        out = tmp_path / "phrase.zip"

        result = runner.invoke(cli, [
            "--wordlist", fake_wordlist_path,
            "--passphrase", "pass",
            "enc-file", str(src), "--out", str(out),
        ])
        assert result.exit_code == 0
        assert out.exists()
        assert not (tmp_path / "phrase.zip.zip").exists()

    def test_from_stdin(self, runner, fake_wordlist_path):
        result = runner.invoke(cli, [
            "--wordlist", fake_wordlist_path,
            "--passphrase", "testpass",
            "enc-file",
        ], input=b"hello from stdin")

        assert result.exit_code == 0
        assert len(result.output.strip().split()) > 0

    def test_file_not_found(self, runner, fake_wordlist_path):
        result = runner.invoke(cli, [
            "--wordlist", fake_wordlist_path,
            "--passphrase", "pass",
            "enc-file", "/nonexistent/file.txt",
        ])
        assert result.exit_code != 0


# ── dec-file ──────────────────────────────────────────────────

class TestDecFile:
    def test_roundtrip_zip(self, runner, tmp_path, fake_wordlist_path):
        """Roundtrip: enc-file --out (zip) → dec-file --phrase-file (auto-detect zip)."""
        src = tmp_path / "original.txt"
        src.write_text("original content", encoding="utf-8")
        out = tmp_path / "phrase.txt"

        result = runner.invoke(cli, [
            "--wordlist", fake_wordlist_path,
            "--passphrase", "pass123",
            "enc-file", str(src), "--out", str(out),
        ])
        assert result.exit_code == 0

        zip_path = tmp_path / "phrase.txt.zip"
        out_file = tmp_path / "recovered.txt"
        result = runner.invoke(cli, [
            "--wordlist", fake_wordlist_path,
            "--passphrase", "pass123",
            "dec-file", "--out", str(out_file), "--phrase-file", str(zip_path),
        ])
        assert result.exit_code == 0
        assert out_file.read_text(encoding="utf-8") == "original content"

    def test_roundtrip_no_zip(self, runner, tmp_path, fake_wordlist_path):
        """Roundtrip with plain text phrase file."""
        src = tmp_path / "original.txt"
        src.write_text("original content", encoding="utf-8")
        phrase_file = tmp_path / "phrase.txt"

        result = runner.invoke(cli, [
            "--wordlist", fake_wordlist_path,
            "--passphrase", "pass123",
            "enc-file", str(src), "--out", str(phrase_file), "--no-zip",
        ])
        assert result.exit_code == 0

        out_file = tmp_path / "recovered.txt"
        result = runner.invoke(cli, [
            "--wordlist", fake_wordlist_path,
            "--passphrase", "pass123",
            "dec-file", "--out", str(out_file), "--phrase-file", str(phrase_file),
        ])
        assert result.exit_code == 0
        assert out_file.read_text(encoding="utf-8") == "original content"

    def test_to_stdout(self, runner, tmp_path, fake_wordlist_path):
        src = tmp_path / "data.txt"
        src.write_text("stdout test", encoding="utf-8")
        phrase_file = tmp_path / "phrase.txt"

        result = runner.invoke(cli, [
            "--wordlist", fake_wordlist_path,
            "--passphrase", "pass",
            "enc-file", str(src), "--out", str(phrase_file), "--no-zip",
        ])
        assert result.exit_code == 0

        result = runner.invoke(cli, [
            "--wordlist", fake_wordlist_path,
            "--passphrase", "pass",
            "dec-file", "--phrase-file", str(phrase_file),
        ])
        assert result.exit_code == 0
        assert b"stdout test" in result.output.encode("latin-1")

    def test_stdin_to_file(self, runner, tmp_path, fake_wordlist_path):
        src = tmp_path / "input.txt"
        src.write_text("stdin roundtrip", encoding="utf-8")
        phrase_file = tmp_path / "phrase.txt"

        result = runner.invoke(cli, [
            "--wordlist", fake_wordlist_path,
            "--passphrase", "p",
            "enc-file", str(src), "--out", str(phrase_file), "--no-zip",
        ])
        assert result.exit_code == 0

        phrase_text = phrase_file.read_text(encoding="utf-8")
        out_file = tmp_path / "recovered.txt"
        result = runner.invoke(cli, [
            "--wordlist", fake_wordlist_path,
            "--passphrase", "p",
            "dec-file", "--out", str(out_file),
        ], input=phrase_text)
        assert result.exit_code == 0
        assert out_file.read_text(encoding="utf-8") == "stdin roundtrip"

    def test_roundtrip_binary(self, runner, tmp_path, fake_wordlist_path):
        """Roundtrip with binary payload via zip."""
        src = tmp_path / "binary.bin"
        payload = bytes(range(256)) * 4
        src.write_bytes(payload)
        out = tmp_path / "phrase.txt"

        result = runner.invoke(cli, [
            "--wordlist", fake_wordlist_path,
            "--passphrase", "binpass",
            "enc-file", str(src), "--out", str(out),
        ])
        assert result.exit_code == 0

        zip_path = tmp_path / "phrase.txt.zip"
        out_file = tmp_path / "recovered.bin"
        result = runner.invoke(cli, [
            "--wordlist", fake_wordlist_path,
            "--passphrase", "binpass",
            "dec-file", "--out", str(out_file), "--phrase-file", str(zip_path),
        ])
        assert result.exit_code == 0
        assert out_file.read_bytes() == payload


# ── enc-files ─────────────────────────────────────────────────

class TestEncFiles:
    def test_roundtrip_multiple_files(self, runner, tmp_path, fake_wordlist_path):
        f1 = tmp_path / "a.txt"
        f1.write_text("content A", encoding="utf-8")
        f2 = tmp_path / "b.txt"
        f2.write_text("content B", encoding="utf-8")
        out = tmp_path / "phrase.txt"

        result = runner.invoke(cli, [
            "--wordlist", fake_wordlist_path,
            "--passphrase", "archivepass",
            "enc-files", str(f1), str(f2), "--out", str(out),
        ])
        assert result.exit_code == 0

        zip_path = tmp_path / "phrase.txt.zip"
        out_dir = tmp_path / "extracted"
        result = runner.invoke(cli, [
            "--wordlist", fake_wordlist_path,
            "--passphrase", "archivepass",
            "dec-file", "--out-dir", str(out_dir), "--phrase-file", str(zip_path),
        ])
        assert result.exit_code == 0
        assert (out_dir / "a.txt").read_text(encoding="utf-8") == "content A"
        assert (out_dir / "b.txt").read_text(encoding="utf-8") == "content B"

    def test_roundtrip_directory(self, runner, tmp_path, fake_wordlist_path):
        sub = tmp_path / "mydir"
        sub.mkdir()
        (sub / "x.txt").write_text("X", encoding="utf-8")
        (sub / "y.txt").write_text("Y", encoding="utf-8")
        out = tmp_path / "phrase.txt"

        result = runner.invoke(cli, [
            "--wordlist", fake_wordlist_path,
            "--passphrase", "dirpass",
            "enc-files", str(sub), "--out", str(out),
        ])
        assert result.exit_code == 0

        zip_path = tmp_path / "phrase.txt.zip"
        out_dir = tmp_path / "out"
        result = runner.invoke(cli, [
            "--wordlist", fake_wordlist_path,
            "--passphrase", "dirpass",
            "dec-file", "--out-dir", str(out_dir), "--phrase-file", str(zip_path),
        ])
        assert result.exit_code == 0
        assert (out_dir / "mydir" / "x.txt").read_text(encoding="utf-8") == "X"
        assert (out_dir / "mydir" / "y.txt").read_text(encoding="utf-8") == "Y"

    def test_tar_requires_out_dir(self, runner, tmp_path, fake_wordlist_path):
        f1 = tmp_path / "a.txt"
        f1.write_text("data", encoding="utf-8")
        out = tmp_path / "phrase.txt"

        runner.invoke(cli, [
            "--wordlist", fake_wordlist_path,
            "--passphrase", "pass",
            "enc-files", str(f1), "--out", str(out),
        ])

        zip_path = tmp_path / "phrase.txt.zip"
        result = runner.invoke(cli, [
            "--wordlist", fake_wordlist_path,
            "--passphrase", "pass",
            "dec-file", "--phrase-file", str(zip_path),
        ])
        assert result.exit_code != 0


# ── errors ────────────────────────────────────────────────────

class TestCliErrors:
    def test_wrong_passphrase(self, runner, tmp_path, fake_wordlist_path):
        src = tmp_path / "file.txt"
        src.write_text("data", encoding="utf-8")
        out = tmp_path / "phrase.txt"

        runner.invoke(cli, [
            "--wordlist", fake_wordlist_path,
            "--passphrase", "correct",
            "enc-file", str(src), "--out", str(out),
        ])

        zip_path = tmp_path / "phrase.txt.zip"
        out_file = tmp_path / "out.txt"
        result = runner.invoke(cli, [
            "--wordlist", fake_wordlist_path,
            "--passphrase", "wrong",
            "dec-file", "--out", str(out_file), "--phrase-file", str(zip_path),
        ])
        assert result.exit_code != 0
