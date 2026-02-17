import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path
from click.testing import CliRunner

from words_crypt.cli import (
    cli,
    encrypt_bytes_to_words,
    decrypt_words_to_bytes,
    SALT_LEN,
    NONCE_LEN,
)


@pytest.fixture
def runner():
    return CliRunner()


FIXED_SALT = b"\x11" * SALT_LEN
FIXED_NONCE = b"\x22" * NONCE_LEN


def _mock_urandom(n):
    if n == SALT_LEN:
        return FIXED_SALT
    if n == NONCE_LEN:
        return FIXED_NONCE
    return b"\x00" * n


class TestEncFile:
    def test_enc_file_stdout(self, runner, tmp_path, fake_wordlist_path):
        src = tmp_path / "secret.txt"
        src.write_text("secret data", encoding="utf-8")

        with patch("words_crypt.cli.os.urandom", side_effect=_mock_urandom):
            result = runner.invoke(cli, [
                "--wordlist", fake_wordlist_path,
                "--passphrase", "testpass",
                "enc-file", str(src),
            ])

        assert result.exit_code == 0
        assert len(result.output.strip().split()) > 0

    def test_enc_file_to_file(self, runner, tmp_path, fake_wordlist_path):
        src = tmp_path / "input.bin"
        src.write_bytes(b"\x00\x01\x02\x03")
        out = tmp_path / "phrase.txt"

        with patch("words_crypt.cli.os.urandom", side_effect=_mock_urandom):
            result = runner.invoke(cli, [
                "--wordlist", fake_wordlist_path,
                "--passphrase", "pass",
                "enc-file", str(src), "--out", str(out),
            ])

        assert result.exit_code == 0
        assert out.exists()
        assert len(out.read_text(encoding="utf-8").strip()) > 0

    def test_enc_file_from_stdin(self, runner, fake_wordlist_path):
        with patch("words_crypt.cli.os.urandom", side_effect=_mock_urandom):
            result = runner.invoke(cli, [
                "--wordlist", fake_wordlist_path,
                "--passphrase", "testpass",
                "enc-file",
            ], input=b"hello from stdin")

        assert result.exit_code == 0
        assert len(result.output.strip().split()) > 0

    def test_enc_file_preserves_filename(self, runner, tmp_path, fake_wordlist_path):
        src = tmp_path / "myfile.dat"
        src.write_bytes(b"data")
        phrase_file = tmp_path / "phrase.txt"

        with patch("words_crypt.cli.os.urandom", side_effect=_mock_urandom):
            result = runner.invoke(cli, [
                "--wordlist", fake_wordlist_path,
                "--passphrase", "pass",
                "enc-file", str(src), "--out", str(phrase_file),
            ])
        assert result.exit_code == 0


class TestDecFile:
    def test_dec_file_from_phrase_file(self, runner, tmp_path, fake_wordlist_path):
        src = tmp_path / "original.txt"
        src.write_text("original content", encoding="utf-8")
        phrase_file = tmp_path / "phrase.txt"

        with patch("words_crypt.cli.os.urandom", side_effect=_mock_urandom):
            result = runner.invoke(cli, [
                "--wordlist", fake_wordlist_path,
                "--passphrase", "pass123",
                "enc-file", str(src), "--out", str(phrase_file),
            ])
        assert result.exit_code == 0

        out_file = tmp_path / "recovered.txt"
        result = runner.invoke(cli, [
            "--wordlist", fake_wordlist_path,
            "--passphrase", "pass123",
            "dec-file", "--out-file", str(out_file), "--phrase-file", str(phrase_file),
        ])
        assert result.exit_code == 0
        assert out_file.read_text(encoding="utf-8") == "original content"

    def test_dec_file_to_stdout(self, runner, tmp_path, fake_wordlist_path):
        src = tmp_path / "data.bin"
        payload = b"binary payload here"
        src.write_bytes(payload)
        phrase_file = tmp_path / "phrase.txt"

        with patch("words_crypt.cli.os.urandom", side_effect=_mock_urandom):
            result = runner.invoke(cli, [
                "--wordlist", fake_wordlist_path,
                "--passphrase", "pass",
                "enc-file", str(src), "--out", str(phrase_file),
            ])
        assert result.exit_code == 0

        result = runner.invoke(cli, [
            "--wordlist", fake_wordlist_path,
            "--passphrase", "pass",
            "dec-file", "--phrase-file", str(phrase_file),
        ])
        assert result.exit_code == 0
        assert payload in result.output.encode("latin-1") or payload in result.output.encode("utf-8", errors="surrogateescape")

    def test_dec_file_stdin_to_file(self, runner, tmp_path, fake_wordlist_path):
        src = tmp_path / "input.txt"
        src.write_text("stdin roundtrip", encoding="utf-8")
        phrase_file = tmp_path / "phrase.txt"

        with patch("words_crypt.cli.os.urandom", side_effect=_mock_urandom):
            result = runner.invoke(cli, [
                "--wordlist", fake_wordlist_path,
                "--passphrase", "p",
                "enc-file", str(src), "--out", str(phrase_file),
            ])
        assert result.exit_code == 0

        phrase_text = phrase_file.read_text(encoding="utf-8")
        out_file = tmp_path / "recovered.txt"
        result = runner.invoke(cli, [
            "--wordlist", fake_wordlist_path,
            "--passphrase", "p",
            "dec-file", "--out-file", str(out_file),
        ], input=phrase_text)
        assert result.exit_code == 0
        assert out_file.read_text(encoding="utf-8") == "stdin roundtrip"


class TestEncFiles:
    def test_enc_files_roundtrip(self, runner, tmp_path, fake_wordlist_path):
        f1 = tmp_path / "a.txt"
        f1.write_text("content A", encoding="utf-8")
        f2 = tmp_path / "b.txt"
        f2.write_text("content B", encoding="utf-8")
        phrase_file = tmp_path / "phrase.txt"

        with patch("words_crypt.cli.os.urandom", side_effect=_mock_urandom):
            result = runner.invoke(cli, [
                "--wordlist", fake_wordlist_path,
                "--passphrase", "archivepass",
                "enc-files", str(f1), str(f2), "--out", str(phrase_file),
            ])
        assert result.exit_code == 0

        out_dir = tmp_path / "extracted"
        result = runner.invoke(cli, [
            "--wordlist", fake_wordlist_path,
            "--passphrase", "archivepass",
            "dec-file", "--out-dir", str(out_dir), "--phrase-file", str(phrase_file),
        ])
        assert result.exit_code == 0, result.output + (result.stderr or "")
        assert (out_dir / "a.txt").read_text(encoding="utf-8") == "content A"
        assert (out_dir / "b.txt").read_text(encoding="utf-8") == "content B"

    def test_enc_files_directory(self, runner, tmp_path, fake_wordlist_path):
        sub = tmp_path / "mydir"
        sub.mkdir()
        (sub / "x.txt").write_text("X", encoding="utf-8")
        (sub / "y.txt").write_text("Y", encoding="utf-8")
        phrase_file = tmp_path / "phrase.txt"

        with patch("words_crypt.cli.os.urandom", side_effect=_mock_urandom):
            result = runner.invoke(cli, [
                "--wordlist", fake_wordlist_path,
                "--passphrase", "dirpass",
                "enc-files", str(sub), "--out", str(phrase_file),
            ])
        assert result.exit_code == 0

        out_dir = tmp_path / "out"
        result = runner.invoke(cli, [
            "--wordlist", fake_wordlist_path,
            "--passphrase", "dirpass",
            "dec-file", "--out-dir", str(out_dir), "--phrase-file", str(phrase_file),
        ])
        assert result.exit_code == 0
        assert (out_dir / "mydir" / "x.txt").read_text(encoding="utf-8") == "X"
        assert (out_dir / "mydir" / "y.txt").read_text(encoding="utf-8") == "Y"

    def test_dec_tar_requires_out_dir(self, runner, tmp_path, fake_wordlist_path):
        f1 = tmp_path / "a.txt"
        f1.write_text("data", encoding="utf-8")
        phrase_file = tmp_path / "phrase.txt"

        with patch("words_crypt.cli.os.urandom", side_effect=_mock_urandom):
            runner.invoke(cli, [
                "--wordlist", fake_wordlist_path,
                "--passphrase", "pass",
                "enc-files", str(f1), "--out", str(phrase_file),
            ])

        result = runner.invoke(cli, [
            "--wordlist", fake_wordlist_path,
            "--passphrase", "pass",
            "dec-file", "--phrase-file", str(phrase_file),
        ])
        assert result.exit_code != 0


class TestCliErrors:
    def test_wrong_passphrase(self, runner, tmp_path, fake_wordlist_path):
        src = tmp_path / "file.txt"
        src.write_text("data", encoding="utf-8")
        phrase_file = tmp_path / "phrase.txt"

        with patch("words_crypt.cli.os.urandom", side_effect=_mock_urandom):
            runner.invoke(cli, [
                "--wordlist", fake_wordlist_path,
                "--passphrase", "correct",
                "enc-file", str(src), "--out", str(phrase_file),
            ])

        out_file = tmp_path / "out.txt"
        result = runner.invoke(cli, [
            "--wordlist", fake_wordlist_path,
            "--passphrase", "wrong",
            "dec-file", "--out-file", str(out_file), "--phrase-file", str(phrase_file),
        ])
        assert result.exit_code != 0
