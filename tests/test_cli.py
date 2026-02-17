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
        assert len(result.output.strip().split()) > 0  # got word phrase

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


class TestDecFile:
    def test_dec_file_from_phrase_file(self, runner, tmp_path, fake_wordlist_path):
        # First encrypt
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

        # Then decrypt
        out_file = tmp_path / "recovered.txt"
        result = runner.invoke(cli, [
            "--wordlist", fake_wordlist_path,
            "--passphrase", "pass123",
            "dec-file", "--out-file", str(out_file), "--phrase-file", str(phrase_file),
        ])
        assert result.exit_code == 0
        assert out_file.read_text(encoding="utf-8") == "original content"


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
