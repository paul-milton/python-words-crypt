import hashlib
import pytest
from unittest.mock import patch
from cryptography.exceptions import InvalidTag

from words_crypt.cli import (
    kdf_scrypt,
    encrypt_bytes_to_words,
    decrypt_words_to_bytes,
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


@pytest.fixture(autouse=True)
def mock_crypto():
    """Mock urandom + scrypt for all crypto tests."""
    with patch("words_crypt.cli.os.urandom", side_effect=_mock_urandom), \
         patch("words_crypt.cli.hashlib.scrypt", side_effect=_fast_scrypt):
        yield


class TestKdfScrypt:
    def test_key_length(self):
        salt = b"\x00" * SALT_LEN
        key = kdf_scrypt("password", salt)
        assert len(key) == KEY_LEN

    def test_deterministic(self):
        salt = b"\xab" * SALT_LEN
        k1 = kdf_scrypt("pass", salt)
        k2 = kdf_scrypt("pass", salt)
        assert k1 == k2

    def test_different_passphrase_different_key(self):
        salt = b"\x00" * SALT_LEN
        k1 = kdf_scrypt("pass1", salt)
        k2 = kdf_scrypt("pass2", salt)
        assert k1 != k2

    def test_different_salt_different_key(self):
        k1 = kdf_scrypt("pass", b"\x00" * SALT_LEN)
        k2 = kdf_scrypt("pass", b"\x01" * SALT_LEN)
        assert k1 != k2


class TestEncryptDecrypt:
    def test_roundtrip(self, fake_wordlist_path):
        data = b"abcdef"
        phrase = encrypt_bytes_to_words(data, "mypass", fake_wordlist_path)
        assert decrypt_words_to_bytes(phrase, "mypass", fake_wordlist_path) == data

    def test_roundtrip_various_sizes(self, fake_wordlist_path):
        """Roundtrip works for all payload sizes (padding fix)."""
        for size in [0, 1, 5, 6, 7, 10, 11, 13, 50, 100, 255]:
            data = bytes(range(256))[:size] if size <= 256 else b"\xaa" * size
            phrase = encrypt_bytes_to_words(data, "pass", fake_wordlist_path)
            assert decrypt_words_to_bytes(phrase, "pass", fake_wordlist_path) == data, \
                f"Failed roundtrip for size={size}"

    def test_roundtrip_empty(self, fake_wordlist_path):
        phrase = encrypt_bytes_to_words(b"", "pass", fake_wordlist_path)
        assert decrypt_words_to_bytes(phrase, "pass", fake_wordlist_path) == b""

    def test_wrong_passphrase_raises(self, fake_wordlist_path):
        data = b"secret"
        phrase = encrypt_bytes_to_words(data, "correct", fake_wordlist_path)
        with pytest.raises(InvalidTag):
            decrypt_words_to_bytes(phrase, "wrong", fake_wordlist_path)

    def test_truncated_ciphertext_raises(self, fake_wordlist_path):
        with pytest.raises(ValueError):
            decrypt_words_to_bytes("word0000", "pass", fake_wordlist_path)

    def test_large_payload(self, fake_wordlist_path):
        data = b"\xaa" * 1030
        phrase = encrypt_bytes_to_words(data, "bigpass", fake_wordlist_path)
        assert decrypt_words_to_bytes(phrase, "bigpass", fake_wordlist_path) == data
