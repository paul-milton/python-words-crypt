import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path

from words_crypt.cli import (
    load_wordlist,
    resolve_wordlist_path,
    _cached_wordlist_path,
    _download_wordlist,
    CACHE_DIR,
    DEFAULT_LANGUAGE,
    ENV_LANGUAGE,
    ENV_WORDLIST_URL,
)
from tests.conftest import FAKE_WORDS


class TestLoadWordlist:
    def test_valid_wordlist(self, fake_wordlist_path):
        words = load_wordlist(fake_wordlist_path)
        assert len(words) == 2048
        assert words[0] == "word0000"
        assert words[2047] == "word2047"

    def test_wrong_count_raises(self, tmp_path):
        p = tmp_path / "short.txt"
        p.write_text("\n".join(f"w{i}" for i in range(100)), encoding="utf-8")
        with pytest.raises(ValueError, match="2048"):
            load_wordlist(str(p))

    def test_empty_file_raises(self, tmp_path):
        p = tmp_path / "empty.txt"
        p.write_text("", encoding="utf-8")
        with pytest.raises(ValueError, match="2048"):
            load_wordlist(str(p))


class TestCachedWordlistPath:
    def test_normalizes_language(self):
        p = _cached_wordlist_path("French")
        assert "french" in p.name

    def test_hyphens_to_underscores(self):
        p = _cached_wordlist_path("chinese-simplified")
        assert "chinese_simplified" in p.name


class TestDownloadWordlist:
    def test_downloads_and_writes(self, tmp_path):
        dst = tmp_path / "wordlists" / "test.txt"
        fake_content = "\n".join(FAKE_WORDS).encode("utf-8")

        mock_response = MagicMock()
        mock_response.read.return_value = fake_content
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch("words_crypt.cli.urllib.request.urlopen", return_value=mock_response) as mock_urlopen, \
             patch("words_crypt.cli.CACHE_DIR", tmp_path / "wordlists"):
            (tmp_path / "wordlists").mkdir(parents=True, exist_ok=True)
            _download_wordlist("https://example.com/words.txt", dst)

        mock_urlopen.assert_called_once_with("https://example.com/words.txt", timeout=20)
        assert dst.exists()
        assert dst.read_bytes() == fake_content


class TestResolveWordlistPath:
    def test_cli_arg_takes_priority(self):
        result = resolve_wordlist_path("/some/path.txt")
        assert result == "/some/path.txt"

    def test_cached_file_returned(self, tmp_path, monkeypatch):
        lang = "english"
        monkeypatch.setenv(ENV_LANGUAGE, lang)
        monkeypatch.setattr("words_crypt.cli.CACHE_DIR", tmp_path)

        cached = tmp_path / f"bip39_{lang}.txt"
        cached.write_text("cached", encoding="utf-8")

        result = resolve_wordlist_path(None)
        assert result == str(cached)

    def test_downloads_when_not_cached(self, tmp_path, monkeypatch):
        lang = "italian"
        monkeypatch.setenv(ENV_LANGUAGE, lang)
        monkeypatch.setattr("words_crypt.cli.CACHE_DIR", tmp_path)

        mock_response = MagicMock()
        mock_response.read.return_value = b"word content"
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch("words_crypt.cli.urllib.request.urlopen", return_value=mock_response):
            result = resolve_wordlist_path(None)

        expected = tmp_path / f"bip39_{lang}.txt"
        assert result == str(expected)
        assert expected.exists()

    def test_env_wordlist_url_used(self, tmp_path, monkeypatch):
        monkeypatch.setenv(ENV_LANGUAGE, "custom")
        monkeypatch.setenv(ENV_WORDLIST_URL, "https://custom.com/words.txt")
        monkeypatch.setattr("words_crypt.cli.CACHE_DIR", tmp_path)

        mock_response = MagicMock()
        mock_response.read.return_value = b"data"
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch("words_crypt.cli.urllib.request.urlopen", return_value=mock_response) as mock_urlopen:
            resolve_wordlist_path(None)

        mock_urlopen.assert_called_once_with("https://custom.com/words.txt", timeout=20)
