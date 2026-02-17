import pytest
from pathlib import Path


FAKE_WORDS = [f"word{i:04d}" for i in range(2048)]


@pytest.fixture
def fake_words():
    """Return the 2048-word fake wordlist as a Python list."""
    return list(FAKE_WORDS)


@pytest.fixture
def fake_wordlist_path(tmp_path):
    """Write the fake wordlist to a temp file and return its path (str)."""
    p = tmp_path / "fake_wordlist.txt"
    p.write_text("\n".join(FAKE_WORDS) + "\n", encoding="utf-8")
    return str(p)
