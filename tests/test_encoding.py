import struct
import pytest
from words_crypt.cli import bytes_to_words, words_to_bytes, WORD_BITS


class TestBytesToWords:
    def test_roundtrip_with_length_header_aligned(self, fake_words):
        """Roundtrip works when framed data has byte-aligned padding (pad=0)."""
        # 7 bytes data + 4 bytes header = 11 bytes → 88 bits → 88%11=0 → pad=0
        data = b"hello!!"
        framed = struct.pack(">I", len(data)) + data
        phrase = bytes_to_words(framed, fake_words)
        raw = words_to_bytes(phrase, fake_words)
        payload_len = struct.unpack(">I", raw[:4])[0]
        assert raw[4:4 + payload_len] == data

    def test_empty_data(self, fake_words):
        phrase = bytes_to_words(b"", fake_words)
        assert phrase == ""

    def test_word_count_consistent(self, fake_words):
        data = b"\xff" * 11  # 88 bits → exactly 8 words
        phrase = bytes_to_words(data, fake_words)
        assert len(phrase.split()) == 8

    def test_word_count_formula(self, fake_words):
        """Number of words = ceil(len(data)*8 / 11)."""
        for n in (1, 5, 11, 22, 50):
            data = b"\xab" * n
            phrase = bytes_to_words(data, fake_words)
            total_bits = n * 8
            expected_words = (total_bits + WORD_BITS - 1) // WORD_BITS
            assert len(phrase.split()) == expected_words

    def test_all_words_in_wordlist(self, fake_words):
        data = b"test payload 123"
        phrase = bytes_to_words(data, fake_words)
        word_set = set(fake_words)
        for w in phrase.split():
            assert w in word_set

    def test_deterministic(self, fake_words):
        data = b"\x01\x02\x03"
        assert bytes_to_words(data, fake_words) == bytes_to_words(data, fake_words)


class TestWordsToBytes:
    def test_unknown_word_skipped(self, fake_words):
        """Unknown words are silently skipped (camouflage support)."""
        data = b"\x01\x02"
        phrase = bytes_to_words(data, fake_words)
        # Insert a fake word that is not in the wordlist
        camouflaged = "notaword " + phrase + " alsonotaword"
        assert words_to_bytes(camouflaged, fake_words) == words_to_bytes(phrase, fake_words)

    def test_empty_phrase(self, fake_words):
        result = words_to_bytes("", fake_words)
        assert result == b""

    def test_whitespace_handling(self, fake_words):
        """Extra whitespace should not change the result."""
        data = b"\x01\x02"
        phrase = bytes_to_words(data, fake_words)
        padded = f"  {phrase}  "
        assert words_to_bytes(padded, fake_words) == words_to_bytes(phrase, fake_words)

    def test_encode_decode_preserves_integer_value(self, fake_words):
        """The encoded integer value is original << pad_bits."""
        data = b"\xde\xad\xbe\xef"
        original_int = int.from_bytes(data, "big")
        total_bits = len(data) * 8
        pad_bits = (WORD_BITS - (total_bits % WORD_BITS)) % WORD_BITS

        phrase = bytes_to_words(data, fake_words)
        raw = words_to_bytes(phrase, fake_words)
        decoded_int = int.from_bytes(raw, "big")

        assert decoded_int == original_int << pad_bits
