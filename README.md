# words-crypt

(c) 2026, The 17711 Frame <https://frame.17711.org> — MIT License

Encrypt/decrypt files into **real-looking words** from BIP39 wordlists.

- **ChaCha20-Poly1305** (AEAD) + **scrypt** key derivation
- Output: words from the **French** BIP39 list (10 languages available)
- **Camouflage** : filler words (articles, conjunctions, verbs) are inserted between encoded words so the output looks like real French prose. Decryption strips them automatically.
- Supports **single files**, **multiple files**, and **directories** (tar archives)
- Full **stdin/stdout** pipe support

## Install

```bash
poetry install
```

## Usage

### Single file

```bash
# Encrypt (file → stdout)
words-crypt --passphrase "secret" enc-file ./photo.png

# Encrypt (file → file)
words-crypt --passphrase "secret" enc-file ./photo.png --out phrase.txt

# Encrypt (stdin → stdout)
cat photo.png | words-crypt --passphrase "secret" enc-file

# Decrypt (→ file)
words-crypt --passphrase "secret" dec-file --out-file photo.png --phrase-file phrase.txt

# Decrypt (→ stdout)
words-crypt --passphrase "secret" dec-file --phrase-file phrase.txt > photo.png

# Decrypt (stdin → file)
cat phrase.txt | words-crypt --passphrase "secret" dec-file --out-file photo.png
```

### Multiple files / directories

```bash
# Encrypt several files into one archive
words-crypt --passphrase "secret" enc-files file1.txt file2.pdf images/ --out phrase.txt

# Decrypt archive into a directory
words-crypt --passphrase "secret" dec-file --out-dir ./extracted/ --phrase-file phrase.txt
```

## Wordlist

By default, the BIP39 wordlist is downloaded on first use and cached in `~/.cache/words-crypt/wordlists/`.

| Variable | Default | Description |
|---|---|---|
| `WORDS_CRYPT_LANGUAGE` | `french` | Language: `english`, `italian`, `spanish`, `japanese`, `korean`, `chinese_simplified`, `chinese_traditional`, `czech`, `portuguese` |
| `WORDS_CRYPT_WORDLIST_URL` | — | Override the download URL entirely |

You can also pass `--wordlist /path/to/list.txt` to use a local file.

## Notes

- BIP39 lists contain exactly **2048 words**
- If any word is altered, decryption fails (AEAD integrity)
- Keep the passphrase safe — there is no recovery mechanism
