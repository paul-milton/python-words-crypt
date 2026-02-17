# words-crypt

(c) 2026, The 17711 Frame <https://frame.17711.org> — MIT License

Encrypt/decrypt files or text into **real-looking words** from BIP39 wordlists.

- **ChaCha20-Poly1305** (AEAD) + **scrypt** key derivation
- Output: words from the **French** BIP39 list (10 languages available)
- **Camouflage** : filler words (articles, conjunctions, verbs) are inserted between encoded words so the output looks like real French prose. Decryption strips them automatically.
- Supports **text**, **single files**, **multiple files**, and **directories**
- Full **stdin/stdout** pipe support

## Install

```bash
poetry install
```

## Usage

### Text

```bash
# Encrypt text (→ stdout, plain words)
words-crypt --passphrase "secret" encrypt --text "Mon message secret"

# Decrypt text (→ stdout)
words-crypt --passphrase "secret" decrypt --in phrase.txt
```

### Single file

```bash
# Encrypt (file → stdout)
words-crypt --passphrase "secret" encrypt ./photo.png

# Encrypt (file → zip, default)
words-crypt --passphrase "secret" encrypt ./photo.png --out phrase.txt

# Encrypt (stdin → stdout)
cat photo.png | words-crypt --passphrase "secret" encrypt

# Decrypt (→ file)
words-crypt --passphrase "secret" decrypt --in phrase.txt.zip --out photo.png

# Decrypt (→ stdout)
words-crypt --passphrase "secret" decrypt --in phrase.txt.zip > photo.png

# Decrypt (stdin → file)
cat phrase.txt | words-crypt --passphrase "secret" decrypt --out photo.png
```

### Multiple files / directories

```bash
# Encrypt several files into one archive
words-crypt --passphrase "secret" encrypt file1.txt file2.pdf images/ --out archive.txt

# Decrypt archive into a directory
words-crypt --passphrase "secret" decrypt --in archive.txt.zip --out ./extracted/
```

### Passphrase

```bash
# Interactive prompt (default if omitted)
words-crypt encrypt photo.png --out phrase.txt

# From command line
words-crypt --passphrase "secret" encrypt photo.png --out phrase.txt

# From file
words-crypt --passphrase-file key.txt encrypt photo.png --out phrase.txt
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
- `--out` creates a zip by default for files (use `--no-zip` for plain text)
- `--text` mode always outputs plain text (never zipped)
