# mnemo-vault

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
mnemo-vault --passphrase "secret" encrypt --text "Mon message secret"

# Decrypt text (→ stdout)
mnemo-vault --passphrase "secret" decrypt --in phrase.txt
```

### Single file

```bash
# Encrypt (file → stdout)
mnemo-vault --passphrase "secret" encrypt ./photo.png

# Encrypt (file → zip, default)
mnemo-vault --passphrase "secret" encrypt ./photo.png --out phrase.txt

# Encrypt (stdin → stdout)
cat photo.png | mnemo-vault --passphrase "secret" encrypt

# Decrypt (→ file)
mnemo-vault --passphrase "secret" decrypt --in phrase.txt.zip --out photo.png

# Decrypt (→ stdout)
mnemo-vault --passphrase "secret" decrypt --in phrase.txt.zip > photo.png

# Decrypt (stdin → file)
cat phrase.txt | mnemo-vault --passphrase "secret" decrypt --out photo.png
```

### Multiple files / directories

```bash
# Encrypt several files into one archive
mnemo-vault --passphrase "secret" encrypt file1.txt file2.pdf images/ --out archive.txt

# Decrypt archive into a directory
mnemo-vault --passphrase "secret" decrypt --in archive.txt.zip --out ./extracted/
```

### Passphrase

```bash
# Interactive prompt (default if omitted)
mnemo-vault encrypt photo.png --out phrase.txt

# From command line
mnemo-vault --passphrase "secret" encrypt photo.png --out phrase.txt

# From file
mnemo-vault --passphrase-file key.txt encrypt photo.png --out phrase.txt
```

## Wordlist

By default, the BIP39 wordlist is downloaded on first use and cached in `~/.cache/mnemo-vault/wordlists/`.

| Variable | Default | Description |
|---|---|---|
| `MNEMO_VAULT_LANGUAGE` | `french` | Language: `english`, `italian`, `spanish`, `japanese`, `korean`, `chinese_simplified`, `chinese_traditional`, `czech`, `portuguese` |
| `MNEMO_VAULT_WORDLIST_URL` | — | Override the download URL entirely |

You can also pass `--wordlist /path/to/list.txt` to use a local file.

## Notes

- BIP39 lists contain exactly **2048 words**
- If any word is altered, decryption fails (AEAD integrity)
- Keep the passphrase safe — there is no recovery mechanism
- `--out` creates a zip by default for files (use `--no-zip` for plain text)
- `--text` mode always outputs plain text (never zipped)
