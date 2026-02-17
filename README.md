# words-crypt

(c) 2026, 🐚 The 17711 Frame <https://frame.17711.org>

Encrypt/decrypt text or binary payloads into **real-looking words** (BIP39 wordlists).

- Strong crypto: **ChaCha20-Poly1305** (AEAD)
- Key derivation: **scrypt**
- Output: words (default **French** BIP39 list)
- **Camouflage automatique** : des mots de remplissage (articles, conjonctions, verbes conjugués) sont insérés entre les mots chiffrés pour que la sortie ressemble à du vrai texte. Le déchiffrement les filtre automatiquement.
- Wordlist download is **dynamic**, **language-selectable**, and **cached**.

## Install (Poetry)

```bash
poetry install
```

## Wordlist download + cache

By default, `words-crypt` downloads the wordlist on first use and caches it:

- Cache dir: `~/.cache/words-crypt/wordlists/`
- Default language: `french`

### Environment variables

- `WORDS_CRYPT_LANGUAGE`
  Default: `french`
  Example: `english`, `italian`, etc. (depends on available list URLs)

- `WORDS_CRYPT_WORDLIST_URL`
  If set, overrides the download URL entirely.

You can still pass `--wordlist /path/to/list.txt` to force a specific file.

## Usage

### Encrypt a raw file -> words (stdout)

```bash
poetry run words-crypt --passphrase "my secret" enc-file ./image.png
```

### Encrypt a raw file -> words (file)

```bash
poetry run words-crypt --passphrase "my secret" enc-file ./image.png --out phrase.txt
```

### Decrypt words -> raw file

```bash
poetry run words-crypt --passphrase "my secret" dec-file --out-file ./image.png --phrase-file phrase.txt
```

## Notes

- If any word is changed or missing, decryption fails (expected for AEAD).
- Keep the passphrase safe.
- BIP39 lists contain exactly **2048 words**.
- The `--out` option on `enc-file` allows exporting the encrypted text directly to a file instead of stdout.
