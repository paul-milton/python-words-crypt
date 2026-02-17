# 🐚 words-crypt — (c) 2026, 🐚 The 17711 Frame <https://frame.17711.org>
# Encrypt/decrypt payloads into BIP39 words.
# MIT License © 2026

import os
import io
import sys
import json
import struct
import random
import hashlib
import tarfile
import zipfile
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

import click
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


# =========================
# 🐚 Config
# =========================

WORD_BITS = 11
SALT_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32
LEN_HDR = 4  # uint32 payload length

SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1

MAGIC = b"WZ01"  # WordZip v1 marker

ENV_LANGUAGE = "WORDS_CRYPT_LANGUAGE"
ENV_WORDLIST_URL = "WORDS_CRYPT_WORDLIST_URL"

DEFAULT_LANGUAGE = "french"
CACHE_DIR = Path.home() / ".cache" / "words-crypt" / "wordlists"

DEFAULT_BIP39_BASE = "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/"
DEFAULT_WORDLIST_URLS = {
    "french": DEFAULT_BIP39_BASE + "french.txt",
    "english": DEFAULT_BIP39_BASE + "english.txt",
    "italian": DEFAULT_BIP39_BASE + "italian.txt",
    "spanish": DEFAULT_BIP39_BASE + "spanish.txt",
    "japanese": DEFAULT_BIP39_BASE + "japanese.txt",
    "korean": DEFAULT_BIP39_BASE + "korean.txt",
    "chinese_simplified": DEFAULT_BIP39_BASE + "chinese_simplified.txt",
    "chinese_traditional": DEFAULT_BIP39_BASE + "chinese_traditional.txt",
    "czech": DEFAULT_BIP39_BASE + "czech.txt",
    "portuguese": DEFAULT_BIP39_BASE + "portuguese.txt",
}

CAMOUFLAGE_WORDS = {
    "french": [
        # Articles
        "le", "la", "les", "un", "une", "des", "du",
        # Prépositions
        "de", "en", "par", "pour", "sur", "avec", "dans", "sous", "vers",
        # Conjonctions
        "et", "ou", "mais", "donc", "or", "ni", "car", "puis",
        # Déterminants démonstratifs
        "ce", "cet", "cette", "ces",
        # Possessifs
        "mon", "ma", "mes", "ton", "ta", "tes", "son", "sa", "ses",
        # Pronoms sujets
        "je", "tu", "il", "elle", "nous", "vous", "ils", "elles",
        # Verbes conjugués courts
        "est", "sont", "a", "ont", "fait", "dit", "va", "vont",
        # Relatifs / connecteurs
        "qui", "que", "dont", "où", "si", "ne", "se", "y",
        # Adverbes courts
        "très", "aussi", "plus", "même", "tout",
    ],
}


# =========================
# 🐚 Wordlist (download + cache)
# =========================

def _ensure_cache_dir() -> None:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)


def _cached_wordlist_path(language: str) -> Path:
    safe = language.strip().lower().replace("-", "_")
    return CACHE_DIR / f"bip39_{safe}.txt"


def _download_wordlist(url: str, dst: Path) -> None:
    _ensure_cache_dir()
    tmp = dst.with_suffix(".tmp")
    with urllib.request.urlopen(url, timeout=20) as r:
        data = r.read()
    tmp.write_bytes(data)
    tmp.replace(dst)


def resolve_wordlist_path(cli_wordlist: Optional[str]) -> str:
    if cli_wordlist:
        return cli_wordlist

    language = os.environ.get(ENV_LANGUAGE, DEFAULT_LANGUAGE).strip().lower()
    dst = _cached_wordlist_path(language)

    if dst.exists():
        return str(dst)

    url = os.environ.get(ENV_WORDLIST_URL, "").strip()
    if not url:
        url = DEFAULT_WORDLIST_URLS.get(language, DEFAULT_WORDLIST_URLS[DEFAULT_LANGUAGE])

    _download_wordlist(url, dst)
    return str(dst)


def load_wordlist(path: str) -> List[str]:
    with open(path, "r", encoding="utf-8") as f:
        words = [w.strip() for w in f.readlines() if w.strip()]
    if len(words) != 2048:
        raise ValueError(f"Wordlist must contain 2048 words, got {len(words)}")
    return words


# =========================
# 🐚 Encoding
# =========================

def bytes_to_words(data: bytes, words: List[str]) -> str:
    total_bits = len(data) * 8
    acc = int.from_bytes(data, "big") if data else 0
    pad_bits = (WORD_BITS - (total_bits % WORD_BITS)) % WORD_BITS
    acc <<= pad_bits
    total_bits += pad_bits

    out = []
    for i in range(total_bits // WORD_BITS):
        shift = total_bits - WORD_BITS * (i + 1)
        idx = (acc >> shift) & ((1 << WORD_BITS) - 1)
        out.append(words[idx])
    return " ".join(out)


def words_to_bytes(phrase: str, words: List[str]) -> bytes:
    inv = {w: i for i, w in enumerate(words)}
    toks = [t for t in phrase.strip().split() if t in inv]

    acc = 0
    for t in toks:
        acc = (acc << WORD_BITS) | inv[t]

    total_bits = len(toks) * WORD_BITS
    byte_len = (total_bits + 7) // 8
    return acc.to_bytes(byte_len, "big") if byte_len else b""


# =========================
# 🐚 Camouflage
# =========================

def _get_language_from_wordlist_path(wordlist_path: str) -> str:
    name = Path(wordlist_path).stem.lower()
    for lang in CAMOUFLAGE_WORDS:
        if lang in name:
            return lang
    return ""


def _validate_camouflage_words(fillers: List[str], bip39_words: List[str]) -> None:
    bip39_set = set(bip39_words)
    collisions = [w for w in fillers if w in bip39_set]
    if collisions:
        raise RuntimeError(
            f"Camouflage filler words found in BIP39 wordlist: {collisions!r}. "
            "Edit CAMOUFLAGE_WORDS to fix."
        )


def _apply_prose_formatting(tokens: List[str], rng: random.Random) -> str:
    if not tokens:
        return ""

    tokens[0] = tokens[0].capitalize()

    result_parts = []
    for i, tok in enumerate(tokens):
        result_parts.append(tok)
        if i < len(tokens) - 1:
            r = rng.random()
            if r < 0.07:
                result_parts[-1] = result_parts[-1] + ","
            elif r < 0.10:
                result_parts[-1] = result_parts[-1] + "."
                tokens[i + 1] = tokens[i + 1].capitalize()
            elif r < 0.12:
                result_parts[-1] = result_parts[-1] + ";"

    result_parts[-1] = result_parts[-1].rstrip(".,;") + "."

    return " ".join(result_parts)


def camouflage_phrase(phrase: str, words: List[str], fillers: List[str],
                      rng: Optional[random.Random] = None) -> str:
    if not fillers:
        return phrase

    _validate_camouflage_words(fillers, words)

    rng = rng or random.Random()
    tokens = phrase.split()
    if not tokens:
        return phrase

    result = []
    for tok in tokens:
        n = rng.choices([0, 1, 2], weights=[40, 45, 15])[0]
        for _ in range(n):
            result.append(rng.choice(fillers))
        result.append(tok)

    if rng.random() < 0.30:
        n_tail = rng.choices([1, 2], weights=[70, 30])[0]
        for _ in range(n_tail):
            result.append(rng.choice(fillers))

    return _apply_prose_formatting(result, rng)


def strip_camouflage(phrase: str, words: List[str]) -> str:
    bip39_set = set(words)
    result = []
    for tok in phrase.split():
        clean = tok.strip(".,;:!?\"'").lower()
        if clean in bip39_set:
            result.append(clean)
    return " ".join(result)


# =========================
# 🐚 Crypto
# =========================

def kdf_scrypt(passphrase: str, salt: bytes) -> bytes:
    return hashlib.scrypt(
        passphrase.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=KEY_LEN,
    )


def encrypt_bytes_to_words(data: bytes, passphrase: str, wordlist_path: str) -> str:
    words = load_wordlist(wordlist_path)

    salt = os.urandom(SALT_LEN)
    key = kdf_scrypt(passphrase, salt)

    nonce = os.urandom(NONCE_LEN)
    aead = ChaCha20Poly1305(key)
    ct = aead.encrypt(nonce, data, None)

    payload = salt + nonce + ct
    framed = struct.pack(">I", len(payload)) + payload
    # Pad to multiple of 11 bytes so that 11-bit word encoding roundtrips exactly
    remainder = len(framed) % WORD_BITS
    if remainder:
        framed += b"\x00" * (WORD_BITS - remainder)
    phrase = bytes_to_words(framed, words)

    lang = _get_language_from_wordlist_path(wordlist_path)
    fillers = CAMOUFLAGE_WORDS.get(lang, [])
    if fillers:
        phrase = camouflage_phrase(phrase, words, fillers)

    return phrase


def decrypt_words_to_bytes(phrase: str, passphrase: str, wordlist_path: str) -> bytes:
    words = load_wordlist(wordlist_path)
    clean_phrase = strip_camouflage(phrase, words)
    raw = words_to_bytes(clean_phrase, words)

    if len(raw) < LEN_HDR:
        raise ValueError("Ciphertext too short")

    payload_len = struct.unpack(">I", raw[:LEN_HDR])[0]
    payload = raw[LEN_HDR:LEN_HDR + payload_len]
    if len(payload) != payload_len:
        raise ValueError("Truncated ciphertext (bad length header)")

    if len(payload) < SALT_LEN + NONCE_LEN + 16:
        raise ValueError("Ciphertext payload too short")

    salt = payload[:SALT_LEN]
    nonce = payload[SALT_LEN:SALT_LEN + NONCE_LEN]
    ct = payload[SALT_LEN + NONCE_LEN:]

    key = kdf_scrypt(passphrase, salt)
    aead = ChaCha20Poly1305(key)
    return aead.decrypt(nonce, ct, None)


def _read_u32(data: bytes, off: int) -> int:
    if off + 4 > len(data):
        raise ValueError("Truncated data while reading u32")
    return struct.unpack(">I", data[off:off + 4])[0]


# =========================
# 🐚 Container format
# =========================

@dataclass(frozen=True)
class WordZipEnvelope:
    kind: str
    filename: str
    meta_json: bytes
    payload: bytes

    def to_bytes(self) -> bytes:
        meta = self.meta_json or b"{}"
        header = {"kind": self.kind, "filename": self.filename}
        header_bytes = json.dumps(header, separators=(",", ":")).encode("utf-8")

        return b"".join([
            MAGIC,
            struct.pack(">I", len(header_bytes)),
            header_bytes,
            struct.pack(">I", len(meta)),
            meta,
            struct.pack(">I", len(self.payload)),
            self.payload,
        ])

    @staticmethod
    def from_bytes(data: bytes) -> "WordZipEnvelope":
        if len(data) < 4 or data[:4] != MAGIC:
            raise ValueError("Not a WordZipEnvelope (bad magic)")

        off = 4
        header_len = _read_u32(data, off); off += 4
        header = json.loads(data[off:off + header_len].decode("utf-8")); off += header_len

        meta_len = _read_u32(data, off); off += 4
        meta = data[off:off + meta_len]; off += meta_len

        payload_len = _read_u32(data, off); off += 4
        payload = data[off:off + payload_len]
        if len(payload) != payload_len:
            raise ValueError("Truncated envelope payload")

        return WordZipEnvelope(
            kind=header.get("kind", "raw"),
            filename=header.get("filename", "output.bin"),
            meta_json=meta,
            payload=payload,
        )


# =========================
# 🐚 CLI (Click)
# =========================

@click.group(help="🐚 words-crypt — (c) 2026, 🐚 The 17711 Frame <https://frame.17711.org>\nEncrypt/decrypt payloads into BIP39 words (default: French).")
@click.option("--wordlist", default=None, help="Path to wordlist file. If omitted, auto-download + cache.")
@click.option("--passphrase", default=None, help="Encryption passphrase (prompted if omitted).")
@click.option("--passphrase-file", default=None, type=click.Path(exists=True), help="Read passphrase from file (first line, stripped).")
@click.pass_context
def cli(ctx, wordlist, passphrase, passphrase_file):
    ctx.ensure_object(dict)
    if passphrase_file and not passphrase:
        passphrase = Path(passphrase_file).read_text(encoding="utf-8").split("\n")[0].strip()
    ctx.obj["wordlist"] = wordlist
    ctx.obj["passphrase"] = passphrase


def _get_passphrase(ctx) -> str:
    pp = ctx.obj["passphrase"]
    if pp is None:
        pp = click.prompt("Passphrase", hide_input=True)
        ctx.obj["passphrase"] = pp
    return pp


def _get_wordlist_path(ctx) -> str:
    if "wordlist_path" not in ctx.obj:
        ctx.obj["wordlist_path"] = resolve_wordlist_path(ctx.obj["wordlist"])
    return ctx.obj["wordlist_path"]


def _read_all_stdin_text() -> str:
    return sys.stdin.read()


def _write_phrase(phrase: str, out_file: str, no_zip: bool) -> None:
    """Write phrase to file. Zip by default unless --no-zip."""
    out_path = Path(out_file)
    if no_zip:
        out_path.write_text(phrase, encoding="utf-8")
    else:
        if not out_path.suffix == ".zip":
            out_path = out_path.with_suffix(out_path.suffix + ".zip")
        with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("phrase.txt", phrase.encode("utf-8"))
    click.echo(f"Written to {out_path}", err=True)


def _read_phrase(phrase_file: Optional[str]) -> str:
    """Read phrase from file (auto-detects zip) or stdin."""
    if not phrase_file:
        return _read_all_stdin_text()
    p = Path(phrase_file)
    data = p.read_bytes()
    if data[:4] == b"PK\x03\x04":
        with zipfile.ZipFile(io.BytesIO(data), "r") as zf:
            names = zf.namelist()
            return zf.read(names[0]).decode("utf-8")
    return data.decode("utf-8")


@cli.command("enc-file", help="Encrypt a single raw file to BIP39 words.")
@click.argument("file", default="-", type=click.Path(exists=False))
@click.option("--name", "out_name", default=None, help="Filename stored in envelope header (default: input filename or 'stdin.bin').")
@click.option("--out", "out_file", default=None, type=click.Path(), help="Output file (default: stdout). Zipped by default.")
@click.option("--no-zip", is_flag=True, default=False, help="Write plain text instead of zip.")
@click.pass_context
def cmd_enc_file(ctx, file, out_name, out_file, no_zip):
    if file == "-":
        data = sys.stdin.buffer.read()
        if out_name is None:
            out_name = "stdin.bin"
    else:
        p = Path(file)
        if not p.exists():
            raise click.BadParameter(f"File not found: {file}", param_hint="'FILE'")
        data = p.read_bytes()
        if out_name is None:
            out_name = p.name
    env = WordZipEnvelope(kind="raw", filename=out_name, meta_json=b"{}", payload=data).to_bytes()
    phrase = encrypt_bytes_to_words(env, _get_passphrase(ctx), _get_wordlist_path(ctx))
    if out_file:
        _write_phrase(phrase, out_file, no_zip)
    else:
        click.echo(phrase)


@cli.command("dec-file", help="Decrypt BIP39 words back to a raw file or archive.")
@click.option("--out", "out_path", default=None, type=click.Path(), help="Output path: file for raw, directory for tar (default: stdout for raw).")
@click.option("--phrase-file", default=None, type=click.Path(exists=True), help="Input phrase file or zip (default: stdin).")
@click.pass_context
def cmd_dec_file(ctx, out_path, phrase_file):
    phrase = _read_phrase(phrase_file)
    data = decrypt_words_to_bytes(phrase, _get_passphrase(ctx), _get_wordlist_path(ctx))
    env = WordZipEnvelope.from_bytes(data)

    if env.kind == "tar":
        if not out_path:
            raise click.UsageError("--out is required for tar archives.")
        dest = Path(out_path)
        dest.mkdir(parents=True, exist_ok=True)
        with tarfile.open(fileobj=io.BytesIO(env.payload), mode="r:gz") as tf:
            tf.extractall(path=dest, filter="data")
    else:
        if out_path:
            Path(out_path).write_bytes(env.payload)
        else:
            sys.stdout.buffer.write(env.payload)


@cli.command("enc-files", help="Encrypt multiple files/directories into a tar archive as BIP39 words.")
@click.argument("files", nargs=-1, required=True, type=click.Path(exists=True))
@click.option("--out", "out_file", default=None, type=click.Path(), help="Output file (default: stdout). Zipped by default.")
@click.option("--no-zip", is_flag=True, default=False, help="Write plain text instead of zip.")
@click.pass_context
def cmd_enc_files(ctx, files, out_file, no_zip):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for f in files:
            tf.add(f, arcname=Path(f).name)
    tar_data = buf.getvalue()

    env = WordZipEnvelope(kind="tar", filename="archive.tar.gz", meta_json=b"{}", payload=tar_data).to_bytes()
    phrase = encrypt_bytes_to_words(env, _get_passphrase(ctx), _get_wordlist_path(ctx))
    if out_file:
        _write_phrase(phrase, out_file, no_zip)
    else:
        click.echo(phrase)


def main():
    cli()


if __name__ == "__main__":
    raise SystemExit(main())
