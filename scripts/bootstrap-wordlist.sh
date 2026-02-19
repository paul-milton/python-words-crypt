#!/usr/bin/env bash
set -euo pipefail

# Downloads (and caches) the BIP39 wordlist for the configured language.
# Uses:
#   MNEMO_VAULT_LANGUAGE (default: french)
#   MNEMO_VAULT_WORDLIST_URL (optional override)

CACHE_DIR="${HOME}/.cache/mnemo-vault/wordlists"
LANGUAGE="${MNEMO_VAULT_LANGUAGE:-french}"
SAFE_LANG="$(echo "${LANGUAGE}" | tr '[:upper:]' '[:lower:]' | tr '-' '_' )"
OUT="${CACHE_DIR}/bip39_${SAFE_LANG}.txt"

DEFAULT_BASE="https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039"
DEFAULT_URL="${DEFAULT_BASE}/${LANGUAGE}.txt"
URL="${MNEMO_VAULT_WORDLIST_URL:-$DEFAULT_URL}"

main() {
  mkdir -p "${CACHE_DIR}"

  if [ -s "${OUT}" ]; then
    echo "OK: cached wordlist already exists: ${OUT}" >&2
    exit 0
  fi

  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "${URL}" -o "${OUT}.tmp"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "${OUT}.tmp" "${URL}"
  else
    echo "ERROR: neither curl nor wget found." >&2
    exit 1
  fi

  mv "${OUT}.tmp" "${OUT}"
  echo "OK: downloaded wordlist to ${OUT}" >&2
}

main "$@"
