$ErrorActionPreference = "Stop"

$cacheDir = Join-Path $HOME ".cache\words-crypt\wordlists"
$language = $env:WORDS_CRYPT_LANGUAGE
if ([string]::IsNullOrWhiteSpace($language)) { $language = "french" }
$safeLang = ($language.ToLower() -replace "-", "_")
$outFile = Join-Path $cacheDir ("bip39_{0}.txt" -f $safeLang)

$defaultBase = "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039"
$defaultUrl = "{0}/{1}.txt" -f $defaultBase, $language
$url = $env:WORDS_CRYPT_WORDLIST_URL
if ([string]::IsNullOrWhiteSpace($url)) { $url = $defaultUrl }

New-Item -ItemType Directory -Force -Path $cacheDir | Out-Null

if (Test-Path $outFile -PathType Leaf) {
  if ((Get-Item $outFile).Length -gt 0) {
    Write-Host ("OK: cached wordlist already exists: {0}" -f $outFile) 1>&2
    exit 0
  }
}

$tmp = "$outFile.tmp"
Invoke-WebRequest -Uri $url -OutFile $tmp -UseBasicParsing
Move-Item -Force $tmp $outFile
Write-Host ("OK: downloaded wordlist to {0}" -f $outFile) 1>&2
