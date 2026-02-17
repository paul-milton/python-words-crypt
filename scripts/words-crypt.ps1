param(
  [Parameter(ValueFromRemainingArguments = $true)]
  [string[]] $ArgsRest
)

$ErrorActionPreference = "Stop"

function Invoke-WordsCrypt {
  if (Get-Command poetry -ErrorAction SilentlyContinue) {
    & poetry run words-crypt @ArgsRest
    exit $LASTEXITCODE
  }

  if (Get-Command words-crypt -ErrorAction SilentlyContinue) {
    & words-crypt @ArgsRest
    exit $LASTEXITCODE
  }

  Write-Error "poetry not found and words-crypt not installed in PATH. Run: poetry install"
}

Invoke-WordsCrypt
