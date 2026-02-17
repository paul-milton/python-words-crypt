param(
  [Parameter(ValueFromRemainingArguments = $true)]
  [string[]] $ArgsRest
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectDir = Split-Path -Parent $ScriptDir

function Invoke-WordsCrypt {
  if (Get-Command poetry -ErrorAction SilentlyContinue) {
    $venvBin = & poetry -C $ProjectDir env info -e 2>$null
    if ($venvBin) {
      & $venvBin -m words_crypt.cli @ArgsRest
      exit $LASTEXITCODE
    }
  }

  if (Get-Command words-crypt -ErrorAction SilentlyContinue) {
    & words-crypt @ArgsRest
    exit $LASTEXITCODE
  }

  Write-Error "poetry virtualenv not found and words-crypt not in PATH. Run: cd $ProjectDir; poetry install"
}

Invoke-WordsCrypt
