param(
  [Parameter(ValueFromRemainingArguments = $true)]
  [string[]] $ArgsRest
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectDir = Split-Path -Parent $ScriptDir

function Invoke-MnemoVault {
  if (Get-Command poetry -ErrorAction SilentlyContinue) {
    $venvBin = & poetry -C $ProjectDir env info -e 2>$null
    if ($venvBin) {
      & $venvBin -m mnemo_vault.cli @ArgsRest
      exit $LASTEXITCODE
    }
  }

  if (Get-Command mnemo-vault -ErrorAction SilentlyContinue) {
    & mnemo-vault @ArgsRest
    exit $LASTEXITCODE
  }

  Write-Error "poetry virtualenv not found and mnemo-vault not in PATH. Run: cd $ProjectDir; poetry install"
}

Invoke-MnemoVault
