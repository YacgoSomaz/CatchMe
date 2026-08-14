[CmdletBinding()]
param(
    [string]$ServerUrl = ""
)

$ErrorActionPreference = "Stop"
$repoRoot = $PSScriptRoot
$venvRoot = Join-Path $repoRoot ".venv"
$venvPython = Join-Path $venvRoot "Scripts\python.exe"
$catchme = Join-Path $venvRoot "Scripts\catchme.exe"

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    throw "Python 3.11 or newer is required and must be available as 'python'."
}
$pythonIsSupported = python -c "import sys; print(int(sys.version_info >= (3, 11)))"
if ($pythonIsSupported -ne "1") {
    throw "Python 3.11 or newer is required."
}

if (-not (Test-Path -LiteralPath $venvPython)) {
    python -m venv $venvRoot
}

& $venvPython -m pip install --upgrade pip
& $venvPython -m pip install -e $repoRoot

Write-Host ""
Write-Host "CatchMe requires one-time recording consent before background startup."
& $catchme consent grant
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

if ($ServerUrl) {
    & $catchme sync configure $ServerUrl
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

& $catchme startup install
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host ""
Write-Host "CatchMe is installed. Use its tray icon to pause, sync, or exit."
