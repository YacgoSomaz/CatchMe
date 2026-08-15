[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$repoRoot = $PSScriptRoot
$venvRoot = Join-Path $repoRoot ".venv-build"
$python = Join-Path $venvRoot "Scripts\python.exe"
$outputDir = Join-Path $repoRoot "portable"

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    throw "Python 3.11 or newer is required only on the build computer."
}

if (-not (Test-Path -LiteralPath $python)) {
    python -m venv $venvRoot
}

& $python -m pip install --upgrade pip
& $python -m pip install --no-deps -e $repoRoot
& $python -m pip install `
    "pyinstaller>=6.10" `
    "Pillow>=10.0" `
    "pynput>=1.7" `
    "psutil>=5.9" `
    "requests>=2.31" `
    "pystray>=0.19" `
    "pywin32>=306" `
    "comtypes>=1.4" `
    "mss>=9.0"

New-Item -ItemType Directory -Force -Path $outputDir | Out-Null
& $python -m PyInstaller `
    --noconfirm `
    --clean `
    --distpath $outputDir `
    --workpath (Join-Path $repoRoot "build\portable") `
    (Join-Path $repoRoot "packaging\CatchMePortable.spec")

if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$executable = Join-Path $outputDir "CatchMe.exe"
$selfTest = Start-Process `
    -FilePath $executable `
    -ArgumentList "self-test" `
    -WindowStyle Hidden `
    -Wait `
    -PassThru
if ($selfTest.ExitCode -ne 0) {
    throw "Portable executable self-test failed with exit code $($selfTest.ExitCode)."
}

Write-Host "Portable executable created: $outputDir\CatchMe.exe"
