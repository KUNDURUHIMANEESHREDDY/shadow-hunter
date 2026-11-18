$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$Root = Split-Path -Parent $PSScriptRoot
Push-Location $Root
try {
    $python = Get-Command python -ErrorAction SilentlyContinue
    if (-not $python) { throw "Python is required for repository metadata validation." }

    & python (Join-Path $PSScriptRoot "validate-repo.py")
    if ($LASTEXITCODE -ne 0) { throw "Repository metadata validation failed." }

    $tests = Join-Path $Root "tests"
    if (Test-Path $tests -PathType Container) {
        $testFiles = @(Get-ChildItem $tests -Recurse -File | Where-Object { $_.Name -match '^test_.*\.py$|.*_test\.py$' })
        if ($testFiles.Count -gt 0) {
            & python -m pytest -q $tests
            if ($LASTEXITCODE -ne 0) { throw "Pytest suite failed." }
        } else {
            Write-Output "No Python test files found; no pytest pass is claimed."
        }
    } else {
        Write-Output "No tests directory exists yet; no test-suite pass is claimed."
    }

    & git diff --check
    if ($LASTEXITCODE -ne 0) { throw "git diff --check failed." }
    Write-Output "Repository verification checks passed."
} finally {
    Pop-Location
}
