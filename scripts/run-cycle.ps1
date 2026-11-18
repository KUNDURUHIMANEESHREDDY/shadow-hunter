$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

if ($env:SHADOW_HUNTER_AUTOMATION_ENABLED -ne "true") {
    Write-Output "Automation is disabled. No agent execution performed."
    exit 0
}

if (-not $env:SHADOW_HUNTER_DEADLINE_UTC) {
    throw "SHADOW_HUNTER_DEADLINE_UTC is required."
}
$deadline = [DateTimeOffset]::Parse($env:SHADOW_HUNTER_DEADLINE_UTC).ToUniversalTime()
if ([DateTimeOffset]::UtcNow -ge $deadline) {
    Write-Output "Project automation deadline reached; no agent execution performed."
    exit 0
}

# Drop stale scheduled runs instead of trying to catch up when the runner was offline.
if ($env:GITHUB_EVENT_NAME -eq "schedule" -and $env:GITHUB_RUN_STARTED_AT) {
    $runStarted = [DateTimeOffset]::Parse($env:GITHUB_RUN_STARTED_AT).ToUniversalTime()
    if (([DateTimeOffset]::UtcNow - $runStarted).TotalMinutes -gt 45) {
        Write-Output "Scheduled run is stale; skipping rather than creating backlog."
        exit 0
    }
}

$expectedRepo = "KUNDURUHIMANEESHREDDY/shadow-hunter"
if ($env:GITHUB_REPOSITORY -and $env:GITHUB_REPOSITORY -ne $expectedRepo) {
    throw "Unexpected repository context: $($env:GITHUB_REPOSITORY)"
}
$branch = (& git branch --show-current).Trim()
if ($branch -ne "main") { throw "Refusing to write outside main (current branch: $branch)." }

# Hold the write token in the wrapper only. The model process must never inherit
# GitHub credentials. Checkout is configured with persist-credentials: false.
$pushToken = $env:GITHUB_TOKEN
Remove-Item Env:GITHUB_TOKEN -ErrorAction SilentlyContinue
Remove-Item Env:GH_TOKEN -ErrorAction SilentlyContinue

$codex = Get-Command codex -ErrorAction SilentlyContinue
if (-not $codex) { throw "Codex CLI is unavailable on this runner." }
& codex login status
if ($LASTEXITCODE -ne 0) { throw "Codex authentication is unavailable for the runner identity." }

$promptPath = Join-Path $PSScriptRoot "AGENT_CYCLE_PROMPT.md"
if (-not (Test-Path $promptPath -PathType Leaf)) { throw "Agent cycle prompt is missing." }
$prompt = Get-Content -Raw -Encoding UTF8 $promptPath
$runId = if ($env:GITHUB_RUN_ID) { $env:GITHUB_RUN_ID } else { [guid]::NewGuid().ToString("N") }
$tempDir = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { [IO.Path]::GetTempPath() }
$lastMessage = Join-Path $tempDir "shadow-hunter-$runId-last-message.md"
$agentLog = Join-Path $tempDir "shadow-hunter-$runId-agent.jsonl"

Write-Output "Starting Shadow Hunter cycle $runId at $([DateTimeOffset]::UtcNow.ToString('o'))"
$agentOutput = $prompt | & codex exec --approve-for-me --json --output-last-message $lastMessage 2>&1
$agentExit = $LASTEXITCODE
$agentOutput | Set-Content -Path $agentLog -Encoding UTF8
if ($agentExit -ne 0) {
    Get-Content $agentLog -Tail 80 | Write-Output
    throw "Codex execution failed with exit code $agentExit. No commit was made."
}
if (-not (Test-Path $lastMessage -PathType Leaf)) {
    throw "Codex produced no final report. No commit was made."
}

$changed = @(& git status --porcelain | ForEach-Object {
    if ($_.Length -gt 3) { $_.Substring(3).Trim('"') }
} | Where-Object { $_ })
if ($changed.Count -eq 0) {
    Write-Output "Agent completed without file changes. No commit created."
    Get-Content $lastMessage
    exit 0
}

$protected = @(
    '^\.github/workflows/',
    '^\.codex/',
    '^\.agents/skills/',
    '^third_party/',
    '^scripts/run-cycle\.ps1$',
    '^scripts/verify\.ps1$',
    '^scripts/AGENT_CYCLE_PROMPT\.md$',
    '^LICENSE$',
    '^\.gitignore$'
)
foreach ($path in $changed) {
    foreach ($pattern in $protected) {
        if ($path -match $pattern) { throw "Protected path modified by agent: $path. Human review required; no commit made." }
    }
    if (-not (Test-Path (Join-Path $RepoRoot $path) -PathType Leaf)) {
        throw "Changed path is missing or not a regular file: $path"
    }
}

$secretPattern = '(?i)(AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|sk-ant-api03-[A-Za-z0-9_-]{60,}|-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----)'
foreach ($path in $changed) {
    $full = Join-Path $RepoRoot $path
    $content = Get-Content -Raw -ErrorAction Stop $full
    if ($content -match $secretPattern) { throw "Potential credential found in changed file $path. No commit made." }
}

& (Join-Path $PSScriptRoot "verify.ps1")
if ($LASTEXITCODE -ne 0) { throw "Repository verification failed. No commit made." }

& git add -- $changed
if ($LASTEXITCODE -ne 0) { throw "git add failed." }
& git diff --cached --check
if ($LASTEXITCODE -ne 0) { throw "Staged diff validation failed." }
$staged = @(& git diff --cached --name-only)
if ($staged.Count -eq 0) { Write-Output "No staged changes; no commit needed."; exit 0 }

& git config user.name "Shadow Hunter Automation"
& git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
$message = "engineering: complete verified cycle $runId"
& git commit -m $message
if ($LASTEXITCODE -ne 0) { throw "Git commit failed." }
if (-not $pushToken) { throw "GITHUB_TOKEN is missing; commit is local but cannot be pushed." }
$authBytes = [Text.Encoding]::UTF8.GetBytes("x-access-token:$pushToken")
$authHeader = "AUTHORIZATION: basic $([Convert]::ToBase64String($authBytes))"
$env:GIT_CONFIG_COUNT = "1"
$env:GIT_CONFIG_KEY_0 = "http.https://github.com/.extraheader"
$env:GIT_CONFIG_VALUE_0 = $authHeader
try {
    & git push origin HEAD:main
    if ($LASTEXITCODE -ne 0) { throw "Push failed. Commit remains local on runner; inspect before retrying." }
} finally {
    Remove-Item Env:GIT_CONFIG_COUNT -ErrorAction SilentlyContinue
    Remove-Item Env:GIT_CONFIG_KEY_0 -ErrorAction SilentlyContinue
    Remove-Item Env:GIT_CONFIG_VALUE_0 -ErrorAction SilentlyContinue
    $pushToken = $null
    $authHeader = $null
    $authBytes = $null
}

Write-Output "Committed and pushed verified cycle $runId."
Write-Output "Commit: $((& git rev-parse HEAD).Trim())"
Get-Content $lastMessage
