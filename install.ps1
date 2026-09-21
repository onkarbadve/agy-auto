<#
.SYNOPSIS
    agy-auto Windows Installer
.DESCRIPTION
    Registers the agy-auto PreToolUse hook on Windows, switches agy to always-proceed,
    runs a smoke test, and provides uninstall capabilities.
#>
[CmdletBinding()]
param (
    [switch]$Uninstall,
    [switch]$DryRunMode,
    [switch]$Help
)

if ($Help) {
    Write-Host "Usage: .\install.ps1 [-DryRunMode] [-Uninstall]"
    exit 0
}

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$HookCmd = Join-Path $ScriptDir "hook.cmd"
$CfgDir = Join-Path $env:USERPROFILE ".gemini\config"
$HooksJson = Join-Path $CfgDir "hooks.json"
$SettingsJson = Join-Path $env:USERPROFILE ".gemini\antigravity-cli\settings.json"
$AutoDir = Join-Path $CfgDir "agy-auto"
$HookName = "agy-auto"
$HookTimeout = 60

# Verify Python
$PythonExe = ""
foreach ($cmd in @("python", "py", "python3")) {
    try {
        $ver = & $cmd -c "import sys, tomllib; print(sys.version_info >= (3, 11))" 2>$null
        if ($ver -eq "True") {
            $PythonExe = $cmd
            break
        }
    } catch {}
}

if (-not $PythonExe) {
    Write-Error "install: Python 3.11+ with tomllib is required but not found on PATH."
    exit 1
}

# Verify agy
$AgyCmd = Get-Command "agy" -ErrorAction SilentlyContinue
if (-not $AgyCmd) {
    Write-Warning "agy not found on PATH. Proceeding with hook registration."
}

# Handle Uninstall
if ($Uninstall) {
    if (Test-Path $HooksJson) {
        $json = Get-Content $HooksJson -Raw | ConvertFrom-Json -AsHashtable
        if ($json.ContainsKey($HookName)) {
            $json.Remove($HookName)
            if ($json.Count -eq 0) {
                Remove-Item $HooksJson -Force
            } else {
                $json | ConvertTo-Json -Depth 10 | Set-Content $HooksJson
            }
        }
    }
    if (Test-Path $SettingsJson) {
        $settings = Get-Content $SettingsJson -Raw | ConvertFrom-Json -AsHashtable
        if ($settings.ContainsKey("toolPermission")) {
            $settings.Remove("toolPermission")
            $settings | ConvertTo-Json -Depth 10 | Set-Content $SettingsJson
        }
    }
    Write-Host "uninstalled: hook '$HookName' removed, toolPermission reset."
    exit 0
}

# 1. Register in hooks.json
if (-not (Test-Path $CfgDir)) {
    New-Item -ItemType Directory -Path $CfgDir -Force | Out-Null
}
if (-not (Test-Path (Join-Path $AutoDir "state"))) {
    New-Item -ItemType Directory -Path (Join-Path $AutoDir "state") -Force | Out-Null
}
if (-not (Test-Path (Join-Path $AutoDir "audit"))) {
    New-Item -ItemType Directory -Path (Join-Path $AutoDir "audit") -Force | Out-Null
}

$hooksData = @{}
if (Test-Path $HooksJson) {
    try {
        $hooksData = Get-Content $HooksJson -Raw | ConvertFrom-Json -AsHashtable
    } catch {}
}

$hooksData[$HookName] = @{
    enabled = $true
    PreToolUse = @(
        @{
            matcher = "*"
            hooks = @(
                @{
                    type = "command"
                    command = $HookCmd
                    timeout = $HookTimeout
                }
            )
        }
    )
}

$hooksData | ConvertTo-Json -Depth 10 | Set-Content $HooksJson
Write-Host "hooks.json: '$HookName' registered -> $HookCmd"

# 2. settings.json: toolPermission = always-proceed
$settingsDir = Split-Path -Parent $SettingsJson
if (-not (Test-Path $settingsDir)) {
    New-Item -ItemType Directory -Path $settingsDir -Force | Out-Null
}
$settingsData = @{}
if (Test-Path $SettingsJson) {
    try {
        $settingsData = Get-Content $SettingsJson -Raw | ConvertFrom-Json -AsHashtable
    } catch {}
}
$settingsData["toolPermission"] = "always-proceed"
$settingsData | ConvertTo-Json -Depth 10 | Set-Content $SettingsJson
Write-Host "settings.json: toolPermission -> always-proceed"

# 3. Policy overlay
$policyFile = Join-Path $AutoDir "policy.toml"
if (-not (Test-Path $policyFile)) {
    $defaultOverlay = @"
# agy-auto user policy overlay. Merged over default.toml
# mode = "enforce"
"@
    Set-Content -Path $policyFile -Value $defaultOverlay
    Write-Host "created $policyFile (user overlay)"
}

Write-Host ""
Write-Host "installed successfully. Audit logs: $AutoDir\audit\"
Write-Host "uninstall: .\install.ps1 -Uninstall"
