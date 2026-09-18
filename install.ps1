<#
.SYNOPSIS
    Installs Antigravity Guardian: Approve for Me Mode globally across all Antigravity instances (Desktop App & VS Code Extension).
.DESCRIPTION
    Deploys the plugin to ~/.gemini/config/plugins, registers the lifecycle hook in ~/.gemini/config/hooks.json,
    configures global permission policies in config.json, and adds the guardian CLI tool to PATH.
#>

[CmdletBinding()]
param(
    [string]$TargetDir = "$HOME\.gemini",
    [switch]$InstallPonytail
)

$ErrorActionPreference = "Stop"

Write-Host "
[+] ANTIGRAVITY GUARDIAN: APPROVE FOR ME INSTALLER" -ForegroundColor Cyan
Write-Host "-------------------------------------------------------" -ForegroundColor DarkGray

$configDir = Join-Path $TargetDir "config"
$pluginsDir = Join-Path $configDir "plugins\antigravity-approve-for-me"
$scriptsDir = Join-Path $pluginsDir "scripts"
$binDir = Join-Path $TargetDir "antigravity\bin"
$hooksFile = Join-Path $configDir "hooks.json"
$configFile = Join-Path $configDir "config.json"
$guardianConfigFile = Join-Path $TargetDir "antigravity\guardian.json"

function Write-JsonNoBom([string]$path, [string]$content) {
    [System.IO.File]::WriteAllText($path, $content)
}

# 1. Create directories
Write-Host "[*] Creating plugin directories..." -ForegroundColor Yellow
New-Item -ItemType Directory -Path $scriptsDir -Force | Out-Null
New-Item -ItemType Directory -Path $binDir -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $TargetDir "antigravity") -Force | Out-Null

# 2. Copy plugin files
$sourceDir = $PSScriptRoot
if (Test-Path (Join-Path $sourceDir "plugin")) {
    $pluginSource = Join-Path $sourceDir "plugin"
} else {
    $pluginSource = $sourceDir
}

Write-Host "[*] Copying plugin files to: $pluginsDir" -ForegroundColor Yellow
Copy-Item -Path "$pluginSource\*" -Destination $pluginsDir -Recurse -Force

# 3. Configure hooks.json
Write-Host "[*] Configuring global PreToolUse lifecycle hook in hooks.json..." -ForegroundColor Yellow
if (Test-Path $hooksFile) {
    Copy-Item -Path $hooksFile -Destination "$hooksFile.bak" -Force
}
$hookObj = [PSCustomObject]@{
    "antigravity-guardian-approve-for-me" = [PSCustomObject]@{
        "PreToolUse" = @(
            [PSCustomObject]@{
                "matcher" = "run_command|write_to_file|replace_file_content"
                "hooks" = @(
                    [PSCustomObject]@{
                        "command" = "node plugins/antigravity-approve-for-me/scripts/guardian_engine.js"
                        "timeout" = 5
                    }
                )
            }
        )
    }
}
$hookContent = $hookObj | ConvertTo-Json -Depth 10
Write-JsonNoBom $hooksFile $hookContent

# 4. Configure config.json
Write-Host "[*] Configuring global permissions in config.json..." -ForegroundColor Yellow
if (Test-Path $configFile) {
    Copy-Item -Path $configFile -Destination "$configFile.bak" -Force
    try {
        $rawConfig = [System.IO.File]::ReadAllText($configFile).TrimStart([char]0xFEFF)
        $cfg = $rawConfig | ConvertFrom-Json
    } catch {
        Write-Error "Failed to parse $configFile. A backup was preserved at $configFile.bak. Aborting installation to protect existing configuration: $_"
        exit 1
    }
} else {
    $cfg = [PSCustomObject]@{}
}

if (-not $cfg.plugins) { $cfg | Add-Member -NotePropertyName "plugins" -NotePropertyValue ([PSCustomObject]@{}) -Force }
$cfg.plugins | Add-Member -NotePropertyName "antigravity-approve-for-me" -NotePropertyValue ([PSCustomObject]@{ enabled = $true }) -Force

if (-not $cfg.userSettings) { $cfg | Add-Member -NotePropertyName "userSettings" -NotePropertyValue ([PSCustomObject]@{}) -Force }
$cfg.userSettings | Add-Member -NotePropertyName "autoExecutionPolicy" -NotePropertyValue "CASCADE_COMMANDS_AUTO_EXECUTION_EAGER" -Force
$cfg.userSettings | Add-Member -NotePropertyName "fileAccessPolicy" -NotePropertyValue "AGENT_SETTING_POLICY_ALLOW" -Force
$cfg.userSettings | Add-Member -NotePropertyName "nonWorkspaceFileAccessPolicy" -NotePropertyValue "AGENT_SETTING_POLICY_ALLOW" -Force
$cfg.userSettings | Add-Member -NotePropertyName "internetPolicy" -NotePropertyValue "AGENT_SETTING_POLICY_ALLOW" -Force
$cfg.userSettings | Add-Member -NotePropertyName "artifactReviewMode" -NotePropertyValue "ARTIFACT_REVIEW_MODE_TURBO" -Force

Write-JsonNoBom $configFile ($cfg | ConvertTo-Json -Depth 20)

# 5. Initialize guardian.json default mode
if (-not (Test-Path $guardianConfigFile)) {
    $guardianObj = [PSCustomObject]@{
        "mode" = "approve-for-me"
        "version" = "1.0.0"
        "allowTests" = $true
        "allowBuilds" = $true
        "allowWorkspaceWrites" = $true
        "blockNetworkPipes" = $true
        "blockSecretAccess" = $true
    }
    Write-JsonNoBom $guardianConfigFile ($guardianObj | ConvertTo-Json -Depth 5)
}

# 6. Install global CLI command
Write-Host "[*] Installing 'guardian' CLI wrapper in $binDir..." -ForegroundColor Yellow
$cmdContent = '@echo off' + [Environment]::NewLine + 'node "' + $scriptsDir + '\guardian.js" %*'
Set-Content -Path (Join-Path $binDir "guardian.cmd") -Value $cmdContent -Encoding ASCII

# Ensure $binDir is in persistent User PATH
try {
    $userPath = [Environment]::GetEnvironmentVariable("PATH", [EnvironmentVariableTarget]::User)
    if ($userPath -split ';' -notcontains $binDir) {
        Write-Host "[*] Adding $binDir to User PATH..." -ForegroundColor Yellow
        $newPath = if ([string]::IsNullOrWhiteSpace($userPath)) { $binDir } else { "$userPath;$binDir" }
        [Environment]::SetEnvironmentVariable("PATH", $newPath, [EnvironmentVariableTarget]::User)
    }
    $env:PATH = "$env:PATH;$binDir"
} catch {
    Write-Warning "Could not update User PATH automatically: $_"
}

# 7. Update all existing project configs if any
$projectsDir = Join-Path $configDir "projects"
if (Test-Path $projectsDir) {
    Write-Host "[*] Updating existing project profiles..." -ForegroundColor Yellow
    Get-ChildItem (Join-Path $projectsDir "*.json") | ForEach-Object {
        try {
            $rawP = [System.IO.File]::ReadAllText($_.FullName).TrimStart([char]0xFEFF)
            $pData = $rawP | ConvertFrom-Json
            if (-not $pData.settings) { $pData | Add-Member -NotePropertyName "settings" -NotePropertyValue ([PSCustomObject]@{}) -Force }
            $pData.settings | Add-Member -NotePropertyName "autoExecutionPolicy" -NotePropertyValue "CASCADE_COMMANDS_AUTO_EXECUTION_EAGER" -Force
            $pData.settings | Add-Member -NotePropertyName "fileAccessPolicy" -NotePropertyValue "AGENT_SETTING_POLICY_ALLOW" -Force
            $pData.settings | Add-Member -NotePropertyName "internetPolicy" -NotePropertyValue "AGENT_SETTING_POLICY_ALLOW" -Force
            Write-JsonNoBom $_.FullName ($pData | ConvertTo-Json -Depth 10)
        } catch {}
    }
}

# 8. Companion Plugin: Ponytail (Optional / Recommended)
$ponytailDir = Join-Path $configDir "plugins\ponytail-plugin"
if ($InstallPonytail) {
    Write-Host "[*] Installing companion Ponytail plugin from https://github.com/DietrichGebert/ponytail..." -ForegroundColor Yellow
    if (Test-Path $ponytailDir) {
        Write-Host "[i] Ponytail is already installed at: $ponytailDir" -ForegroundColor DarkGray
    } else {
        try {
            git clone https://github.com/DietrichGebert/ponytail.git $ponytailDir
            Write-Host "[+] Ponytail successfully installed!" -ForegroundColor Green
        } catch {
            Write-Warning "Could not clone Ponytail repository: $_"
        }
    }
}

Write-Host "
[SUCCESS] INSTALLATION COMPLETE!" -ForegroundColor Green
Write-Host "Antigravity Guardian: Approve for Me mode is now active across:" -ForegroundColor White
Write-Host "  * Google AntiGravity Desktop App" -ForegroundColor Gray
Write-Host "  * Antigravity VS Code Extension / IDE" -ForegroundColor Gray
Write-Host "  * Antigravity CLI (agy)
" -ForegroundColor Gray
Write-Host "Test it from any terminal with: guardian status" -ForegroundColor Cyan

Write-Host "`nCompanion Ecosystem:" -ForegroundColor White
Write-Host "  * Ponytail (Anti-Bloat & YAGNI Engine) by Dietrich Gebert" -ForegroundColor Gray
Write-Host "    Repository: https://github.com/DietrichGebert/ponytail" -ForegroundColor Gray
if (Test-Path $ponytailDir) {
    Write-Host "    Status: Installed at $ponytailDir" -ForegroundColor Green
} else {
    Write-Host "    Status: Not installed. Run with -InstallPonytail to install." -ForegroundColor DarkGray
}

