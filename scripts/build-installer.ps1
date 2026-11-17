# Builds the OPH-S Windows installer (NSIS) with the Windows agent and Android APK bundled.
# Usage:  powershell -ExecutionPolicy Bypass -File scripts\build-installer.ps1 [-Icon op-shield]
param([string]$Icon = "op-shield")
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

Write-Host "1/4 Agent (release)"
cargo build --release -p oph-agent
if ($LASTEXITCODE) { throw "agent build failed" }

Write-Host "2/4 Android APK"
if (-not (Test-Path "dist\OPH-S.apk")) {
  if (Test-Path "android\gradlew.bat") {
    $env:JAVA_HOME = "C:\Program Files\Android\Android Studio\jbr"
    Push-Location android; .\gradlew.bat assembleRelease; Pop-Location
  }
  if (-not (Test-Path "dist\OPH-S.apk")) { throw "dist\OPH-S.apk missing: build the Android app first" }
}

Write-Host "3/4 Icon: $Icon"
$icons = "app\src-tauri\icons"
if ((Test-Path "app\ui\icons\$Icon.svg") -and (Get-Command node -ErrorAction SilentlyContinue) -and $env:OPH_ICON_TOOL) {
  node $env:OPH_ICON_TOOL $root $Icon   # regenerates icon.ico / png set from the chosen concept
}

Write-Host "4/4 Installer"
Push-Location app\src-tauri
cargo tauri build --config tauri.installer.conf.json
if ($LASTEXITCODE) { Pop-Location; throw "tauri build failed" }
Pop-Location
$setup = Get-ChildItem "target\release\bundle\nsis\*.exe" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
New-Item -ItemType Directory -Force dist | Out-Null
Copy-Item $setup.FullName "dist\$($setup.Name)" -Force
Write-Host "Installer: dist\$($setup.Name)"
