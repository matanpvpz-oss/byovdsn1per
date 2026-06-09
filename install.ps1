[CmdletBinding()]
param(
    [switch]$Uninstall,
    [string]$InstallDir = (Join-Path $env:LOCALAPPDATA "Programs\BYOVDsn1per")
)

$ErrorActionPreference = "Stop"
$source = $PSScriptRoot

function Add-ToUserPath {
    param([string]$Dir)
    $current = [Environment]::GetEnvironmentVariable("PATH", "User")
    if ([string]::IsNullOrEmpty($current)) { $current = "" }
    $parts = $current -split ';' | Where-Object { $_ -ne "" }
    if ($parts -notcontains $Dir) {
        $new = (@($Dir) + $parts) -join ';'
        [Environment]::SetEnvironmentVariable("PATH", $new, "User")
        Write-Host "  + added to USER PATH: $Dir" -ForegroundColor Green
        return $true
    }
    Write-Host "  - already in USER PATH: $Dir" -ForegroundColor DarkGray
    return $false
}

function Remove-FromUserPath {
    param([string]$Dir)
    $current = [Environment]::GetEnvironmentVariable("PATH", "User")
    if ([string]::IsNullOrEmpty($current)) { return $false }
    $parts = $current -split ';' | Where-Object { $_ -ne "" -and $_ -ne $Dir }
    $new = $parts -join ';'
    if ($new -ne $current) {
        [Environment]::SetEnvironmentVariable("PATH", $new, "User")
        Write-Host "  - removed from USER PATH: $Dir" -ForegroundColor Yellow
        return $true
    }
    return $false
}

if ($Uninstall) {
    Write-Host "BYOVDsn1per uninstaller"
    Write-Host "  install dir: $InstallDir"
    if (Test-Path $InstallDir) {
        Remove-Item -Recurse -Force $InstallDir
        Write-Host "  - removed $InstallDir" -ForegroundColor Yellow
    } else {
        Write-Host "  (not installed)"
    }
    Remove-FromUserPath -Dir $InstallDir | Out-Null
    Write-Host ""
    Write-Host "Open a NEW terminal for PATH changes to apply." -ForegroundColor Cyan
    exit 0
}

Write-Host "BYOVDsn1per installer"
Write-Host "  source:      $source"
Write-Host "  install dir: $InstallDir"
Write-Host ""

foreach ($f in @("BYOVDsn1per.py", "BYOVDsn1per.cmd")) {
    $p = Join-Path $source $f
    if (-not (Test-Path $p)) {
        Write-Host "  ! missing $f in $source" -ForegroundColor Red
        Write-Host "    Run install.ps1 from the repository root." -ForegroundColor Red
        exit 1
    }
}

$py = $null
try {
    $py = (Get-Command python -ErrorAction Stop).Source
} catch {
    try {
        $py = (Get-Command py -ErrorAction Stop).Source + "  (Windows launcher)"
    } catch {
        Write-Host "  ! Python not found on PATH." -ForegroundColor Red
        Write-Host "    Install Python 3.10+ from https://www.python.org/downloads/" -ForegroundColor Red
        Write-Host "    Make sure 'Add to PATH' is checked during install." -ForegroundColor Red
        exit 1
    }
}
Write-Host "  python:      $py" -ForegroundColor Green

if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    Write-Host "  + created $InstallDir" -ForegroundColor Green
} else {
    Write-Host "  - install dir already exists: $InstallDir" -ForegroundColor DarkGray
}

foreach ($f in @("BYOVDsn1per.py", "BYOVDsn1per.cmd", "README.md")) {
    $src = Join-Path $source $f
    if (Test-Path $src) {
        Copy-Item $src (Join-Path $InstallDir $f) -Force
        Write-Host "  + copied $f" -ForegroundColor Green
    }
}

$alias = Join-Path $InstallDir "byovdsn1per.cmd"
if (-not (Test-Path $alias)) {
    Copy-Item (Join-Path $InstallDir "BYOVDsn1per.cmd") $alias -Force
    Write-Host "  + created lowercase alias: byovdsn1per.cmd" -ForegroundColor Green
}

Add-ToUserPath -Dir $InstallDir | Out-Null

$defaultCrawlOut = Join-Path $env:APPDATA "BYOVDsn1per\crawler"
if (-not (Test-Path $defaultCrawlOut)) {
    New-Item -ItemType Directory -Path $defaultCrawlOut -Force | Out-Null
    Write-Host "  + pre-created default crawl output: $defaultCrawlOut" -ForegroundColor Green
}

Write-Host ""
Write-Host "Install complete." -ForegroundColor Cyan
Write-Host ""
Write-Host "  Open a NEW terminal, then try:" -ForegroundColor Cyan
Write-Host "    byovdsn1per --version"
Write-Host "    byovdsn1per --help"
Write-Host "    byovdsn1per --list-default-roots"
Write-Host ""
Write-Host "  Crawl results go to: $defaultCrawlOut" -ForegroundColor Cyan
Write-Host "  Override with: --crawl-out DIR"
