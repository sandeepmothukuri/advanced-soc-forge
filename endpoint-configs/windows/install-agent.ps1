#Requires -RunAsAdministrator
<#
.SYNOPSIS
    SOC Lab Windows Agent Installer — Sysmon + Winlogbeat
.DESCRIPTION
    Installs Sysmon (with SOC config) and Winlogbeat on a Windows endpoint.
    Connects the host to the SOC pipeline (Vector → OpenSearch).
.PARAMETER VectorHost
    IP or hostname of the Vector log aggregator (default: auto-detect from SOC_VECTOR_HOST env)
.EXAMPLE
    .\install-agent.ps1 -VectorHost 192.168.10.30
#>
param(
    [string]$VectorHost = $env:SOC_VECTOR_HOST ?? "192.168.10.30",
    [string]$SocLabDir  = "C:\SOCLab"
)

$ErrorActionPreference = "Stop"
$ProgressPreference    = "SilentlyContinue"

Write-Host "`n╔══════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║   SOC Lab Windows Agent Installer v2.0              ║" -ForegroundColor Cyan
Write-Host "║   Sysmon 15 + Winlogbeat 8 + SOC Detection Rules    ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════╝`n" -ForegroundColor Cyan

# ── Directories ──────────────────────────────────────────────────────────────
New-Item -ItemType Directory -Force -Path $SocLabDir | Out-Null
New-Item -ItemType Directory -Force -Path "$SocLabDir\tools" | Out-Null
New-Item -ItemType Directory -Force -Path "$SocLabDir\configs" | Out-Null

# ── Step 1: Download Sysmon ───────────────────────────────────────────────────
Write-Host "[1/5] Downloading Sysmon 15..." -ForegroundColor Yellow
$sysmonUrl = "https://download.sysinternals.com/files/Sysmon.zip"
$sysmonZip = "$SocLabDir\tools\Sysmon.zip"
Invoke-WebRequest -Uri $sysmonUrl -OutFile $sysmonZip -UseBasicParsing
Expand-Archive -Path $sysmonZip -DestinationPath "$SocLabDir\tools\sysmon" -Force

# ── Step 2: Download SOC sysmon config ───────────────────────────────────────
Write-Host "[2/5] Fetching SOC Sysmon config..." -ForegroundColor Yellow
# In production: fetch from your SOC config server
# For lab: copy from this repo
$configSrc = "\\$VectorHost\soc-configs\sysmon-config.xml"
if (Test-Path $configSrc) {
    Copy-Item $configSrc "$SocLabDir\configs\sysmon-config.xml" -Force
} else {
    Write-Warning "Config server unreachable — using embedded minimal config"
    # Fallback: minimal inline config
    @'
<Sysmon schemaversion="4.90">
  <HashAlgorithms>md5,sha256</HashAlgorithms>
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <ProcessCreate onmatch="exclude"/>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
'@ | Out-File "$SocLabDir\configs\sysmon-config.xml" -Encoding UTF8
}

# ── Step 3: Install Sysmon ────────────────────────────────────────────────────
Write-Host "[3/5] Installing Sysmon with SOC config..." -ForegroundColor Yellow
$sysmonExe = "$SocLabDir\tools\sysmon\Sysmon64.exe"
# Uninstall existing if present
& $sysmonExe -u 2>$null
Start-Sleep 2
# Install with SOC config
& $sysmonExe -accepteula -i "$SocLabDir\configs\sysmon-config.xml" -l -n
if ($LASTEXITCODE -ne 0) { throw "Sysmon install failed: exit $LASTEXITCODE" }
Write-Host "   ✅ Sysmon installed" -ForegroundColor Green

# ── Step 4: Download and install Winlogbeat ───────────────────────────────────
Write-Host "[4/5] Installing Winlogbeat 8..." -ForegroundColor Yellow
$wlbUrl   = "https://artifacts.elastic.co/downloads/beats/winlogbeat/winlogbeat-8.14.0-windows-x86_64.zip"
$wlbZip   = "$SocLabDir\tools\winlogbeat.zip"
$wlbDir   = "C:\Program Files\winlogbeat"
Invoke-WebRequest -Uri $wlbUrl -OutFile $wlbZip -UseBasicParsing
Expand-Archive -Path $wlbZip -DestinationPath "C:\Program Files\" -Force
$wlbExtracted = Get-ChildItem "C:\Program Files\" -Filter "winlogbeat-*" | Select-Object -First 1
Rename-Item $wlbExtracted.FullName $wlbDir -Force -ErrorAction SilentlyContinue

# Write winlogbeat config with actual Vector host
$wlbConfig = Get-Content "$SocLabDir\configs\winlogbeat.yml" -Raw -ErrorAction SilentlyContinue
if (-not $wlbConfig) {
    $wlbConfig = @"
winlogbeat.event_logs:
  - name: Security
    event_id: 4624,4625,4648,4672,4688,4698,4699,4700,4720
  - name: Microsoft-Windows-Sysmon/Operational
  - name: Microsoft-Windows-PowerShell/Operational
    event_id: 4104

output.logstash:
  hosts: ["${VectorHost}:5044"]

processors:
  - add_host_metadata: ~
"@
}
$wlbConfig -replace 'vector', $VectorHost | Out-File "$wlbDir\winlogbeat.yml" -Encoding UTF8

# Install as Windows service
Push-Location $wlbDir
& powershell -File install-service-winlogbeat.ps1
Pop-Location
Start-Service winlogbeat -ErrorAction SilentlyContinue
Write-Host "   ✅ Winlogbeat installed and started" -ForegroundColor Green

# ── Step 5: Validate ─────────────────────────────────────────────────────────
Write-Host "[5/5] Validating agent deployment..." -ForegroundColor Yellow
$sysmonSvc = Get-Service "Sysmon64" -ErrorAction SilentlyContinue
$wlbSvc    = Get-Service "winlogbeat" -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "══════════════════════ DEPLOYMENT SUMMARY ════════════════════════" -ForegroundColor Cyan
Write-Host " Host:       $env:COMPUTERNAME" -ForegroundColor White
Write-Host " Vector:     $VectorHost`:5044" -ForegroundColor White
Write-Host " Sysmon:     $(if ($sysmonSvc.Status -eq 'Running') {'✅ Running'} else {'❌ NOT Running'})" -ForegroundColor $(if ($sysmonSvc.Status -eq 'Running') {'Green'} else {'Red'})
Write-Host " Winlogbeat: $(if ($wlbSvc.Status -eq 'Running') {'✅ Running'} else {'❌ NOT Running'})" -ForegroundColor $(if ($wlbSvc.Status -eq 'Running') {'Green'} else {'Red'})
Write-Host "══════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
Write-Host "🔍 Verify in OpenSearch: index soc-logs-* | filter host.name: $env:COMPUTERNAME" -ForegroundColor Yellow
