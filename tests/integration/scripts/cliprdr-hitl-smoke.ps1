# CLIPRDR bidirectional HITL smoke — PRD #35 Module D / E reusable harness.
#
# Drives the host-side trigger via PSRemoting + Set-Clipboard against a
# configured RDP server, runs the headless `cliprdr_cli` example for a
# bounded duration, and asserts that the expected `[DIAG-clip]` log
# lines appear, proving the cliprdr channel made a full round trip.
#
# Replaces the previous "open Tauri, copy in VM, paste on host" manual
# smoke from PRD #34 with a single CLI invocation. Reproducible without
# GUI manipulation.
#
# Prerequisites on the host running this script (one-time, admin shell):
#
#     Start-Service WinRM
#     Set-Item WSMan:\localhost\Client\TrustedHosts -Value '192.168.136.136' -Force -Concatenate
#
# Prerequisites on the test VM (one-time):
#     `rdptest` must be an Administrator or member of `Remote Management
#     Users`, and (for workgroup hosts)
#     `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\
#     LocalAccountTokenFilterPolicy` must be 1.
#
# Usage:
#     pwsh tests/integration/scripts/cliprdr-hitl-smoke.ps1 `
#         -Host 192.168.136.136 -User rdptest -Password 'qweQWEqwe@'
#
# Exit codes:
#     0 — smoke passed (both directions visible in [DIAG-clip])
#     1 — argument / setup failure
#     2 — cliprdr_cli returned a runtime error
#     3 — smoke failed (expected log markers missing)

param(
    [Parameter(Mandatory=$true)] [string] $RdpHost,
    [Parameter(Mandatory=$true)] [string] $User,
    [Parameter(Mandatory=$true)] [string] $Password,
    [int] $Seconds = 30,
    [string] $Cap = '0x02'
)

$ErrorActionPreference = 'Stop'

$secure = ConvertTo-SecureString $Password -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential ($User, $secure)

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..' '..' '..')
$cliprdrCli = Join-Path $repoRoot 'target' 'debug' 'examples' 'cliprdr_cli.exe'
if (-not (Test-Path $cliprdrCli)) {
    Write-Error "cliprdr_cli not built. Run: cargo build -p justrdp-blocking --example cliprdr_cli"
    exit 1
}

# Marker text that travels host -> server -> host so we can verify both
# directions in one run. The timestamp prevents collisions with stale
# clipboard contents from a previous test run.
$marker = "PRD-35-HITL-$(Get-Date -Format 'HHmmss')"
Write-Host "[HITL] marker=$marker host=$RdpHost user=$User cap=$Cap seconds=$Seconds"

# Pre-seed the host clipboard before launching the binary so the Win32
# listener can pick up the change once it starts.
Set-Clipboard -Value $marker
Write-Host "[HITL] host clipboard seeded with marker"

# Start cliprdr_cli in the background with verbose logging. RUST_LOG
# includes the trace target for the wire-byte dump.
$env:RUST_LOG = 'info,justrdp_svc::chunk=trace'
$logFile = New-TemporaryFile
Write-Host "[HITL] log -> $logFile"
$proc = Start-Process -FilePath $cliprdrCli `
    -ArgumentList @(
        '--host', $RdpHost,
        '--user', $User,
        '--password', $Password,
        '--cap', $Cap,
        '--seconds', $Seconds
    ) `
    -RedirectStandardError $logFile `
    -PassThru `
    -NoNewWindow

# Wait for the handshake to complete (CliprdrClient.state=Initialized)
# before triggering the VM-side copy.
$timeout = (Get-Date).AddSeconds(10)
do {
    Start-Sleep -Milliseconds 500
    $content = Get-Content -Raw $logFile -ErrorAction SilentlyContinue
} until (
    ($content -match 'state=Initialized') -or ((Get-Date) -gt $timeout) -or $proc.HasExited
)

if ($content -notmatch 'state=Initialized') {
    Write-Error "[HITL] cliprdr handshake never completed; check log $logFile"
    exit 2
}
Write-Host "[HITL] handshake complete — triggering VM-side Set-Clipboard"

# Drive the server-side copy via PSRemoting. This is what would otherwise
# require a human inside the VM doing Ctrl+C.
$vmMarker = "$marker-from-vm"
Invoke-Command -ComputerName $RdpHost -Credential $cred -ScriptBlock {
    param($m) Set-Clipboard -Value $m
} -ArgumentList $vmMarker

# Wait for the binary to finish its bounded window.
$proc.WaitForExit()
$content = Get-Content -Raw $logFile

# Assertions: the round trip should produce *both* of these markers.
$hostToServerOk = $content -match '\[DIAG-clip\] poll emit total_len=\d+'
$serverToHostOk = $content -match '\[DIAG-clip\] CliprdrClient\.process pdu_type=FormatList'

Write-Host "[HITL] host->server outbound seen: $hostToServerOk"
Write-Host "[HITL] server->host inbound seen:  $serverToHostOk"

if (-not ($hostToServerOk -and $serverToHostOk)) {
    Write-Error "[HITL] FAIL: full bidirectional cliprdr round trip not observed. Log: $logFile"
    exit 3
}

Write-Host "[HITL] PASS — bidirectional cliprdr smoke complete"
exit 0
