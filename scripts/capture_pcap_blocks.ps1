# Time-sampled passive capture for a second network, needing only Wireshark (dumpcap + Npcap).
# Same bounds as the first network: 12 blocks of at most 5 minutes or 90 MB, 10 minutes apart.
# It generates no traffic, never chooses an interface, and writes only to the -Out folder.
#
#   & "C:\Program Files\Wireshark\dumpcap.exe" -D          # list interfaces; pick the Wi-Fi one by number
#   powershell -ExecutionPolicy Bypass -File capture_pcap_blocks.ps1 -Interface 4 -Out D:\net2_evening1
#
# Capture only a network you live on, with everyone in the household agreeing first.
param(
    [Parameter(Mandatory = $true)] [string] $Interface,
    [Parameter(Mandatory = $true)] [string] $Out,
    [int] $Blocks = 12,
    [int] $BlockSeconds = 300,
    [int] $GapSeconds = 600,
    [int] $MaxBytes = 94371840,
    [string] $Dumpcap = "C:\Program Files\Wireshark\dumpcap.exe"
)
$ErrorActionPreference = "Stop"
if (-not (Test-Path $Dumpcap)) { throw "dumpcap not found at $Dumpcap; install Wireshark (with Npcap) first" }
if ($Blocks -lt 1 -or $Blocks -gt 48) { throw "-Blocks must be 1-48" }
New-Item -ItemType Directory -Force $Out | Out-Null
if (Get-ChildItem $Out -Filter "block_*.pcap" -ErrorAction SilentlyContinue) { throw "$Out already has block captures; use an empty folder" }

$kib = [int](($MaxBytes - 128 * 1024) / 1024)
$record = [ordered]@{ interface = $Interface; block_seconds = $BlockSeconds; gap_seconds = $GapSeconds
                      max_bytes = $MaxBytes; blocks = @() }
for ($i = 0; $i -lt $Blocks; $i++) {
    $file = "block_{0:D2}.pcap" -f $i
    $started = (Get-Date).ToUniversalTime().ToString("o")
    Write-Host "Block $($i + 1)/$Blocks started $started"
    # Non-promiscuous, full packets (header-only capture corrupts the flow features), pcap format, two autostops.
    & $Dumpcap -q -p -i $Interface -s 65535 -F pcap -a "duration:$BlockSeconds" -a "filesize:$kib" -w (Join-Path $Out $file)
    $record.blocks += [ordered]@{ file = $file; started_utc = $started; exit_code = $LASTEXITCODE }
    $record | ConvertTo-Json -Depth 4 | Set-Content -Encoding utf8 (Join-Path $Out "blocks.json")
    if ($i -lt $Blocks - 1) { Start-Sleep -Seconds $GapSeconds }
}
Write-Host "Done. Bring the folder $Out to the analysis PC in person (USB drive); do not upload or email it."
