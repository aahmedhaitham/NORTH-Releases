$ErrorActionPreference = 'Stop'
$channel = 'Microsoft-Windows-Sysmon/Operational'
$null = Get-WinEvent -ListLog $channel -ErrorAction Stop
. (Join-Path $PSScriptRoot 'SysmonFormat.ps1')

$output = Join-Path (Split-Path -Parent $PSScriptRoot) 'raw-logs'
New-Item -Path $output -ItemType Directory -Force | Out-Null
$tag = 'north-telemetry-' + [guid]::NewGuid().ToString('N')
$marker = Join-Path $output "$tag.ps1"
$quotedPath = $marker.Replace("'", "''")
$command = "[IO.File]::WriteAllText('$quotedPath', '# NORTH telemetry test file')"
$start = Get-Date

# The child writes a comment-only file. The file is never executed.
& powershell.exe -NoProfile -NonInteractive -Command $command
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $marker)) {
    throw 'The test process did not create the marker file.'
}

$filter = @{ LogName = $channel; Id = 1, 11; StartTime = $start }
$deadline = (Get-Date).AddSeconds(15)
do {
    $records = @(
        Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue | ForEach-Object {
            @{ event = $_; fields = Read-SysmonFields $_ }
        }
    )
    $file = $records | Where-Object {
        $_.event.Id -eq 11 -and $_.fields.TargetFilename -eq $marker -and $_.fields.ProcessGuid
    } | Select-Object -First 1
    if ($file) {
        $process = $records | Where-Object {
            $_.event.Id -eq 1 -and $_.fields.ProcessGuid -eq $file.fields.ProcessGuid
        } | Select-Object -First 1
        if ($process) { break }
    }
    Start-Sleep -Milliseconds 300
} while ((Get-Date) -lt $deadline)

if (-not $file -or -not $process) {
    throw 'Sysmon did not record both matching events. Check the capture configuration and log access.'
}

$destination = Join-Path $output "$tag.json"
$events = @(Export-NorthEvent $process; Export-NorthEvent $file)
ConvertTo-Json -InputObject $events -Depth 8 | Set-Content -LiteralPath $destination -Encoding UTF8
Write-Host "Saved two real Sysmon events to $destination"
