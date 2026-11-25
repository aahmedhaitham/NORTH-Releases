param([long]$After = 0, [switch]$Recent)

$ErrorActionPreference = 'Stop'
$channel = 'Microsoft-Windows-Sysmon/Operational'
. (Join-Path $PSScriptRoot 'SysmonFormat.ps1')
$null = Get-WinEvent -ListLog $channel -ErrorAction Stop

function Read-Events([string]$Query, [int]$Limit, [switch]$Oldest) {
    try {
        Get-WinEvent -LogName $channel -FilterXPath $Query -MaxEvents $Limit -Oldest:$Oldest -ErrorAction Stop
    } catch {
        if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound,*') { throw }
    }
}

$latest = Read-Events '*' 1
$tail = if ($latest) { [long]$latest.RecordId } else { 0 }
if ($tail -lt $After) { $After = 0 }
$query = "*[System[(EventID=1 or EventID=3 or EventID=11) and EventRecordID > $After]]"
$records = if ($Recent) { @(Read-Events $query 200) } else { @(Read-Events $query 500 -Oldest) }
$records = @($records | Where-Object { $null -ne $_ })
$position = if ($records.Count) { [long]$records[-1].RecordId } else { $tail }
$alerts = @(
    foreach ($event in $records) {
        Export-NorthEvent @{ event = $event; fields = Read-SysmonFields $event }
    }
)

[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
ConvertTo-Json -InputObject @{ position = $position; alerts = $alerts } -Depth 8 -Compress
