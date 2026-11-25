[CmdletBinding(DefaultParameterSetName = 'Enable')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Enable')]
    [switch]$Enable,
    [Parameter(Mandatory, ParameterSetName = 'Pair')]
    [switch]$Pair,
    [Parameter(Mandatory, ParameterSetName = 'Enable')]
    [Parameter(ParameterSetName = 'Pair')]
    [string]$Url,
    [Parameter(ParameterSetName = 'Enable')]
    [Parameter(Mandatory, ParameterSetName = 'Pair')]
    [ValidatePattern('^[a-z0-9][a-z0-9-]{0,47}$')]
    [string]$Source = 'windows-pc',
    [Parameter(ParameterSetName = 'Enable')]
    [ValidateLength(1, 80)]
    [string]$Label = 'Windows PC',
    [Parameter(Mandatory, ParameterSetName = 'Disable')]
    [switch]$Disable
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$runtime = Join-Path $root '.north-launcher'
$settings = Join-Path $runtime 'cloud-connection.json'

if ($Disable) {
    if (Test-Path -LiteralPath $settings) { Remove-Item -LiteralPath $settings }
    Write-Host 'Cloud sync is disabled for the next launcher start. Restart NORTH to stop an active sync.'
    return
}

if ($Pair -and !$Url) { $Url = Read-Host 'NORTH Cloud HTTPS address' }
$destination = [Uri]::new($Url, [UriKind]::Absolute)
if ($destination.Scheme -ne 'https' -or !$destination.Host -or $destination.UserInfo -or
    $destination.AbsolutePath -ne '/' -or $destination.Query -or $destination.Fragment) {
    throw 'Enter an HTTPS workspace address without credentials, a page path, or a query.'
}
if ($Enable -and !(Test-Path -LiteralPath (Join-Path $runtime 'cloud-keys.json'))) {
    throw 'No workspace keys were found. Deploy NORTH Cloud from this Windows account first.'
}

$connection = @{
    url = $destination.GetLeftPart([UriPartial]::Authority)
    source = $Source
    label = $Label
}
if ($Pair) {
    $token = Read-Host 'Pairing key' -AsSecureString
    if ($token.Length -ne 64) { throw 'Expected the 64-character key shown in Collectors.' }
    $connection.ingest_key = ConvertFrom-SecureString $token
}
New-Item -ItemType Directory -Path $runtime -Force | Out-Null
$connection | ConvertTo-Json | Set-Content -LiteralPath $settings -Encoding UTF8
Write-Host "Cloud sync enabled for $($destination.GetLeftPart([UriPartial]::Authority))."
Write-Host 'Restart NORTH with Start NORTH.cmd to begin syncing local telemetry.'
