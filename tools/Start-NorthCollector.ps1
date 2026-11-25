param(
    [ValidatePattern('^collector-[a-f0-9]{20}$')][string]$Source,
    [ValidatePattern('^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,79}$')][string]$OpenWrtHost,
    [switch]$DisableOpenWrt
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$runtime = Join-Path $root '.north-launcher'
$settings = Join-Path $runtime 'collector-connection.json'
$routerSettings = Join-Path $runtime 'collector-openwrt.txt'
$environment = Join-Path $runtime 'collector-python'
$python = Join-Path $environment 'Scriptspython.exe'
$requirements = Join-Path $root 'backendequirements.txt'
$requirementsStamp = Join-Path $environment 'north-requirements.sha256'
if ($OpenWrtHost -and $DisableOpenWrt) { throw 'Choose an OpenWrt host or disable OpenWrt collection.' }
New-Item -ItemType Directory -Path $runtime -Force | Out-Null

try {
    $collectorLock = [IO.File]::Open((Join-Path $runtime 'collector.lock'), 'OpenOrCreate', 'ReadWrite', 'None')
} catch {
    throw 'NORTH Collector is already running in this folder.'
}
try {
    if (!(Test-Path -LiteralPath $python)) {
        $launcher = Get-Command py.exe -ErrorAction SilentlyContinue
        if (!$launcher) { throw 'Install Python 3.11 or newer with the Windows Python launcher, then reopen NORTH Collector.' }
        & $launcher.Source -3 -c "import sys; sys.exit(sys.version_info < (3, 11))"
        if ($LASTEXITCODE -ne 0) { throw 'NORTH Collector requires Python 3.11 or newer.' }
        & $launcher.Source -3 -m venv $environment
        if ($LASTEXITCODE -ne 0) { throw 'Could not prepare the collector Python environment.' }
    }
    $hash = (Get-FileHash -LiteralPath $requirements).Hash
    if (!(Test-Path -LiteralPath $requirementsStamp) -or (Get-Content -LiteralPath $requirementsStamp) -ne $hash) {
        & $python -m pip install --disable-pip-version-check -r $requirements
        if ($LASTEXITCODE -ne 0) { throw 'Could not install the collector dependencies.' }
        Set-Content -LiteralPath $requirementsStamp -Value $hash
    }
    if ($Source) {
        $address = [Uri]::new((Read-Host 'NORTH Cloud HTTPS address'), [UriKind]::Absolute)
        if ($address.Scheme -ne 'https' -or !$address.Host -or $address.UserInfo -or
            $address.AbsolutePath -ne '/' -or $address.Query -or $address.Fragment) {
            throw 'Enter the HTTPS workspace address without a path, query or credentials.'
        }
        $token = Read-Host 'Collector pairing key' -AsSecureString
        if ($token.Length -ne 64) { throw 'Expected the 64-character pairing key shown in Collectors.' }
        @{
            url = $address.GetLeftPart([UriPartial]::Authority)
            source = $Source
            ingest_key = ConvertFrom-SecureString $token
        } | ConvertTo-Json | Set-Content -LiteralPath $settings -Encoding UTF8
    }
    if (!(Test-Path -LiteralPath $settings)) {
        throw 'Create a pairing in the Collectors screen and run the command it shows once.'
    }
    $connection = Get-Content -LiteralPath $settings -Raw | ConvertFrom-Json
    $credential = [Management.Automation.PSCredential]::new('north', (ConvertTo-SecureString $connection.ingest_key))
    $env:NORTH_CLOUD_URL = $connection.url
    $env:NORTH_CLOUD_SOURCE = $connection.source
    $env:NORTH_CLOUD_INGEST_KEY = $credential.GetNetworkCredential().Password
    $env:NORTH_DB_PATH = Join-Path $runtime 'collector.sqlite3'
    if ($OpenWrtHost) { Set-Content -LiteralPath $routerSettings -Value $OpenWrtHost }
    if ($DisableOpenWrt -and (Test-Path -LiteralPath $routerSettings)) { Remove-Item -LiteralPath $routerSettings }
    Remove-Item Env:NORTH_OPENWRT_HOST -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $routerSettings) {
        $env:NORTH_OPENWRT_HOST = (Get-Content -LiteralPath $routerSettings -Raw).Trim()
    }
    Remove-Item Env:DATABASE_URL -ErrorAction SilentlyContinue
    Write-Host 'NORTH Collector is running. Leave this window open. Press Ctrl+C to stop.'
    & $python (Join-Path $root 'backendun_collector.py')
    if ($LASTEXITCODE -ne 0) { throw 'NORTH Collector stopped with an error.' }
} finally {
    $collectorLock.Dispose()
}
