param([switch]$ShowAccessKey, [switch]$EnableCloudAI)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$configPath = Join-Path $root 'cloud\wrangler.jsonc'
$templatePath = Join-Path $root 'cloud\wrangler.example.jsonc'
$stateDirectory = Join-Path $root '.north-launcher'
$keyPath = Join-Path $stateDirectory 'cloud-keys.json'

function Invoke-Wrangler {
    & npx.cmd --yes wrangler @args
    if ($LASTEXITCODE -ne 0) { throw "Wrangler command failed (exit $LASTEXITCODE)." }
}

function New-Secret {
    $bytes = New-Object byte[] 32
    $random = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $random.GetBytes($bytes) } finally { $random.Dispose() }
    return [Convert]::ToBase64String($bytes)
}

function Find-NorthDatabase {
    $databases = Invoke-Wrangler d1 list --json | Out-String | ConvertFrom-Json
    return $databases | Where-Object { $_.name -eq 'north-cloud' } | Select-Object -First 1
}

function Get-Secrets {
    if (Test-Path -LiteralPath $keyPath) {
        $saved = Get-Content -LiteralPath $keyPath -Raw | ConvertFrom-Json
        $result = @{}
        foreach ($field in $saved.PSObject.Properties) {
            $secure = ConvertTo-SecureString $field.Value
            $credential = [Management.Automation.PSCredential]::new('north', $secure)
            $result[$field.Name] = $credential.GetNetworkCredential().Password
        }
        return $result
    }
    $result = @{}
    $encrypted = @{}
    foreach ($name in 'NORTH_ACCESS_KEY','NORTH_INGEST_KEY','NORTH_SESSION_SECRET') {
        $result[$name] = New-Secret
        $encrypted[$name] = ConvertFrom-SecureString (ConvertTo-SecureString $result[$name] -AsPlainText -Force)
    }
    New-Item -ItemType Directory -Path $stateDirectory -Force | Out-Null
    $encrypted | ConvertTo-Json | Set-Content -LiteralPath $keyPath -Encoding UTF8
    return $result
}

Push-Location -LiteralPath $root
try {
    if ($ShowAccessKey) {
        if (!(Test-Path -LiteralPath $keyPath)) { throw 'Deploy NORTH Cloud before retrieving its key.' }
        Write-Host "NORTH sign-in key: $((Get-Secrets)['NORTH_ACCESS_KEY'])"
        return
    }
    if (!(Test-Path -LiteralPath $configPath)) {
        $database = Find-NorthDatabase
        if (!$database) {
            Invoke-Wrangler d1 create north-cloud
            $database = Find-NorthDatabase
        }
        $identifier = [guid]::Empty
        if (!$database -or ![guid]::TryParse([string]$database.uuid, [ref]$identifier)) {
            throw 'Could not find the north-cloud database ID.'
        }
        $config = Get-Content -LiteralPath $templatePath -Raw | ConvertFrom-Json
        $config.d1_databases[0].database_id = $identifier.ToString()
        [IO.File]::WriteAllText($configPath, ($config | ConvertTo-Json -Depth 8))
    }

    Invoke-Wrangler d1 execute north-cloud --config $configPath --remote --file cloud/schema.sql
    & npm.cmd --prefix frontend run build -- --mode cloud
    if ($LASTEXITCODE -ne 0) { throw 'Cloud frontend build failed.' }
    $deploymentConfig = $configPath
    if ($EnableCloudAI) {
        $deploymentConfig = Join-Path $root 'cloudwrangler.ai.local.jsonc'
        $config = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
        $config | Add-Member -NotePropertyName ai -NotePropertyValue @{ binding = 'AI' } -Force
        [IO.File]::WriteAllText($deploymentConfig, ($config | ConvertTo-Json -Depth 8))
    }
    $deployment = @(Invoke-Wrangler deploy --config $deploymentConfig)
    $deployment | Write-Output

    $secrets = Get-Secrets
    ($secrets | ConvertTo-Json -Compress) | & npx.cmd --yes wrangler secret bulk --config $deploymentConfig
    if ($LASTEXITCODE -ne 0) { throw 'Cloudflare did not accept the workspace secrets.' }

    $url = [regex]::Match(($deployment -join "`n"), 'https://[a-z0-9.-]+\.workers\.dev').Value
    if ($url) { Write-Host "NORTH Cloud URL: $url" }
    Write-Host 'Deployment complete. Run this script with -ShowAccessKey to view your private sign-in key.'
    Write-Host 'No local telemetry was uploaded.'
} finally {
    Pop-Location
}
