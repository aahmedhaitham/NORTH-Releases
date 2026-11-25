param([switch]$Stop)

$ErrorActionPreference = 'Stop'
$runtime = Join-Path $PSScriptRoot '.north-launcher'
$statePath = Join-Path $runtime 'servers.json'
$backend = Join-Path $PSScriptRoot 'backend'
$frontend = Join-Path $PSScriptRoot 'frontend'
$python = Join-Path $backend '.venv\Scripts\python.exe'
$vite = Join-Path $frontend 'node_modules\vite\bin\vite.js'

function Stop-NorthServer($server) {
    $process = Get-Process -Id ([int]$server.id) -ErrorAction SilentlyContinue
    if ($null -eq $process -or $process.StartTime.ToUniversalTime().Ticks.ToString() -ne $server.started) {
        return
    }
    & taskkill.exe /PID $process.Id /T /F 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0 -and -not $process.HasExited) {
        throw "Could not stop NORTH's $($server.name) process."
    }
}

function Start-NorthServer($name, $program, $arguments, $directory) {
    $process = Start-Process -FilePath $program -ArgumentList $arguments -WorkingDirectory $directory `
        -RedirectStandardOutput (Join-Path $runtime "$name.out.log") `
        -RedirectStandardError (Join-Path $runtime "$name.err.log") `
        -WindowStyle Hidden -PassThru
    return @{
        name = $name
        id = $process.Id
        started = $process.StartTime.ToUniversalTime().Ticks.ToString()
    }
}

function Wait-NorthServer($server, $url) {
    $deadline = [DateTime]::UtcNow.AddSeconds(25)
    do {
        if (-not (Get-Process -Id $server.id -ErrorAction SilentlyContinue)) {
            break
        }
        try {
            $response = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 2
            if ($response.StatusCode -eq 200) {
                return
            }
        } catch {
            Start-Sleep -Milliseconds 300
        }
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "$($server.name) did not start. See $(Join-Path $runtime "$($server.name).err.log")."
}

New-Item -ItemType Directory -Path $runtime -Force | Out-Null
try {
    $lock = [IO.File]::Open((Join-Path $runtime 'restart.lock'), 'OpenOrCreate', 'ReadWrite', 'None')
} catch {
    Write-Host 'NORTH is already being started or restarted.' -ForegroundColor Red
    exit 1
}

$started = @()
try {
    if (-not $Stop) {
        if (-not (Test-Path -LiteralPath $python -PathType Leaf) -or -not (Test-Path -LiteralPath $vite -PathType Leaf)) {
            throw 'Install the backend and frontend dependencies using the README before launching NORTH.'
        }
        $node = (Get-Command node.exe -ErrorAction Stop).Source
    }
    if (Test-Path -LiteralPath $statePath) {
        $previous = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
        foreach ($server in $previous) {
            Stop-NorthServer $server
        }
        Remove-Item -LiteralPath $statePath
    }
    if ($Stop) { return }

    $listeners = [Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetActiveTcpListeners()
    $occupied = @($listeners | Where-Object { $_.Port -in 8000, 5173 } | Select-Object -ExpandProperty Port -Unique)
    if ($occupied.Count) {
        throw "Port(s) $($occupied -join ', ') already in use. If you started NORTH manually, press Ctrl+C in those tabs and run this launcher again."
    }

    $env:NORTH_NETWORK_AUTO = '1'
    $env:NORTH_SYSMON_AUTO = '1'
    $cloudConnection = Join-Path $runtime 'cloud-connection.json'
    if (Test-Path -LiteralPath $cloudConnection) {
        $connection = Get-Content -LiteralPath $cloudConnection -Raw | ConvertFrom-Json
        $storedKey = $connection.ingest_key
        if (!$storedKey) {
            $keys = Get-Content -LiteralPath (Join-Path $runtime 'cloud-keys.json') -Raw | ConvertFrom-Json
            $storedKey = $keys.NORTH_INGEST_KEY
        }
        $secureKey = ConvertTo-SecureString $storedKey
        $credential = [Management.Automation.PSCredential]::new('north', $secureKey)
        $env:NORTH_CLOUD_URL = $connection.url
        $env:NORTH_CLOUD_SOURCE = $connection.source
        $env:NORTH_CLOUD_LABEL = $connection.label
        $env:NORTH_CLOUD_INGEST_KEY = $credential.GetNetworkCredential().Password
    }
    $started += Start-NorthServer 'backend' $python '-m uvicorn main:app --host 127.0.0.1 --port 8000' $backend
    ConvertTo-Json -InputObject $started | Set-Content -LiteralPath $statePath -Encoding UTF8
    Wait-NorthServer $started[0] 'http://127.0.0.1:8000/api/health'
    $started += Start-NorthServer 'frontend' $node 'node_modules/vite/bin/vite.js --host 127.0.0.1 --port 5173 --strictPort' $frontend
    ConvertTo-Json -InputObject $started | Set-Content -LiteralPath $statePath -Encoding UTF8
    Wait-NorthServer $started[1] 'http://127.0.0.1:5173/'
    Write-Host 'NORTH is running at http://127.0.0.1:5173/'
} catch {
    $failure = $_
    foreach ($server in $started) {
        try { Stop-NorthServer $server } catch { Write-Warning $_.Exception.Message }
    }
    Write-Host $failure.Exception.Message -ForegroundColor Red
    exit 1
} finally {
    $lock.Dispose()
}
