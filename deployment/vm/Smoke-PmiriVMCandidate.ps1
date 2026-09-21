#requires -Version 5.1

[CmdletBinding()]
param(
    [string]$PythonPath = 'C:\Program Files\Python312\python.exe',
    [string]$ProjectRoot = 'C:\PMIRI\source',
    [string]$ProfilePath = 'C:\PMIRI\profile.json',
    [string]$AdapterDir = 'C:\PMIRI\source\deployment\vm',
    [string]$AdapterConfigPath = 'C:\PMIRI\local-candidate-adapter-config.json',
    [string]$AdapterModule = 'local_candidate_adapters',
    [string]$AuditPath = 'C:\PMIRI\artifacts\read-audit.jsonl',
    [int]$Port = 8765,
    [int]$TimeoutSeconds = 20
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

foreach ($path in @($PythonPath, $ProfilePath, $AdapterConfigPath)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required smoke input is missing: $path"
    }
}
foreach ($path in @($ProjectRoot, $AdapterDir)) {
    if (-not (Test-Path -LiteralPath $path -PathType Container)) {
        throw "Required smoke directory is missing: $path"
    }
}
if ($Port -lt 1 -or $Port -gt 65535) {
    throw "Smoke port is invalid: $Port"
}
if ($TimeoutSeconds -lt 1) {
    throw "Smoke timeout must be positive: $TimeoutSeconds"
}

$logRoot = Join-Path $ProjectRoot '.pmiri-vm-smoke'
New-Item -ItemType Directory -Path $logRoot -Force | Out-Null
$stdoutPath = Join-Path $logRoot 'serve.stdout.log'
$stderrPath = Join-Path $logRoot 'serve.stderr.log'

$arguments = @(
    (Join-Path $ProjectRoot 'deployment\vm\serve_vm.py'),
    '--profile', $ProfilePath,
    '--adapter-module', $AdapterModule,
    '--adapter-dir', $AdapterDir,
    '--adapter-config', $AdapterConfigPath,
    '--port', [string]$Port
)
$serverProcess = Start-Process `
    -FilePath $PythonPath `
    -ArgumentList $arguments `
    -WorkingDirectory $ProjectRoot `
    -RedirectStandardOutput $stdoutPath `
    -RedirectStandardError $stderrPath `
    -WindowStyle Hidden `
    -PassThru

function Invoke-ExpectedUnauthenticatedRead {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri
    )

    $body = '{"request_id":"vm-smoke-unauth-1","project_constraint":"project","query":"release"}'
    Add-Type -AssemblyName System.Net.Http
    $client = New-Object System.Net.Http.HttpClient
    $client.Timeout = [TimeSpan]::FromSeconds(2)
    $content = New-Object System.Net.Http.StringContent($body, [Text.Encoding]::UTF8, 'application/json')
    $response = $null
    try {
        $response = $client.PostAsync($Uri, $content).GetAwaiter().GetResult()
        $responseText = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        $statusCode = [int]$response.StatusCode
        if ($statusCode -ne 401) {
            throw "Unauthenticated read returned unexpected HTTP ${statusCode}: $responseText"
        }
        $decoded = $responseText | ConvertFrom-Json
        $errorProperty = $decoded.PSObject.Properties['error']
        $codeProperty = if ($null -ne $errorProperty -and $null -ne $errorProperty.Value) {
            $errorProperty.Value.PSObject.Properties['code']
        } else {
            $null
        }
        if ($null -eq $codeProperty -or $codeProperty.Value -ne 'REQUEST_REJECTED') {
            throw "Unauthenticated read returned a non-generic error response: $responseText"
        }
        return $statusCode
    } finally {
        if ($null -ne $content) {
            $content.Dispose()
        }
        if ($null -ne $response) {
            $response.Dispose()
        }
        $client.Dispose()
    }
}

try {
    $health = $null
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        if ($serverProcess.HasExited) {
            $stdout = if (Test-Path -LiteralPath $stdoutPath) { Get-Content -LiteralPath $stdoutPath -Raw } else { '' }
            $stderr = if (Test-Path -LiteralPath $stderrPath) { Get-Content -LiteralPath $stderrPath -Raw } else { '' }
            throw "VM candidate server exited with code $($serverProcess.ExitCode). stdout=$stdout stderr=$stderr"
        }
        try {
            $health = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/healthz" -Method Get -TimeoutSec 2
            break
        } catch {
            Start-Sleep -Milliseconds 250
        }
    }
    if ($null -eq $health -or $health.status -ne 'OK' -or $health.transport -ne 'LOOPBACK_ONLY') {
        throw "VM candidate health check failed or timed out: $($TimeoutSeconds)s"
    }

    $unauthenticatedStatus = Invoke-ExpectedUnauthenticatedRead -Uri "http://127.0.0.1:$Port/v1/read/search"
    $metrics = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/metrics" -Method Get -TimeoutSec 2
    if ($null -eq $metrics -or $null -eq $metrics.status -or $metrics.status -ne 'OK') {
        throw 'VM candidate metrics check failed.'
    }
    if ($metrics.metrics.http_requests_total -ne 3 -or
        $metrics.metrics.http_requests_rejected_total -ne 1 -or
        $metrics.metrics.http_requests_emitted_total -ne 0 -or
        $metrics.metrics.audit_write_failures_total -ne 0) {
        throw "VM candidate auth/metrics boundary failed: $($metrics | ConvertTo-Json -Compress)"
    }
    if (-not (Test-Path -LiteralPath $AuditPath -PathType Leaf)) {
        throw "VM candidate audit file was not created: $AuditPath"
    }
    $auditLine = Get-Content -LiteralPath $AuditPath -Tail 1
    if ([string]::IsNullOrWhiteSpace($auditLine)) {
        throw "VM candidate audit file is empty: $AuditPath"
    }
    $auditEvent = $auditLine | ConvertFrom-Json
    if ($auditEvent.outcome -ne 'REJECTED' -or $auditEvent.status_code -ne 401) {
        throw "VM candidate audit rejection was not recorded correctly: $auditLine"
    }
    if ($auditLine -match 'vm-smoke-unauth-1') {
        throw 'VM candidate audit leaked the request identifier.'
    }

    [ordered]@{
        status = 'VM_LOCAL_HTTP_SMOKE_PASS'
        health = $health
        unauthenticated_read_status = $unauthenticatedStatus
        metrics = $metrics
        audit = 'REJECTED_401_REDACTED'
        audit_path = $AuditPath
        host = '127.0.0.1'
        port = $Port
        adapter_module = $AdapterModule
        teardown = 'PROCESS_STOPPED_IN_FINALLY'
        stdout_log = $stdoutPath
        stderr_log = $stderrPath
    } | ConvertTo-Json -Compress
} finally {
    if ($null -ne $serverProcess -and -not $serverProcess.HasExited) {
        Stop-Process -Id $serverProcess.Id -Force -ErrorAction SilentlyContinue
        $serverProcess.WaitForExit()
    }
}
