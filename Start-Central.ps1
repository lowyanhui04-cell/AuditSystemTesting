$ErrorActionPreference = 'Stop'
$certDir = Join-Path $env:LOCALAPPDATA 'EndpointLens\certs'
New-Item -ItemType Directory -Force -Path $certDir | Out-Null
$certPath = Join-Path $certDir 'localhost.pfx'
$certPassword = [guid]::NewGuid().ToString('N')
dotnet dev-certs https --export-path $certPath --password $certPassword --trust
if ($LASTEXITCODE -ne 0) { throw 'HTTPS certificate export failed.' }

$adminPassword = Read-Host 'Set the audit-admin password for this server session (12 or more characters)' -AsSecureString
if ($adminPassword.Length -lt 12 -or $adminPassword.Length -gt 128) { throw 'Use 12 to 128 characters.' }

$env:AuditOperator__UserName = 'audit-admin'
$env:AuditOperator__Password = [System.Net.NetworkCredential]::new('', $adminPassword).Password
$env:Kestrel__Certificates__Default__Path = $certPath
$env:Kestrel__Certificates__Default__Password = $certPassword
$env:ASPNETCORE_URLS = 'https://localhost:5443'
$centralExe = Join-Path $PSScriptRoot 'EndpointLens.exe'
$previousSource = Join-Path $PSScriptRoot 'Source'
Push-Location $previousSource
try {
    & $centralExe --server
} finally {
    Pop-Location
    Remove-Item Env:AuditOperator__Password, Env:Kestrel__Certificates__Default__Password -ErrorAction SilentlyContinue
}
