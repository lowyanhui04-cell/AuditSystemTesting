param([string]$OutDir = (Join-Path $PSScriptRoot 'publish\portable'))

$ErrorActionPreference = 'Stop'
$project = Join-Path $PSScriptRoot 'src\EndpointLens.Server\EndpointLens.Server.csproj'

dotnet publish $project -c Release -r win-x64 --self-contained true `
    -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true `
    -p:EnableCompressionInSingleFile=true -p:DebugType=embedded -o $OutDir
if ($LASTEXITCODE -ne 0) { throw "EndpointLens publish failed." }
Write-Host "Copy this file to your USB drive: $(Join-Path $OutDir 'EndpointLens.exe')"
