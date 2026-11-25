# Copyright (c) 2026 Liam P. Ward. Licensed under the MIT License; see LICENSE in the repository root.
# SPDX-License-Identifier: MIT
#
# Builds the release package the same way locally and in CI, so the two can be compared.
# - Run it from a clean clone, on Windows, with .NET SDK 10.0.401 (the CI package job uses the same).
# - The clone is mapped to drive T: and built from T:\, because Razor writes the full path of each view into the
#   sources it generates, and those sources are embedded in the symbols. The same path gives the same bytes
#   and keeps local folder names out of the package.
# - Writes the .nupkg and .snupkg to <Out>, with SHA256SUMS (the files) and CONTENTSUMS (every file inside them;
#   the zip containers themselves carry build times, the files inside do not).
param([string] $Out = 'out', [string] $Drive = 'T:')
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if (Test-Path "$Drive\") { throw "$Drive is already in use; choose another drive with -Drive" }
subst $Drive $repo
# the release build uses exactly this SDK (global.json otherwise allows later 10.0 SDKs, which compile other bytes)
$globalJson = Join-Path $repo 'global.json'
$committedGlobalJson = [IO.File]::ReadAllBytes($globalJson)
try {
    [IO.File]::WriteAllText($globalJson, "{`n  `"sdk`": {`n    `"version`": `"10.0.401`",`n    `"rollForward`": `"disable`"`n  }`n}`n")
    Push-Location "$Drive\"
    $sdk = dotnet --version
    if ($LASTEXITCODE -or $sdk -ne '10.0.401') { throw "the release build needs .NET SDK 10.0.401 installed (found: $sdk)" }
    dotnet restore Tor.slnx --locked-mode
    if ($LASTEXITCODE) { throw 'restore failed' }
    dotnet build src/Tor/Tor.csproj --no-restore -c Release -p:ContinuousIntegrationBuild=true
    if ($LASTEXITCODE) { throw 'build failed' }
    $target = Join-Path "$Drive\" $Out
    dotnet pack src/Tor/Tor.csproj --no-build -c Release -p:ContinuousIntegrationBuild=true -o $target
    if ($LASTEXITCODE) { throw 'pack failed' }

    $packages = Get-ChildItem $target -File | Where-Object Extension -in '.nupkg', '.snupkg' | Sort-Object Name
    $packages | ForEach-Object { "$((Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant())  $($_.Name)" } |
        Set-Content (Join-Path $target 'SHA256SUMS') -Encoding ascii

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $sha = [Security.Cryptography.SHA256]::Create()
    $lines = foreach ($package in $packages) {
        $zip = [IO.Compression.ZipFile]::OpenRead($package.FullName)
        try {
            foreach ($entry in $zip.Entries | Sort-Object FullName) {
                # the package's core-properties part has a random name and id on every pack
                if ($entry.FullName -like 'package/services/metadata/core-properties/*' -or $entry.FullName -like '_rels/*') { continue }
                $stream = $entry.Open()
                try { $hash = [BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-', '').ToLowerInvariant() } finally { $stream.Dispose() }
                "$hash  $($package.Name)/$($entry.FullName)"
            }
        }
        finally { $zip.Dispose() }
    }
    $lines | Set-Content (Join-Path $target 'CONTENTSUMS') -Encoding ascii
    Get-Content (Join-Path $target 'SHA256SUMS')
    Get-Content (Join-Path $target 'CONTENTSUMS')
}
finally {
    Pop-Location
    subst $Drive /d
    [IO.File]::WriteAllBytes($globalJson, $committedGlobalJson)
}
