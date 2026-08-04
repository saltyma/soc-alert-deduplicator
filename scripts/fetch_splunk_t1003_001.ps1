[CmdletBinding()]
param(
    [string]$Destination = ''
)

$ErrorActionPreference = 'Stop'
$scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
if ([string]::IsNullOrWhiteSpace($Destination)) {
    $Destination = Join-Path $scriptDirectory '..\data\external\splunk_attack_data\T1003.001'
}
$commit = '671041b0405d5d766378a34a82bae59c5c672d9f'
$datasetBase = "https://media.githubusercontent.com/media/splunk/attack_data/$commit/datasets/attack_techniques/T1003.001/atomic_red_team"
$rawBase = "https://raw.githubusercontent.com/splunk/attack_data/$commit"
$destinationPath = [IO.Path]::GetFullPath($Destination)

$files = @(
    [PSCustomObject]@{
        RelativePath = 'raw\windows-sysmon.log'
        Uri = "$datasetBase/windows-sysmon.log"
        Sha256 = 'a1905850598f1e943708c3329190e29c6cb046389c1575cb2afd6369b5f269f1'
    }
    [PSCustomObject]@{
        RelativePath = 'raw\windows-sysmon_creddump.log'
        Uri = "$datasetBase/windows-sysmon_creddump.log"
        Sha256 = 'a37b69dce32eaff6b5c1fdb4bb9cbea6dec78a4fbd22cd41362ab0e377f075ef'
    }
    [PSCustomObject]@{
        RelativePath = 'raw\procdump_windows-security.log'
        Uri = "$datasetBase/procdump_windows-security.log"
        Sha256 = '86be8a91228678b0639f5cc192722b40acb81f06eb998bbc34916cf08f436abd'
    }
    [PSCustomObject]@{
        RelativePath = 'raw\crowdstrike_falcon.log'
        Uri = "$datasetBase/crowdstrike_falcon.log"
        Sha256 = '9eb639b8642f067f76ddb8b4ab66494deb9893eed528bcb02063802c2dbff140'
    }
    [PSCustomObject]@{
        RelativePath = 'raw\createdump_windows-sysmon.log'
        Uri = "$datasetBase/createdump_windows-sysmon.log"
        Sha256 = 'b898327b2b446ba63c13934d50c899eb4b2ee2c722a7c6c4a1dae6c515720001'
    }
    [PSCustomObject]@{
        RelativePath = 'atomic_red_team.yml'
        Uri = "$rawBase/datasets/attack_techniques/T1003.001/atomic_red_team/atomic_red_team.yml"
        Sha256 = 'fcb48abd1ac0cc2576092167cf1ec122fa120e3a2abfd29150801c9e3e4123d6'
    }
    [PSCustomObject]@{
        RelativePath = 'UPSTREAM_LICENSE'
        Uri = "$rawBase/LICENSE"
        Sha256 = '8505946b2464fa90223996d99eecbc7639a86648ca071f0cac21695be2623a0a'
    }
)

foreach ($file in $files) {
    $target = Join-Path $destinationPath $file.RelativePath
    $parent = Split-Path -Parent $target
    New-Item -ItemType Directory -Path $parent -Force | Out-Null

    if (Test-Path -LiteralPath $target) {
        $existingHash = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash
        if ($existingHash -ieq $file.Sha256) {
            Write-Host "Verified existing $($file.RelativePath)"
            continue
        }
        throw "Refusing to overwrite a checksum-mismatched file: $target"
    }

    $partial = "$target.download"
    if (Test-Path -LiteralPath $partial) {
        throw "Refusing to overwrite an incomplete download: $partial"
    }
    Write-Host "Downloading $($file.RelativePath)"
    Invoke-WebRequest -Uri $file.Uri -OutFile $partial
    $downloadHash = (Get-FileHash -LiteralPath $partial -Algorithm SHA256).Hash
    if ($downloadHash -ine $file.Sha256) {
        throw "Checksum mismatch for $($file.RelativePath); incomplete file kept at $partial"
    }
    Move-Item -LiteralPath $partial -Destination $target
}

Write-Host "Dataset ready at $destinationPath"
