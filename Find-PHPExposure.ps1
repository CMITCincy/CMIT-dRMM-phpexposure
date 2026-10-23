[CmdletBinding()]
param(
    [string[]]$ScanRoots,
    [string]$CsvPath,
    [string]$JsonPath,
    [switch]$EnableRuntimeVersionProbe,
    [switch]$NoFileSystemScan
)

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'

# Exit 0: no actionable finding. Exit 1: PHP installation requires review/remediation.
# Runtime probing is optional because executing an unknown binary during discovery adds risk.

$excludedDirectoryNames = @(
    '$Recycle.Bin','System Volume Information','WinSxS','SoftwareDistribution',
    'Windows.old','Recovery','MSOCache','Config.Msi'
)
$targetNames = @('php.exe','php-cgi.exe','php-win.exe')
$fixedBuilds = @{
    '8.2' = [version]'8.2.35'
    '8.3' = [version]'8.3.36'
    '8.4' = [version]'8.4.27'
    '8.5' = [version]'8.5.12'
}

function Get-NormalizedPath([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    try { return [IO.Path]::GetFullPath($Path).TrimEnd('\') } catch { return $Path.TrimEnd('\') }
}

function Find-PHPFiles {
    param([string[]]$Roots)
    $found = [Collections.Generic.Dictionary[string,IO.FileInfo]]::new([StringComparer]::OrdinalIgnoreCase)

    $quickPatterns = @(
        "$env:SystemDrive\PHP\php*.exe",
        "$env:SystemDrive\xampp\php\php*.exe",
        "$env:SystemDrive\wamp*\bin\php\*\php*.exe",
        "$env:SystemDrive\laragon\bin\php\*\php*.exe",
        "$env:ProgramFiles\PHP\php*.exe",
        "${env:ProgramFiles(x86)}\PHP\php*.exe"
    )
    foreach ($pattern in $quickPatterns) {
        Get-ChildItem -Path $pattern -File -Force | Where-Object Name -in $targetNames | ForEach-Object {
            $found[$_.FullName] = $_
        }
    }

    if (-not $NoFileSystemScan) {
        foreach ($root in $Roots) {
            if (-not (Test-Path -LiteralPath $root -PathType Container)) { continue }
            $stack = [Collections.Generic.Stack[string]]::new()
            $stack.Push((Get-NormalizedPath $root))
            while ($stack.Count -gt 0) {
                $dir = $stack.Pop()
                try {
                    foreach ($item in [IO.Directory]::EnumerateFileSystemEntries($dir)) {
                        try {
                            $attr = [IO.File]::GetAttributes($item)
                            if (($attr -band [IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
                            if (($attr -band [IO.FileAttributes]::Directory) -ne 0) {
                                $leaf = [IO.Path]::GetFileName($item)
                                if ($excludedDirectoryNames -notcontains $leaf) { $stack.Push($item) }
                            }
                            elseif ($targetNames -contains [IO.Path]::GetFileName($item)) {
                                $fi = Get-Item -LiteralPath $item -Force
                                if ($fi) { $found[$fi.FullName] = $fi }
                            }
                        } catch {}
                    }
                } catch {}
            }
        }
    }
    return $found.Values
}

function ConvertTo-Version([string]$Text) {
    if ($Text -match '(?<!\d)(\d+\.\d+\.\d+)(?:\.\d+)?') {
        try { return [version]$Matches[1] } catch {}
    }
    return $null
}

function Get-PHPVersionInfo([IO.FileInfo]$File) {
    $source = 'File metadata'
    $text = $File.VersionInfo.ProductVersion
    $ver = ConvertTo-Version $text
    if (-not $ver) {
        $text = $File.VersionInfo.FileVersion
        $ver = ConvertTo-Version $text
    }
    if ($EnableRuntimeVersionProbe -and $File.Name -eq 'php.exe') {
        try {
            $runtime = & $File.FullName -n -r 'echo PHP_VERSION;' 2>$null
            $runtimeVer = ConvertTo-Version ([string]$runtime)
            if ($runtimeVer) { $ver = $runtimeVer; $text = [string]$runtime; $source = 'Runtime probe (-n)' }
        } catch {}
    }
    [pscustomobject]@{ Version = $ver; VersionText = if ($ver) { $ver.ToString(3) } else { $text }; Source = $source }
}

function Get-PatchStatus([version]$Version) {
    if (-not $Version) { return 'UNKNOWN_VERSION' }
    $branch = '{0}.{1}' -f $Version.Major,$Version.Minor
    if ($fixedBuilds.ContainsKey($branch)) {
        if ($Version -ge $fixedBuilds[$branch]) { return 'PATCHED_FOR_PHP2SHELL' }
        return 'VULNERABLE_TO_PHP2SHELL'
    }
    if ($Version.Major -lt 8 -or ($Version.Major -eq 8 -and $Version.Minor -le 1)) {
        return 'UNSUPPORTED_OR_VENDOR_BACKPORT_REQUIRED'
    }
    return 'NEWER_OR_UNLISTED_BRANCH_REVIEW'
}

function Get-IniAssessment([string]$BinaryDirectory) {
    $iniCandidates = @(
        (Join-Path $BinaryDirectory 'php.ini'),
        (Join-Path $env:WINDIR 'php.ini')
    ) | Select-Object -Unique | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf }

    $assessments = foreach ($ini in $iniCandidates) {
        $content = Get-Content -LiteralPath $ini -Raw
        $upload = if ($content -match '(?im)^\s*session\.upload_progress\.enabled\s*=\s*(?<v>[^;\r\n]+)') { $Matches.v.Trim() } else { 'Default/Not explicitly set' }
        $serializer = if ($content -match '(?im)^\s*session\.serialize_handler\s*=\s*(?<v>[^;\r\n]+)') { $Matches.v.Trim() } else { 'Default/Not explicitly set' }
        [pscustomobject]@{ Path=$ini; UploadProgress=$upload; SerializeHandler=$serializer }
    }
    return @($assessments)
}

if (-not $ScanRoots -or $ScanRoots.Count -eq 0) {
    $ScanRoots = @(Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | ForEach-Object { "$($_.DeviceID)\" })
}

$processes = @(Get-CimInstance Win32_Process | Select-Object ProcessId,Name,ExecutablePath,CommandLine)
$services = @(Get-CimInstance Win32_Service | Select-Object Name,DisplayName,State,StartMode,PathName,ProcessId)
$webProcessNames = @('w3wp.exe','httpd.exe','apache.exe','apache2.exe','nginx.exe','php-cgi.exe')
$webProcesses = @($processes | Where-Object { $webProcessNames -contains $_.Name })

$listeners = @()
if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
    $listeners = @(Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort,OwningProcess)
}

$iisFastCgiText = $null
$appcmd = Join-Path $env:WINDIR 'System32\inetsrv\appcmd.exe'
if (Test-Path -LiteralPath $appcmd) {
    try { $iisFastCgiText = (& $appcmd list config /section:system.webServer/fastCgi 2>$null | Out-String) } catch {}
}

$files = @(Find-PHPFiles -Roots $ScanRoots | Sort-Object FullName -Unique)
$results = foreach ($file in $files) {
    $v = Get-PHPVersionInfo $file
    $status = Get-PatchStatus $v.Version
    $normalized = Get-NormalizedPath $file.FullName

    $procMatches = @($processes | Where-Object {
        (Get-NormalizedPath $_.ExecutablePath) -eq $normalized -or $_.CommandLine -like "*$($file.FullName)*"
    })
    $serviceMatches = @($services | Where-Object { $_.PathName -like "*$($file.FullName)*" })
    $iisMatch = [bool]($iisFastCgiText -and $iisFastCgiText -like "*$($file.FullName)*")

    $relatedWeb = @($webProcesses | Where-Object {
        $_.CommandLine -like "*$($file.DirectoryName)*" -or
        $_.ExecutablePath -like "$($file.DirectoryName)*"
    })
    $relatedPids = @($procMatches.ProcessId + $relatedWeb.ProcessId | Where-Object { $_ } | Select-Object -Unique)
    $ports = @($listeners | Where-Object { $relatedPids -contains $_.OwningProcess } | ForEach-Object { "$($_.LocalAddress):$($_.LocalPort)" } | Select-Object -Unique)
    $inis = @(Get-IniAssessment $file.DirectoryName)

    $webEvidence = @()
    if ($iisMatch) { $webEvidence += 'Referenced by IIS FastCGI configuration' }
    if ($procMatches) { $webEvidence += 'PHP binary is currently running' }
    if ($serviceMatches) { $webEvidence += 'Referenced by a Windows service' }
    if ($relatedWeb) { $webEvidence += 'Related web-server process detected' }
    if ($ports) { $webEvidence += ('Related listening endpoint(s): ' + ($ports -join ', ')) }

    $priority = if ($status -in @('VULNERABLE_TO_PHP2SHELL','UNSUPPORTED_OR_VENDOR_BACKPORT_REQUIRED') -and $webEvidence.Count) {
        'HIGH'
    } elseif ($status -eq 'PATCHED_FOR_PHP2SHELL' -and -not $webEvidence.Count) {
        'LOW'
    } else {
        'REVIEW'
    }

    [pscustomobject]@{
        ComputerName          = $env:COMPUTERNAME
        Path                  = $file.FullName
        FileName              = $file.Name
        Version               = $v.VersionText
        VersionSource         = $v.Source
        PHP2ShellStatus       = $status
        Priority              = $priority
        WebServingEvidence    = if ($webEvidence) { $webEvidence -join '; ' } else { 'None detected' }
        RunningProcessIds     = ($procMatches.ProcessId -join ',')
        RelatedServices       = ($serviceMatches.Name -join ',')
        RelatedWebProcesses   = (($relatedWeb | ForEach-Object { "$($_.Name):$($_.ProcessId)" }) -join ',')
        ListeningEndpoints    = ($ports -join ',')
        IISFastCgiReference   = $iisMatch
        PhpIniFiles           = (($inis.Path) -join ',')
        UploadProgressSetting = (($inis | ForEach-Object { "$($_.Path)=$($_.UploadProgress)" }) -join '; ')
        SerializeHandlers     = (($inis | ForEach-Object { "$($_.Path)=$($_.SerializeHandler)" }) -join '; ')
        LastWriteTime         = $file.LastWriteTime
        SHA256                = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
    }
}

Write-Output "PHP_DISCOVERY_SUMMARY Computer=$env:COMPUTERNAME Found=$($results.Count) High=$(@($results | Where-Object Priority -eq 'HIGH').Count) Review=$(@($results | Where-Object Priority -eq 'REVIEW').Count)"
if ($results.Count -eq 0) {
    Write-Output 'No PHP executable binaries were found in the scanned fixed drives.'
} else {
    $results | Sort-Object Priority,Path | Format-Table Priority,Version,PHP2ShellStatus,Path,WebServingEvidence -AutoSize | Out-String -Width 4096 | Write-Output
    Write-Output 'PHP_DISCOVERY_JSON_BEGIN'
    $results | ConvertTo-Json -Depth 5 -Compress | Write-Output
    Write-Output 'PHP_DISCOVERY_JSON_END'
}

if ($CsvPath) { $results | Export-Csv -LiteralPath $CsvPath -NoTypeInformation -Encoding UTF8 }
if ($JsonPath) { $results | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $JsonPath -Encoding UTF8 }

$actionable = @($results | Where-Object { $_.Priority -in @('HIGH','REVIEW') })
if ($actionable.Count -gt 0) { exit 1 }
exit 0
