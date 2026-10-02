#Requires -Version 7.4
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ExePath,
    [Parameter(Mandatory)][string]$NativeExePath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ExePath = (Resolve-Path -LiteralPath $ExePath).Path
$NativeExePath = (Resolve-Path -LiteralPath $NativeExePath).Path
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('RepaclsRegression_' + [guid]::NewGuid().ToString('N'))
New-Item -Path $testRoot -ItemType Directory | Out-Null
$script:checks = 0

function Assert-That([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
    $script:checks++
    Write-Host "PASS: $Message"
}

function Invoke-Repacls {
    param([Parameter(ValueFromRemainingArguments)][string[]]$Arguments)
    $start = [Diagnostics.ProcessStartInfo]::new($ExePath)
    $start.UseShellExecute = $false
    $start.WorkingDirectory = (Get-Location).Path
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    foreach ($argument in $Arguments) { $start.ArgumentList.Add($argument) }
    $process = [Diagnostics.Process]::Start($start)
    try {
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(60000)) {
            $process.Kill($true)
            throw 'Repacls exceeded the regression timeout.'
        }
        [PSCustomObject]@{
            ExitCode = $process.ExitCode
            Output = $stdout.GetAwaiter().GetResult() + $stderr.GetAwaiter().GetResult()
        }
    } finally {
        $process.Dispose()
    }
}

try {
    # Native tests use Windows ACL APIs and capture privileged storage boundaries.
    & $NativeExePath $testRoot
    Assert-That ($LASTEXITCODE -eq 0) 'Native ACL and descriptor regressions pass'

    $fixtures = Join-Path $testRoot 'fixtures'
    New-Item -Path $fixtures -ItemType Directory | Out-Null
    $textFile = Join-Path $fixtures 'a.txt'
    $logFile = Join-Path $fixtures 'b.log'
    $lines = @('alpha "quoted", value', 'alpha ""', 'alpha café, 日本語')
    [IO.File]::WriteAllLines($textFile, $lines, [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText($logFile, 'log')

    # Quoted text must round-trip through a real CSV reader.
    $textReport = Join-Path $testRoot 'text.csv'
    $result = Invoke-Repacls '/Path' $textFile '/LocateText' $textReport '.*:alpha' '/Threads' '1'
    Assert-That ($result.ExitCode -eq 0) 'LocateText succeeds'
    $rows = @(Import-Csv -LiteralPath $textReport)
    Assert-That ($rows.Count -eq $lines.Count) 'CSV retains every matched line'
    for ($index = 0; $index -lt $lines.Count; $index++) {
        Assert-That ($rows[$index].'Matched Line' -ceq $lines[$index] -and
            $rows[$index].'Line Number' -eq ($index + 1)) "CSV preserves line $($index + 1) exactly"
    }

    # Repeated commands share one report and initialize it only once.
    $sharedReport = Join-Path $testRoot 'shared.csv'
    [IO.File]::WriteAllText($sharedReport, 'stale report content')
    Push-Location $testRoot
    try {
        $result = Invoke-Repacls '/Path' $fixtures '/Locate' $sharedReport '.*\.txt' `
            '/Locate' '.\shared.csv' '.*\.log' '/Threads' '1'
    } finally {
        Pop-Location
    }
    $rows = @(Import-Csv -LiteralPath $sharedReport)
    Assert-That ($result.ExitCode -eq 0 -and $rows.Count -eq 2) 'Relative and absolute report paths share one output'
    Assert-That (@($rows | Where-Object { $_.Path -match '\\a\.txt$' }).Count -eq 1 -and
        @($rows | Where-Object { $_.Path -match '\\b\.log$' }).Count -eq 1) `
        'Shared reports retain both command results'

    # Different report schemas are rejected without truncating the first header.
    $result = Invoke-Repacls '/Path' $textFile '/Locate' $sharedReport '.*' `
        '/LocateText' $sharedReport '.*:alpha' '/Threads' '1'
    Assert-That ($result.ExitCode -ne 0 -and $result.Output -match 'mismatching') 'Incompatible report reuse fails'
    Assert-That ((Get-Content -LiteralPath $sharedReport -First 1) -match 'Creation Time') `
        'Rejected reuse preserves the first report'

    # Every digest must work together, including returning to an earlier algorithm.
    $hashReport = Join-Path $testRoot 'hashes.csv'
    $hashArguments = [Collections.Generic.List[string]]::new()
    $hashArguments.AddRange([string[]]@('/Path', $textFile, '/Threads', '1'))
    $expectedHashes = foreach ($algorithm in @('MD5', 'SHA1', 'SHA256', 'SHA384', 'SHA512', 'MD5')) {
        $hash = (Get-FileHash -LiteralPath $textFile -Algorithm $algorithm).Hash
        $hashArguments.AddRange([string[]]@('/LocateHash', $hashReport, ".*:$hash"))
        $hash
    }
    $result = Invoke-Repacls -Arguments ($hashArguments.ToArray())
    $rows = @(Import-Csv -LiteralPath $hashReport)
    Assert-That ($result.ExitCode -eq 0 -and $rows.Count -eq $expectedHashes.Count) `
        'Mixed hash algorithms complete in one scan'
    for ($index = 0; $index -lt $expectedHashes.Count; $index++) {
        Assert-That ($rows[$index].Hash -eq $expectedHashes[$index]) `
            "Hash result $($index + 1) matches Windows hashing"
    }

    # Filter protected child files and directories without hiding single-attribute files.
    $protectedFile = Join-Path $fixtures 'protected.txt'
    $protectedDirectory = Join-Path $fixtures 'protected-directory'
    $hiddenFile = Join-Path $fixtures 'hidden-only.txt'
    $systemFile = Join-Path $fixtures 'system-only.txt'
    New-Item -Path $protectedDirectory -ItemType Directory | Out-Null
    foreach ($path in @($protectedFile, (Join-Path $protectedDirectory 'inside.txt'), $hiddenFile, $systemFile)) {
        [IO.File]::WriteAllText($path, 'fixture')
    }
    $protectedAttributes = [IO.FileAttributes]::Hidden -bor [IO.FileAttributes]::System
    [IO.File]::SetAttributes($protectedFile, $protectedAttributes)
    [IO.File]::SetAttributes($protectedDirectory, $protectedAttributes -bor [IO.FileAttributes]::Directory)
    [IO.File]::SetAttributes($hiddenFile, [IO.FileAttributes]::Hidden)
    [IO.File]::SetAttributes($systemFile, [IO.FileAttributes]::System)
    $discoveryReport = Join-Path $testRoot 'discovery.csv'
    $result = Invoke-Repacls '/Path' $fixtures '/Locate' $discoveryReport '.*' '/Threads' '5'
    $allRows = @(Import-Csv -LiteralPath $discoveryReport)
    Assert-That ($result.ExitCode -eq 0 -and
        @($allRows | Where-Object { $_.Path -match 'protected|inside' }).Count -eq 3) `
        'Unfiltered scan includes protected descendants'
    $result = Invoke-Repacls '/Path' $fixtures '/Locate' $discoveryReport '.*' '/NoHiddenSystem' '/Threads' '5'
    $rows = @(Import-Csv -LiteralPath $discoveryReport)
    Assert-That ($result.ExitCode -eq 0 -and
        @($rows | Where-Object { $_.Path -match 'protected|inside' }).Count -eq 0) `
        'NoHiddenSystem excludes protected descendants'
    Assert-That (@($rows | Where-Object { $_.Path -match 'hidden-only|system-only' }).Count -eq 2) `
        'Single-attribute files remain eligible'
    $result = Invoke-Repacls '/Path' $protectedDirectory '/Locate' $discoveryReport '.*' `
        '/NoHiddenSystem' '/Threads' '1'
    Assert-That ($result.ExitCode -eq 0 -and @(Import-Csv -LiteralPath $discoveryReport).Count -eq 0) `
        'Protected scan roots remain excluded'

    # A real sharing violation must propagate to the process exit status even in quiet mode.
    $locked = [IO.File]::Open($textFile, 'Open', 'ReadWrite', 'None')
    try {
        $result = Invoke-Repacls '/Path' $textFile '/LocateText' $textReport '.*:alpha' '/Quiet' '/Threads' '1'
        Assert-That ($result.ExitCode -ne 0 -and $result.Output -match 'Unable to open file') `
            'Operation failures return a failing exit status'
    } finally {
        $locked.Dispose()
    }

    Write-Host "All $script:checks regression checks passed."
} finally {
    # Remove only the unique fixture directory created by this run.
    $resolvedRoot = [IO.Path]::GetFullPath($testRoot)
    $tempDirectory = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    if (-not $resolvedRoot.StartsWith($tempDirectory, [StringComparison]::OrdinalIgnoreCase) -or
        [IO.Path]::GetFileName($resolvedRoot) -notlike 'RepaclsRegression_*') {
        throw 'Regression cleanup path is outside its temporary directory.'
    }
    Remove-Item -LiteralPath $resolvedRoot -Recurse -Force
}
