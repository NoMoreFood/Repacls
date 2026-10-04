#Requires -Version 7.4
#Requires -RunAsAdministrator
[CmdletBinding()]
param([Parameter(Mandatory)][string]$ExePath)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ExePath = (Resolve-Path -LiteralPath $ExePath).Path
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('RepaclsElevatedRegression_' + [guid]::NewGuid().ToString('N'))
New-Item -Path $testRoot -ItemType Directory | Out-Null
$createdShares = [Collections.Generic.List[string]]::new()
$sharePrefix = 'RepaclsEval' + [guid]::NewGuid().ToString('N')
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

function Read-Descriptor([string]$BackupPath) {
    $row = Get-Content -LiteralPath $BackupPath -First 1
    [Security.AccessControl.RawSecurityDescriptor]::new(($row -split '\|', 2)[1])
}

try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $everyone = [Security.Principal.SecurityIdentifier]::new('S-1-1-0')
    $sections = [Security.AccessControl.AccessControlSections]
    $information = [Security.AccessControl.AccessControlSections]::All

    # Give the fixtures known inherited permissions and an empty parent SACL.
    $rootAcl = Get-Acl -LiteralPath $testRoot -Audit
    $rootAcl.SetSecurityDescriptorSddlForm(
        'D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;' + $identity.User.Value + ')S:P',
        $sections::Access -bor $sections::Audit)
    Set-Acl -LiteralPath $testRoot -AclObject $rootAcl

    # Restore every combination of DACL and SACL protection on real files.
    foreach ($daclProtected in @($false, $true)) {
        foreach ($saclProtected in @($false, $true)) {
            $name = "protection-$daclProtected-$saclProtected"
            $file = Join-Path $testRoot "$name.txt"
            [IO.File]::WriteAllText($file, 'fixture')
            $acl = Get-Acl -LiteralPath $file -Audit
            $acl.SetAccessRuleProtection($daclProtected, $true)
            $acl.SetSecurityDescriptorSddlForm('S:P(AU;SA;0x1;;;WD)', $sections::Audit)
            $acl.SetAuditRuleProtection($saclProtected, $false)
            Set-Acl -LiteralPath $file -AclObject $acl
            $savedAcl = Get-Acl -LiteralPath $file -Audit
            $backup = Join-Path $testRoot "$name.backup"
            $result = Invoke-Repacls '/Path' $file '/BackupSecurity' $backup '/Threads' '1'
            Assert-That ($result.ExitCode -eq 0) "Save $name security"

            $acl = Get-Acl -LiteralPath $file -Audit
            $acl.SetAccessRuleProtection(-not $daclProtected, $true)
            $acl.SetSecurityDescriptorSddlForm('S:P(AU;FA;0x1;;;WD)', $sections::Audit)
            $acl.SetAuditRuleProtection(-not $saclProtected, $false)
            Set-Acl -LiteralPath $file -AclObject $acl
            $result = Invoke-Repacls '/Path' $file '/RestoreSecurity' $backup '/PrintDescriptor' '/Threads' '1'
            Assert-That ($result.ExitCode -eq 0) "Restore $name security"
            $restored = Get-Acl -LiteralPath $file -Audit
            Assert-That ($restored.AreAccessRulesProtected -eq $daclProtected -and
                $restored.AreAuditRulesProtected -eq $saclProtected) "Persist both $name protection flags"
            Assert-That ($restored.GetSecurityDescriptorSddlForm($information) -ceq
                $savedAcl.GetSecurityDescriptorSddlForm($information)) "Restore all $name descriptor parts"
            $printed = [Security.AccessControl.RawSecurityDescriptor]::new(
                [regex]::Match($result.Output, 'SD: ([^\r\n]+)').Groups[1].Value)
            $control = [Security.AccessControl.ControlFlags]
            Assert-That (
                [bool]($printed.ControlFlags -band $control::DiscretionaryAclProtected) -eq $daclProtected -and
                [bool]($printed.ControlFlags -band $control::SystemAclProtected) -eq $saclProtected) `
                "Print $name protection flags"
        }
    }

    # An inherited success audit must not suppress an explicit failure audit.
    $auditParent = Join-Path $testRoot 'audit-parent'
    New-Item -Path $auditParent -ItemType Directory | Out-Null
    $acl = Get-Acl -LiteralPath $auditParent -Audit
    $acl.SetSecurityDescriptorSddlForm('S:P(AU;OICISA;0x1;;;WD)', $sections::Audit)
    Set-Acl -LiteralPath $auditParent -AclObject $acl
    $auditFile = Join-Path $auditParent 'audit.txt'
    [IO.File]::WriteAllText($auditFile, 'fixture')
    $acl = Get-Acl -LiteralPath $auditFile -Audit
    $acl.AddAuditRule([Security.AccessControl.FileSystemAuditRule]::new($everyone, 'ReadData', 'Failure'))
    Set-Acl -LiteralPath $auditFile -AclObject $acl
    $before = Get-Acl -LiteralPath $auditFile -Audit
    $rules = @($before.GetAuditRules($true, $true, [Security.Principal.SecurityIdentifier]))
    Assert-That (@($rules | Where-Object { $_.IsInherited -and $_.AuditFlags -eq 'Success' }).Count -eq 1 -and
        @($rules | Where-Object { -not $_.IsInherited -and $_.AuditFlags -eq 'Failure' }).Count -eq 1) `
        'Fixture contains independent inherited and explicit audit outcomes'
    $result = Invoke-Repacls '/Path' $auditFile '/RemoveRedundant' '/Threads' '1'
    Assert-That ($result.ExitCode -eq 0) 'RemoveRedundant accepts the audit fixture'
    $after = Get-Acl -LiteralPath $auditFile -Audit
    Assert-That ($after.GetSecurityDescriptorSddlForm($sections::Audit) -ceq
        $before.GetSecurityDescriptorSddlForm($sections::Audit)) 'Persist both necessary audit outcomes'

    # Descriptor readers must include pending DACL, group, and SACL edits.
    $pipelineFile = Join-Path $testRoot 'pipeline.txt'
    [IO.File]::WriteAllText($pipelineFile, 'fixture')
    $acl = Get-Acl -LiteralPath $pipelineFile -Audit
    $acl.SetSecurityDescriptorSddlForm('S:P(AU;SA;0x1;;;WD)', $sections::Audit)
    Set-Acl -LiteralPath $pipelineFile -AclObject $acl
    $pipelineBackup = Join-Path $testRoot 'pipeline.backup'
    $result = Invoke-Repacls '/Path' $pipelineFile '/GrantPerms' 'S-1-1-0:(R)' `
        '/SetOwner' 'S-1-5-32-545:GROUP' '/ReplaceAccount' 'S-1-1-0:S-1-5-11:SACL' `
        '/PrintDescriptor' '/BackupSecurity' $pipelineBackup '/Threads' '1'
    Assert-That ($result.ExitCode -eq 0) 'Commit the descriptor pipeline'
    $saved = Read-Descriptor $pipelineBackup
    $printed = [Security.AccessControl.RawSecurityDescriptor]::new(
        [regex]::Match($result.Output, 'SD: ([^\r\n]+)').Groups[1].Value)
    Assert-That ($printed.GetSddlForm($information) -ceq $saved.GetSddlForm($information)) `
        'Print and backup observe the same pending edits'
    Assert-That ($saved.Group.Value -eq 'S-1-5-32-545' -and
        @($saved.DiscretionaryAcl | Where-Object { $_.SecurityIdentifier.Value -eq 'S-1-1-0' -and
            $_.AccessMask -eq 0x120089 }).Count -eq 1 -and
        @($saved.SystemAcl | Where-Object { $_.SecurityIdentifier.Value -eq 'S-1-5-11' }).Count -eq 1) `
        'Backup contains the grant, group replacement, and audit replacement'
    $actual = Get-Acl -LiteralPath $pipelineFile -Audit
    Assert-That ($actual.GetSecurityDescriptorSddlForm($information) -ceq $saved.GetSddlForm($information)) `
        'Persist the descriptor observed by backup'

    # A restore with absent ACLs must clear the old audit pointers.
    $objectName = ((Get-Content -LiteralPath $pipelineBackup -First 1) -split '\|', 2)[0]
    $absentBackup = Join-Path $testRoot 'absent.backup'
    [IO.File]::WriteAllText($absentBackup, "$objectName|O:$($saved.Owner.Value)G:$($saved.Group.Value)`n")
    $result = Invoke-Repacls '/Path' $pipelineFile '/RestoreSecurity' $absentBackup '/Threads' '1'
    Assert-That ($result.ExitCode -eq 0) 'Restore absent ACLs without retaining freed pointers'
    $actual = Get-Acl -LiteralPath $pipelineFile -Audit
    Assert-That (@($actual.GetAuditRules($true, $true, [Security.Principal.SecurityIdentifier])).Count -eq 0) `
        'Restore clears the old audit entries'

    # Real SMB aliases retain one path while nested shares are excluded.
    $data = Join-Path $testRoot 'data'
    $child = Join-Path $data 'child'
    $other = Join-Path $testRoot 'database'
    New-Item -Path $child, $other -ItemType Directory | Out-Null
    $sharePaths = [ordered]@{
        ($sharePrefix + 'A') = $data
        ($sharePrefix + 'B') = $data
        ($sharePrefix + 'Child') = $child
        ($sharePrefix + 'Other') = $other
    }
    foreach ($share in $sharePaths.GetEnumerator()) {
        New-SmbShare -Name $share.Key -Path $share.Value -FullAccess $identity.Name -Temporary | Out-Null
        $createdShares.Add($share.Key)
    }
    $shareReport = Join-Path $testRoot 'shares.csv'
    $options = '127.0.0.1:Match=^' + $sharePrefix + ',StopOnError'
    $result = Invoke-Repacls '/SharePaths' $options '/Locate' $shareReport '.*' '/MaxDepth' '0' '/Threads' '5'
    Assert-That ($result.ExitCode -eq 0) 'Enumerate and scan live SMB shares'
    $rows = @(Import-Csv -LiteralPath $shareReport)
    Assert-That ($rows.Count -eq 2 -and
        @($rows | Where-Object { $_.Path.EndsWith('\' + $sharePrefix + 'A') }).Count -eq 1 -and
        @($rows | Where-Object { $_.Path.EndsWith('\' + $sharePrefix + 'Other') }).Count -eq 1) `
        'Keep one SMB alias and the unrelated directory'
    $result = Invoke-Repacls '/SharePaths' ($options + ',NoDeDupe') '/Locate' $shareReport '.*' `
        '/MaxDepth' '0' '/Threads' '5'
    Assert-That ($result.ExitCode -eq 0 -and @(Import-Csv -LiteralPath $shareReport).Count -eq 4) `
        'NoDeDupe scans every live SMB alias'

    Write-Host "All $script:checks elevated regression checks passed."
} finally {
    foreach ($name in $createdShares) {
        if (-not $name.StartsWith($sharePrefix, [StringComparison]::Ordinal)) {
            throw 'Unexpected SMB cleanup target.'
        }
        Remove-SmbShare -Name $name -Force -Confirm:$false
    }
    $resolvedRoot = [IO.Path]::GetFullPath($testRoot)
    $tempParent = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    if (-not $resolvedRoot.StartsWith($tempParent, [StringComparison]::OrdinalIgnoreCase) -or
        [IO.Path]::GetFileName($resolvedRoot) -notmatch '^RepaclsElevatedRegression_[0-9a-f]{32}$') {
        throw 'Test cleanup path is outside its temporary directory.'
    }
    Remove-Item -LiteralPath $resolvedRoot -Recurse -Force
}
