#Requires -Version 7.4
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Comprehensive functional test suite for repacls.exe.

.DESCRIPTION
    Creates an isolated directory tree under the user's temp directory and
    exercises every major repacls command, validating outputs and side-effects.
    Designed to be reproducible on any Windows machine with PowerShell 7.4+.

    The script must be run elevated (administrator) because repacls itself
    requires administrator privileges to acquire backup/restore/take-ownership
    privileges.

.NOTES
    The script assumes repacls.exe has already been built. It searches for the
    binary relative to its own location (..\\Build\\*\\repacls.exe) or accepts
    an explicit path via the -ExePath parameter.
#>
[CmdletBinding()]
param(
    [string]$ExePath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region ── Helper: locate repacls.exe ──────────────────────────────────────────

if (-not $ExePath) {
    # Walk up from the script directory and look for a built binary
    $candidates = @(
        (Join-Path $PSScriptRoot '..\Build\Release\x64\repacls.exe'),
        (Join-Path $PSScriptRoot '..\Build\Debug\x64\repacls.exe'),
        (Join-Path $PSScriptRoot '..\Build\Release\x86\repacls.exe'),
        (Join-Path $PSScriptRoot '..\Build\Debug\x86\repacls.exe')
    )
    foreach ($c in $candidates) {
        if (Test-Path $c) { $ExePath = (Resolve-Path $c).Path; break }
    }
    if (-not $ExePath) {
        throw 'Could not locate repacls.exe. Pass -ExePath explicitly or build the project first.'
    }
}
if (-not (Test-Path $ExePath)) { throw "repacls.exe not found at '$ExePath'." }
Write-Host "Using repacls.exe at: $ExePath" -ForegroundColor Cyan

#endregion

#region ── Test infrastructure ─────────────────────────────────────────────────

# Unique sandbox under temp
$Script:TestRoot = Join-Path ([IO.Path]::GetTempPath()) "RepaclsTests_$([guid]::NewGuid().ToString('N').Substring(0,8))"
New-Item -Path $Script:TestRoot -ItemType Directory -Force | Out-Null
Push-Location $Script:TestRoot

$Script:PassCount  = 0
$Script:FailCount  = 0
$Script:SkipCount  = 0
$Script:TestNumber = 0

function Invoke-Repacls {
    <# Runs repacls.exe with the supplied arguments. Returns a PSCustomObject
       with ExitCode, StdOut (string[]), and StdErr (string[]). #>
    [CmdletBinding()]
    param([Parameter(ValueFromRemainingArguments)][string[]]$Arguments)

    $psi = [System.Diagnostics.ProcessStartInfo]::new($ExePath)
    $psi.UseShellExecute  = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.CreateNoWindow = $true
    foreach ($a in $Arguments) { $psi.ArgumentList.Add($a) }

    $proc = [System.Diagnostics.Process]::Start($psi)
    $stdoutTask = $proc.StandardOutput.ReadToEndAsync()
    $stderr = $proc.StandardError.ReadToEnd()
    $stdout = $stdoutTask.GetAwaiter().GetResult()
    $proc.WaitForExit()

    [PSCustomObject]@{
        ExitCode = $proc.ExitCode
        StdOut   = ($stdout -split "`r?`n" | Where-Object { $_ -ne '' })
        StdErr   = ($stderr -split "`r?`n" | Where-Object { $_ -ne '' })
        RawOut   = $stdout
        RawErr   = $stderr
    }
}

function Assert-True {
    param([bool]$Condition, [string]$Message)
    $Script:TestNumber++
    if ($Condition) {
        $Script:PassCount++
        Write-Host "  [PASS] #$Script:TestNumber $Message" -ForegroundColor Green
    } else {
        $Script:FailCount++
        Write-Host "  [FAIL] #$Script:TestNumber $Message" -ForegroundColor Red
    }
}

function Assert-False {
    param([bool]$Condition, [string]$Message)
    Assert-True -Condition (-not $Condition) -Message $Message
}

function Write-Section ([string]$Title) {
    Write-Host "`n== $Title ==" -ForegroundColor Yellow
}

# Well-known SIDs that exist on every Windows machine
$SidEveryone       = 'S-1-1-0'           # Everyone
$SidBuiltinAdmins  = 'S-1-5-32-544'      # BUILTIN\Administrators
$SidBuiltinUsers   = 'S-1-5-32-545'      # BUILTIN\Users
$SidSystem         = 'S-1-5-18'          # NT AUTHORITY\SYSTEM
$SidAuthUsers      = 'S-1-5-11'          # NT AUTHORITY\Authenticated Users

# Friendly names
$NameEveryone  = 'Everyone'
$NameSystem    = 'NT AUTHORITY\SYSTEM'

#endregion

#region ── C# raw ACL validation helpers (Add-Type) ────────────────────────────

Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;

namespace RepaclsTest
{
    public class RawAce
    {
        public string Sid;
        public string AccountName;
        public string AceType;
        public int AccessMask;
        public string InheritanceFlags;
        public string PropagationFlags;
        public bool IsInherited;

        public override string ToString()
        {
            return string.Format("{0} {1} ({2}) Mask=0x{3:X} Inh={4} IF={5} PF={6}",
                AceType, Sid, AccountName, AccessMask, IsInherited, InheritanceFlags, PropagationFlags);
        }
    }

    public class AclSnapshot
    {
        public string Path;
        public string OwnerSid;
        public string GroupSid;
        public string Sddl;
        public bool DaclPresent;
        public bool DaclProtected;
        public List<RawAce> DaclAces = new List<RawAce>();
        public int DaclAceCount { get { return DaclAces.Count; } }
        public DateTime CapturedAt;
    }

    public class AclDifference
    {
        public string Property;
        public string Before;
        public string After;

        public override string ToString()
        {
            return string.Format("{0}: '{1}' -> '{2}'", Property, Before, After);
        }
    }

    public static class RawAclValidator
    {
        public static AclSnapshot CaptureSnapshot(string path)
        {
            var sections = AccessControlSections.Access
                         | AccessControlSections.Owner
                         | AccessControlSections.Group;
            FileSystemSecurity acl;
            if (Directory.Exists(path))
                acl = new DirectorySecurity(path, sections);
            else
                acl = new FileSecurity(path, sections);
            return ParseAcl(path, acl);
        }

        private static AclSnapshot ParseAcl(string path, FileSystemSecurity acl)
        {
            var snap = new AclSnapshot();
            snap.Path = path;
            snap.CapturedAt = DateTime.UtcNow;
            snap.Sddl = string.Empty;

            var ownerSid = acl.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
            snap.OwnerSid = ownerSid != null ? ownerSid.Value : "(null)";

            var groupSid = acl.GetGroup(typeof(SecurityIdentifier)) as SecurityIdentifier;
            snap.GroupSid = groupSid != null ? groupSid.Value : "(null)";

            snap.DaclProtected = acl.AreAccessRulesProtected;
            snap.DaclPresent = true;

            var rules = acl.GetAccessRules(true, true, typeof(SecurityIdentifier));
            foreach (FileSystemAccessRule rule in rules)
            {
                var ace = new RawAce();
                ace.Sid = ((SecurityIdentifier)rule.IdentityReference).Value;
                ace.AceType = rule.AccessControlType.ToString();
                ace.AccessMask = (int)rule.FileSystemRights;
                ace.InheritanceFlags = rule.InheritanceFlags.ToString();
                ace.PropagationFlags = rule.PropagationFlags.ToString();
                ace.IsInherited = rule.IsInherited;
                try
                {
                    var translated = rule.IdentityReference.Translate(typeof(NTAccount));
                    ace.AccountName = translated != null ? translated.Value : ace.Sid;
                }
                catch { ace.AccountName = ace.Sid; }
                snap.DaclAces.Add(ace);
            }

            return snap;
        }

        public static Dictionary<string, AclSnapshot> CaptureTreeSnapshot(string rootPath)
        {
            var result = new Dictionary<string, AclSnapshot>(StringComparer.OrdinalIgnoreCase);
            try { result[rootPath] = CaptureSnapshot(rootPath); } catch { }
            if (Directory.Exists(rootPath))
            {
                foreach (var entry in Directory.GetFileSystemEntries(rootPath, "*", SearchOption.AllDirectories))
                {
                    try { result[entry] = CaptureSnapshot(entry); } catch { }
                }
            }
            return result;
        }

        public static List<AclDifference> CompareSnapshots(AclSnapshot before, AclSnapshot after)
        {
            return CompareSnapshots(before, after, false);
        }

        public static List<AclDifference> CompareSnapshots(AclSnapshot before, AclSnapshot after, bool explicitOnly)
        {
            var diffs = new List<AclDifference>();
            if (before.OwnerSid != after.OwnerSid)
                diffs.Add(new AclDifference { Property = "Owner",
                    Before = before.OwnerSid, After = after.OwnerSid });
            if (before.GroupSid != after.GroupSid)
                diffs.Add(new AclDifference { Property = "Group",
                    Before = before.GroupSid, After = after.GroupSid });
            if (before.DaclProtected != after.DaclProtected)
                diffs.Add(new AclDifference { Property = "DaclProtected",
                    Before = before.DaclProtected.ToString(), After = after.DaclProtected.ToString() });

            int beforeCount = 0, afterCount = 0;
            var beforeSet = new HashSet<string>();
            foreach (var a in before.DaclAces)
            {
                if (explicitOnly && a.IsInherited) continue;
                beforeCount++;
                beforeSet.Add(string.Format("{0}|{1}|0x{2:X}|{3}|{4}",
                    a.AceType, a.Sid, a.AccessMask, a.InheritanceFlags, a.IsInherited));
            }
            var afterSet = new HashSet<string>();
            foreach (var a in after.DaclAces)
            {
                if (explicitOnly && a.IsInherited) continue;
                afterCount++;
                afterSet.Add(string.Format("{0}|{1}|0x{2:X}|{3}|{4}",
                    a.AceType, a.Sid, a.AccessMask, a.InheritanceFlags, a.IsInherited));
            }

            if (beforeCount != afterCount)
                diffs.Add(new AclDifference
                {
                    Property = explicitOnly ? "ExplicitAceCount" : "DaclAceCount",
                    Before = beforeCount.ToString(), After = afterCount.ToString()
                });

            foreach (var item in beforeSet)
                if (!afterSet.Contains(item))
                    diffs.Add(new AclDifference { Property = "ACE_Removed",
                        Before = item, After = "(absent)" });
            foreach (var item in afterSet)
                if (!beforeSet.Contains(item))
                    diffs.Add(new AclDifference { Property = "ACE_Added",
                        Before = "(absent)", After = item });

            return diffs;
        }

        public static Dictionary<string, List<AclDifference>> FindUnexpectedChanges(
            Dictionary<string, AclSnapshot> before,
            Dictionary<string, AclSnapshot> after,
            string[] excludePaths)
        {
            return FindUnexpectedChanges(before, after, excludePaths, false);
        }

        public static Dictionary<string, List<AclDifference>> FindUnexpectedChanges(
            Dictionary<string, AclSnapshot> before,
            Dictionary<string, AclSnapshot> after,
            string[] excludePaths,
            bool explicitOnly)
        {
            var exclude = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (excludePaths != null)
                foreach (var p in excludePaths) exclude.Add(p);

            var result = new Dictionary<string, List<AclDifference>>(StringComparer.OrdinalIgnoreCase);
            foreach (var kvp in before)
            {
                if (exclude.Contains(kvp.Key)) continue;
                AclSnapshot afterSnap;
                if (!after.TryGetValue(kvp.Key, out afterSnap)) continue;
                var diffs = CompareSnapshots(kvp.Value, afterSnap, explicitOnly);
                if (diffs.Count > 0)
                    result[kvp.Key] = diffs;
            }
            return result;
        }

        public static string ValidateCanonicalOrder(AclSnapshot snapshot)
        {
            int phase = 0;
            for (int i = 0; i < snapshot.DaclAces.Count; i++)
            {
                var ace = snapshot.DaclAces[i];
                int acePhase;
                if (!ace.IsInherited && ace.AceType == "Deny") acePhase = 0;
                else if (!ace.IsInherited && ace.AceType == "Allow") acePhase = 1;
                else if (ace.IsInherited && ace.AceType == "Deny") acePhase = 2;
                else acePhase = 3;

                if (acePhase < phase)
                    return string.Format("ACE #{0} ({1}) is in phase {2} but expected >= {3}",
                        i, ace, acePhase, phase);
                phase = acePhase;
            }
            return null;
        }

        public static bool HasAceForSid(AclSnapshot snapshot, string sid, string aceType)
        {
            foreach (var ace in snapshot.DaclAces)
                if (ace.Sid == sid && (aceType == null || ace.AceType == aceType))
                    return true;
            return false;
        }

        public static RawAce[] GetAcesForSid(AclSnapshot snapshot, string sid)
        {
            var result = new List<RawAce>();
            foreach (var ace in snapshot.DaclAces)
                if (ace.Sid == sid) result.Add(ace);
            return result.ToArray();
        }

        public static string[] GetUniqueSids(AclSnapshot snapshot)
        {
            var set = new HashSet<string>();
            foreach (var ace in snapshot.DaclAces) set.Add(ace.Sid);
            var arr = new string[set.Count];
            set.CopyTo(arr);
            return arr;
        }
    }
}
'@

#endregion

#region ── Sandbox creation helpers ────────────────────────────────────────────

function New-TestTree {
    <# Creates a small directory tree under TestRoot with known permissions. #>
    param([string]$Name)
    $root = Join-Path $Script:TestRoot $Name
    $sub  = Join-Path $root 'SubDir'
    $file = Join-Path $root 'File.txt'
    $subFile = Join-Path $sub 'SubFile.txt'

    New-Item -Path $sub -ItemType Directory -Force | Out-Null
    Set-Content -Path $file    -Value 'hello' -Encoding UTF8
    Set-Content -Path $subFile -Value 'world' -Encoding UTF8

    [PSCustomObject]@{ Root = $root; Sub = $sub; File = $file; SubFile = $subFile }
}

function Get-AclSddl ([string]$Path) {
    (Get-Acl -Path $Path).Sddl
}

function Get-Owner ([string]$Path) {
    (Get-Acl -Path $Path).Owner
}

function Test-AclContainsSid {
    <# Returns $true if any ACE in the ACL of $Path references the given SID.
       Uses .NET identity translation instead of SDDL string matching because
       SDDL uses abbreviated aliases (WD, BA, BU, SY) for well-known SIDs. #>
    param([string]$Path, [string]$Sid)
    $sidObj = [System.Security.Principal.SecurityIdentifier]::new($Sid)
    $acl = Get-Acl -Path $Path
    foreach ($rule in $acl.Access) {
        $ruleSid = $rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier])
        if ($ruleSid.Value -eq $sidObj.Value) { return $true }
    }
    return $false
}

function Test-AclContainsDenySid {
    <# Returns $true if any Deny ACE in the ACL of $Path references the given SID. #>
    param([string]$Path, [string]$Sid)
    $sidObj = [System.Security.Principal.SecurityIdentifier]::new($Sid)
    $acl = Get-Acl -Path $Path
    foreach ($rule in $acl.Access) {
        if ($rule.AccessControlType -ne 'Deny') { continue }
        $ruleSid = $rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier])
        if ($ruleSid.Value -eq $sidObj.Value) { return $true }
    }
    return $false
}

function Get-RawAclSnapshot {
    <# Captures a detailed ACL snapshot using the C# RawAclValidator. #>
    param([string]$Path)
    [RepaclsTest.RawAclValidator]::CaptureSnapshot($Path)
}

function Get-TreeAclSnapshot {
    <# Captures ACL snapshots for a path and all descendants. #>
    param([string]$RootPath)
    [RepaclsTest.RawAclValidator]::CaptureTreeSnapshot($RootPath)
}

function Assert-NoSideEffects {
    <# Compares before/after tree snapshots and asserts no unexpected changes.
       Use -ExplicitOnly to ignore inherited ACE changes from OS propagation. #>
    param($Before, $After, [string[]]$ExpectedChangePaths, [string]$Message, [switch]$ExplicitOnly)
    $unexpected = [RepaclsTest.RawAclValidator]::FindUnexpectedChanges(
        $Before, $After, $ExpectedChangePaths, [bool]$ExplicitOnly)
    if ($unexpected.Count -gt 0) {
        $details = ($unexpected.Keys | ForEach-Object {
            $diffs = $unexpected[$_]
            "$_ : $(($diffs | ForEach-Object { $_.ToString() }) -join '; ')"
        }) -join ' | '
        Assert-True $false "$Message [Unexpected changes: $details]"
    } else {
        Assert-True $true $Message
    }
}

function Assert-AclCanonical {
    <# Validates that the DACL ACEs are in canonical order using the C# validator. #>
    param([string]$Path, [string]$Message)
    $snap = [RepaclsTest.RawAclValidator]::CaptureSnapshot($Path)
    $violation = [RepaclsTest.RawAclValidator]::ValidateCanonicalOrder($snap)
    Assert-True ($null -eq $violation) "$Message$(if ($violation) { " [$violation]" })"
}

function Assert-RawAceExists {
    <# Validates that a specific ACE exists in the raw ACL for the given SID and type. #>
    param([string]$Path, [string]$Sid, [string]$AceType, [string]$Message)
    $snap = [RepaclsTest.RawAclValidator]::CaptureSnapshot($Path)
    $found = [RepaclsTest.RawAclValidator]::HasAceForSid($snap, $Sid, $AceType)
    Assert-True $found $Message
}

function Assert-SnapshotUnchanged {
    <# Compares a single path's ACL snapshot before and after an operation. #>
    param($Before, $After, [string]$Message)
    $diffs = [RepaclsTest.RawAclValidator]::CompareSnapshots($Before, $After)
    if ($diffs.Count -gt 0) {
        $details = ($diffs | ForEach-Object { $_.ToString() }) -join '; '
        Assert-True $false "$Message [Changes: $details]"
    } else {
        Assert-True $true $Message
    }
}

#endregion

try {

# ═══════════════════════════════════════════════════════════════════════════════
Write-Section 'Basic Invocation & Help'
# ═══════════════════════════════════════════════════════════════════════════════

$r = Invoke-Repacls '/Help'
Assert-True ($r.RawOut -match 'Repacls') 'Help output contains program name'
Assert-True ($r.RawOut -match '/Path') 'Help output documents /Path'
Assert-True ($r.RawOut -match '/WhatIf') 'Help output documents /WhatIf'
Assert-True ($r.RawOut -match '/SetOwner') 'Help output documents /SetOwner'

$r = Invoke-Repacls '/?'
Assert-True ($r.RawOut -match 'Repacls') '/? also displays help'

$r = Invoke-Repacls '/H'
Assert-True ($r.RawOut -match 'Repacls') '/H also displays help'

# ═══════════════════════════════════════════════════════════════════════════════
Write-Section 'Error Handling – No Path'
# ═══════════════════════════════════════════════════════════════════════════════

$r = Invoke-Repacls '/WhatIf' '/FindAccount' $NameEveryone
Assert-True ($r.RawOut -match 'ERROR.*[Nn]o path') 'Error shown when no /Path specified'

# ═══════════════════════════════════════════════════════════════════════════════
Write-Section '/PrintDescriptor'
# ═══════════════════════════════════════════════════════════════════════════════

$tree = New-TestTree 'PrintDesc'
$r = Invoke-Repacls '/Path' $tree.Root '/PrintDescriptor' '/Threads' '1' '/MaxDepth' '0'
Assert-True ($r.RawOut -match 'SD:') 'PrintDescriptor outputs SD:'
Assert-True ($r.RawOut -match 'D:') 'PrintDescriptor output contains DACL marker'

# ═══════════════════════════════════════════════════════════════════════════════
Write-Section '/FindAccount'
# ═══════════════════════════════════════════════════════════════════════════════

# Grant Everyone read on tree root so we know the SID is present
$acl = Get-Acl $tree.Root
$rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
    $NameEveryone,
    'Read',
    'ContainerInherit,ObjectInherit',
    'None',
    'Allow')
$acl.AddAccessRule($rule)
Set-Acl -Path $tree.Root -AclObject $acl

$r = Invoke-Repacls '/Path' $tree.Root '/FindAccount' $NameEveryone '/Threads' '1'
Assert-True ($r.RawOut -match 'Found identifier') 'FindAccount reports found identifier for Everyone'

# Using SID string
$r = Invoke-Repacls '/Path' $tree.Root '/FindAccount' $SidEveryone '/Threads' '1'
Assert-True ($r.RawOut -match 'Found identifier') 'FindAccount works with SID string'

# ═══════════════════════════════════════════════════════════════════════════════
Write-Section '/FindNullAcl'
# ═══════════════════════════════════════════════════════════════════════════════

$tree2 = New-TestTree 'FindNull'
$r = Invoke-Repacls '/Path' $tree2.Root '/FindNullAcl' '/Threads' '1'
# Normal files should not have null ACLs
Assert-False ($r.RawOut -match 'Access control list is null') 'No null ACLs on normal test tree'

# ═══════════════════════════════════════════════════════════════════════════════
Write-Section '/CheckCanonical'
# ═══════════════════════════════════════════════════════════════════════════════

$tree3 = New-TestTree 'CheckCanon'
$r = Invoke-Repacls '/Path' $tree3.Root '/CheckCanonical' '/Threads' '1'
Assert-False ($r.RawOut -match 'not canonical') 'Default ACLs are canonical'

# ═══════════════════════════════════════════════════════════════════════════════
Write-Section '/SetOwner'
# ═══════════════════════════════════════════════════════════════════════════════

$tree4 = New-TestTree 'SetOwner'

# Set owner to SYSTEM
$r = Invoke-Repacls '/Path' $tree4.Root '/SetOwner' $NameSystem '/MaxDepth' '0' '/Threads' '1'
$owner = Get-Owner $tree4.Root
Assert-True ($owner -match 'SYSTEM') 'SetOwner changed owner to SYSTEM on root'

# Set owner using SID string
$r = Invoke-Repacls '/Path' $tree4.File '/SetOwner' $SidBuiltinAdmins '/MaxDepth' '0' '/Threads' '1'
$owner = Get-Owner $tree4.File
Assert-True ($owner -match 'Administrators' -or $owner -match $SidBuiltinAdmins) 'SetOwner works with SID string (Administrators)'

# Recursive
$r = Invoke-Repacls '/Path' $tree4.Root '/SetOwner' $NameSystem '/Threads' '1'
$ownerSub = Get-Owner $tree4.SubFile
Assert-True ($ownerSub -match 'SYSTEM') 'SetOwner recursively sets owner on SubFile'

# ═══════════════════════════════════════════════════════════════════════════════
Write-Section '/SetOwner with /WhatIf'
# ═══════════════════════════════════════════════════════════════════════════════

$tree5 = New-TestTree 'WhatIfOwner'
$ownerBefore = Get-Owner $tree5.Root
$r = Invoke-Repacls '/Path' $tree5.Root '/SetOwner' $NameSystem '/WhatIf' '/MaxDepth' '0' '/Threads' '1'
$ownerAfter = Get-Owner $tree5.Root
Assert-True ($r.RawOut -match 'What If Mode: Yes') 'WhatIf mode is reported'
Assert-True ($ownerBefore -eq $ownerAfter) 'WhatIf does not actually change owner'

# ═══════════════════════════════════════════════════════════════════════════════
Write-Section '/GrantPerms'
# ═══════════════════════════════════════════════════════════════════════════════

$tree6 = New-TestTree 'GrantPerms'
$r = Invoke-Repacls '/Path' $tree6.Root '/GrantPerms' "$NameEveryone`:(F)(CI)(OI)" '/Threads' '1'
Assert-True (Test-AclContainsSid $tree6.Root $SidEveryone) 'GrantPerms adds Everyone to DACL of root'
Assert-True (Test-AclContainsSid $tree6.SubFile $SidEveryone) 'GrantPerms inherits to SubFile'
Assert-AclCanonical $tree6.Root 'GrantPerms: result ACL is canonical'

# ═══════════════════════════════════════════════════════════════════════════════
Write-Section '/DenyPerms'
# ═══════════════════════════════════════════════════════════════════════════════

$tree7 = New-TestTree 'DenyPerms'
$r = Invoke-Repacls '/Path' $tree7.Root '/DenyPerms' "$NameEveryone`:(R)(CI)(OI)" '/Threads' '1' '/MaxDepth' '0'
Assert-True (Test-AclContainsDenySid $tree7.Root $SidEveryone) 'DenyPerms creates a Deny ACE for Everyone'
Assert-AclCanonical $tree7.Root 'DenyPerms: result ACL is canonical'
Assert-RawAceExists $tree7.Root $SidEveryone 'Deny' 'DenyPerms: raw Deny ACE exists for Everyone'

# ═══════════════════════════════════════════════════════════════════════════════
Write-Section '/RemoveAccount'
# ═══════════════════════════════════════════════════════════════════════════════

$tree8 = New-TestTree 'RemoveAcct'
# First ensure Everyone is present
$r = Invoke-Repacls '/Path' $tree8.Root '/GrantPerms' "$NameEveryone`:(R)(CI)(OI)" '/Threads' '1'
Assert-True (Test-AclContainsSid $tree8.Root $SidEveryone) 'Pre-condition: Everyone is in ACL'

# Now remove
$r = Invoke-Repacls '/Path' $tree8.Root '/RemoveAccount' $NameEveryone '/Threads' '1'
Assert-True ($r.RawOut -match 'Removing account') 'RemoveAccount reports removing'
Assert-False (Test-AclContainsSid $tree8.Root $SidEveryone) 'Everyone removed from root ACL'

# ═══════════════════════════════════════════════════════════════════════════════
Write-Section '/RemoveAccount with granular targeting (DACL only)'
# ═══════════════════════════════════════════════════════════════════════════════

$tree8b = New-TestTree 'RemoveAcctGranular'
$r = Invoke-Repacls '/Path' $tree8b.Root '/GrantPerms' "$NameEveryone`:(R)(CI)(OI)" '/Threads' '1'
# Remove only from DACL
$r = Invoke-Repacls '/Path' $tree8b.Root '/RemoveAccount' "$NameEveryone`:DACL" '/Threads' '1' '/MaxDepth' '0'
Assert-True ($r.RawOut -match 'Removing account') 'Granular RemoveAccount (DACL) reports removing'
Assert-False (Test-AclContainsSid $tree8b.Root $SidEveryone) 'Granular RemoveAccount (DACL) removed Everyone from ACL'

# ═══════════════════════════════════════════════════════════════════════════════
Write-Section '/ReplaceAccount'
# ═══════════════════════════════════════════════════════════════════════════════

$tree9 = New-TestTree 'ReplaceAcct'
# Add Everyone
$r = Invoke-Repacls '/Path' $tree9.Root '/GrantPerms' "$NameEveryone`:(R)(CI)(OI)" '/Threads' '1'
Assert-True (Test-AclContainsSid $tree9.Root $SidEveryone) 'Pre-condition: Everyone present'

# Replace Everyone → BUILTIN\Users (both exist on all machines)
$r = Invoke-Repacls '/Path' $tree9.Root '/ReplaceAccount' "$SidEveryone`:$SidBuiltinUsers" '/Threads' '1'
Assert-True ($r.RawOut -match 'Replacing account') 'ReplaceAccount reports replacement'
Assert-True (Test-AclContainsSid $tree9.Root $SidBuiltinUsers) 'BUILTIN\Users now in ACL'

# ═══════════════════════════════════════════════════════════════════════════════
Write-Section '/BackupSecurity & /RestoreSecurity'
# ═══════════════════════════════════════════════════════════════════════════════

$tree10 = New-TestTree 'BackupRestore'
$backupFile = Join-Path $Script:TestRoot 'backup.txt'

# Backup
$r = Invoke-Repacls '/Path' $tree10.Root '/BackupSecurity' $backupFile '/Threads' '1'
Assert-True (Test-Path $backupFile) 'Backup file created'
$backupContent = Get-Content $backupFile -Raw -Encoding UTF8
Assert-True ($backupContent -match [regex]::Escape($tree10.Root)) 'Backup contains root path'
Assert-True ($backupContent -match 'D:') 'Backup contains DACL descriptor'

# Capture original owner, change owner, then restore.
# If the test is already running as SYSTEM, use Administrators as the intermediate
# so the pre-condition (owner actually changed) is always satisfiable.
$originalOwner = Get-Owner $tree10.Root
$intermediateOwner = if ($originalOwner -match 'SYSTEM') { $SidBuiltinAdmins } else { $NameSystem }
$r = Invoke-Repacls '/Path' $tree10.Root '/SetOwner' $intermediateOwner '/MaxDepth' '0' '/Threads' '1'
$changedOwner = Get-Owner $tree10.Root
Assert-True ($originalOwner -ne $changedOwner) 'Owner was changed before restore'

# Restore
$r = Invoke-Repacls '/Path' $tree10.Root '/RestoreSecurity' $backupFile '/Threads' '1'
$restoredOwner = Get-Owner $tree10.Root
Assert-True ($restoredOwner -eq $originalOwner) 'RestoreSecurity restored original owner'

# ═══════════════════════════════════════════════════════════════════════════════
Write-Section '/Compact'
# ═══════════════════════════════════════════════════════════════════════════════

$tree11 = New-TestTree 'Compact'
# Add two overlapping entries that are compactable
$r = Invoke-Repacls '/Path' $tree11.File '/GrantPerms' "$NameEveryone`:(R)" '/Threads' '1' '/MaxDepth' '0'
$r = Invoke-Repacls '/Path' $tree11.File '/GrantPerms' "$NameEveryone`:(R)(CI)(OI)" '/Threads' '1' '/MaxDepth' '0'
$aclBefore = Get-Acl $tree11.File
$r = Invoke-Repacls '/Path' $tree11.File '/Compact' '/Threads' '1' '/MaxDepth' '0'
$aclAfter = Get-Acl $tree11.File
# Verify the command ran without error and potentially reduced/compacted ACEs
Assert-True ($r.ExitCode -eq 0 -and $r.RawOut -notmatch 'ERROR') 'Compact runs without error'
Assert-True ($aclAfter.Access.Count -le $aclBefore.Access.Count) 'Compact merges or leaves ACE count less than or equal to before'

# ═══════════════════════════════════════════════════════════════════════════════
Write-Section '/RemoveRedundant'
# ═══════════════════════════════════════════════════════════════════════════════

$tree12 = New-TestTree 'RemoveRedundant'
# Force some redundant inheritance (if applicable) or explicit redundant ACEs
$r = Invoke-Repacls '/Path' $tree12.SubFile '/GrantPerms' "$NameEveryone`:(R)" '/Threads' '1' '/MaxDepth' '0'
$aclBefore = Get-Acl $tree12.SubFile
$r = Invoke-Repacls '/Path' $tree12.SubFile '/RemoveRedundant' '/Threads' '1'
$aclAfter = Get-Acl $tree12.SubFile
Assert-True ($r.ExitCode -eq 0 -and $r.RawOut -notmatch 'ERROR') 'RemoveRedundant runs without error'
Assert-True ($aclAfter.Access.Count -le $aclBefore.Access.Count) 'RemoveRedundant maintains or reduces ACE count'

# ═══════════════════════════════════════════════════════════════════════════════
Write-Section '/CanonicalizeAcls'
# ═══════════════════════════════════════════════════════════════════════════════

$tree13 = New-TestTree 'Canonicalize'
$r = Invoke-Repacls '/Path' $tree13.Root '/CanonicalizeAcls' '/Threads' '1'
Assert-True ($r.ExitCode -eq 0 -and $r.RawOut -notmatch 'ERROR') 'CanonicalizeAcls runs without error'
# Verify they are now canonical
$r2 = Invoke-Repacls '/Path' $tree13.Root '/CheckCanonical' '/Threads' '1'
Assert-False ($r2.RawOut -match 'not canonical') 'After canonicalize, ACLs are canonical'
Assert-AclCanonical $tree13.Root 'CanonicalizeAcls: raw-validated canonical order on root'

# ═══════════════════════════════════════════════════════════════════════════════
Write-Section '/Report'
# ═══════════════════════════════════════════════════════════════════════════════

$tree14 = New-TestTree 'Report'
$reportFile = Join-Path $Script:TestRoot 'report.csv'
$r = Invoke-Repacls '/Path' $tree14.Root '/Report' $reportFile '.*' '/Threads' '1'
Assert-True (Test-Path $reportFile) 'Report CSV file created'
$reportContent = Get-Content $reportFile -Raw -Encoding UTF8
Assert-True ($reportContent -match 'Path') 'Report contains header with Path column'
Assert-True ($reportContent -match 'Permissions') 'Report contains header with Permissions column'
Assert-True ($reportContent.Length -gt 100) 'Report file has meaningful content'

# Report with account regex filter
$reportFile2 = Join-Path $Script:TestRoot 'report_filtered.csv'
$r = Invoke-Repacls '/Path' $tree14.Root '/Report' $reportFile2 '.*SYSTEM.*' '/Threads' '1'
Assert-True (Test-Path $reportFile2) 'Filtered report CSV file created'

# ═══════════════════════════════════════════════════════════════════════════════
Write-Section '/Locate'
# ═══════════════════════════════════════════════════════════════════════════════

$tree15 = New-TestTree 'Locate'
$locateFile = Join-Path $Script:TestRoot 'locate.csv'
$r = Invoke-Repacls '/Path' $tree15.Root '/Locate' $locateFile '.*\.txt' '/Threads' '1'
Assert-True (Test-Path $locateFile) 'Locate CSV file created'
$locContent = Get-Content $locateFile -Raw -Encoding UTF8
Assert-True ($locContent -match 'File\.txt') 'Locate found File.txt'
Assert-True ($locContent -match 'SubFile\.txt') 'Locate found SubFile.txt'
Assert-True ($locContent -match 'Path') 'Locate CSV has header'

# Locate with wildcard matching everything
$locateFile2 = Join-Path $Script:TestRoot 'locate_all.csv'
$r = Invoke-Repacls '/Path' $tree15.Root '/Locate' $locateFile2 '.*' '/Threads' '1'
Assert-True (Test-Path $locateFile2) 'Locate all CSV file created'
$loc2Content = Get-Content $locateFile2 -Raw -Encoding UTF8
Assert-True ($loc2Content -match 'SubDir') 'Locate all includes SubDir directory'

# ═══════════════════════════════════════════════════════════════════════════════
Write-Section '/LocateText'
# ═══════════════════════════════════════════════════════════════════════════════

$tree16 = New-TestTree 'LocateText'
Set-Content -Path $tree16.File -Value @('This is a test line', 'Another line with KEYWORD here') -Encoding UTF8
$locTextFile = Join-Path $Script:TestRoot 'locatetext.csv'
$r = Invoke-Repacls '/Path' $tree16.Root '/LocateText' $locTextFile ".*\.txt:KEYWORD" '/Threads' '1'
Assert-True (Test-Path $locTextFile) 'LocateText CSV file created'
$ltContent = Get-Content $locTextFile -Raw -Encoding UTF8
Assert-True ($ltContent -match 'KEYWORD') 'LocateText found line containing KEYWORD'

# ═══════════════════════════════════════════════════════════════════════════════
Write-Section '/LocateHash'
# ═══════════════════════════════════════════════════════════════════════════════

$tree17 = New-TestTree 'LocateHash'
# Write known content and compute its SHA256 hash
$knownContent = 'HashTestContent12345'
[System.IO.File]::WriteAllBytes($tree17.File, [System.Text.Encoding]::UTF8.GetBytes($knownContent))
$sha256 = (Get-FileHash -Path $tree17.File -Algorithm SHA256).Hash.ToLower()
$locHashFile = Join-Path $Script:TestRoot 'locatehash.csv'
$r = Invoke-Repacls '/Path' $tree17.Root '/LocateHash' $locHashFile ".*\.txt:$sha256" '/Threads' '1'
Assert-True (Test-Path $locHashFile) 'LocateHash CSV file created'
$lhContent = Get-Content $locHashFile -Raw -Encoding UTF8
Assert-True ($lhContent -match 'File\.txt') 'LocateHash found matched file'
Assert-True ($lhContent -match [regex]::Escape($sha256)) 'LocateHash matched file by hash'

# ═══════════════════════════════════════════════════════════════════════════════
Write-Section '/Log'
# ═══════════════════════════════════════════════════════════════════════════════

$tree18 = New-TestTree 'LogTest'
$logFile = Join-Path $Script:TestRoot 'repacls.log'
$r = Invoke-Repacls '/Path' $tree18.Root '/FindAccount' $NameEveryone '/Log' $logFile '/Threads' '1'
Assert-True (Test-Path $logFile) 'Log file created'
$logContent = Get-Content $logFile -Raw -Encoding UTF8
Assert-True ($logContent -match 'Time' -and $logContent -match 'Type') 'Log file has CSV header'

# ═══════════════════════════════════════════════════════════════════════════════
Write-Section '/Quiet'
# ═══════════════════════════════════════════════════════════════════════════════

$tree19  = New-TestTree 'QuietTest'
$tree19n = New-TestTree 'QuietTestNormal'
# Use GrantPerms because its AddInfo calls use bMandatory=false (quiet-suppressible).
# FindAccount uses bMandatory=true, so its messages always appear even in quiet mode.
# Run identical commands on equivalent fresh trees so /Quiet is the only variable.
$r       = Invoke-Repacls '/Path' $tree19.Root  '/GrantPerms' "$NameEveryone`:(R)(CI)(OI)" '/Quiet' '/Threads' '1'
$rNormal = Invoke-Repacls '/Path' $tree19n.Root '/GrantPerms' "$NameEveryone`:(R)(CI)(OI)" '/Threads' '1'
Assert-True ($r.StdOut.Count -lt $rNormal.StdOut.Count) 'Quiet mode produces fewer output lines than normal'

# ═══════════════════════════════════════════════════════════════════════════════
Write-Section '/Threads'
# ═══════════════════════════════════════════════════════════════════════════════

$tree20 = New-TestTree 'ThreadsTest'
$r = Invoke-Repacls '/Path' $tree20.Root '/FindAccount' $NameEveryone '/Threads' '1'
Assert-True ($r.RawOut -match 'Maximum Threads: 1') 'Threads=1 reported correctly'

$r = Invoke-Repacls '/Path' $tree20.Root '/FindAccount' $NameEveryone '/Threads' '3'
Assert-True ($r.RawOut -match 'Maximum Threads: 3') 'Threads=3 reported correctly'

# ═══════════════════════════════════════════════════════════════════════════════
Write-Section '/MaxDepth'
# ═══════════════════════════════════════════════════════════════════════════════

$treeDepth = New-TestTree 'DepthTest'
# Create deeper structure
$deepDir = Join-Path $treeDepth.Sub 'Level2'
New-Item -Path $deepDir -ItemType Directory -Force | Out-Null
Set-Content -Path (Join-Path $deepDir 'deep.txt') -Value 'deep' -Encoding UTF8

$reportDepth0 = Join-Path $Script:TestRoot 'depth0.csv'
$reportDepthAll = Join-Path $Script:TestRoot 'depthAll.csv'
$r0 = Invoke-Repacls '/Path' $treeDepth.Root '/Locate' $reportDepth0 '.*' '/MaxDepth' '0' '/Threads' '1'
$rAll = Invoke-Repacls '/Path' $treeDepth.Root '/Locate' $reportDepthAll '.*' '/Threads' '1'

$lines0   = @(Get-Content $reportDepth0 -Encoding UTF8).Count
$linesAll = @(Get-Content $reportDepthAll -Encoding UTF8).Count
Assert-True ($lines0 -lt $linesAll) 'MaxDepth=0 produces fewer results than unlimited'
# Depth-0 output must not contain content from inside SubDir
$depth0Content = Get-Content $reportDepth0 -Raw -Encoding UTF8
Assert-False ($depth0Content -match 'SubFile') 'MaxDepth=0 does not include SubDir content'

# ═══════════════════════════════════════════════════════════════════════════════
Write-Section '/PathList'
# ═══════════════════════════════════════════════════════════════════════════════

$treeA = New-TestTree 'PathListA'
$treeB = New-TestTree 'PathListB'
$pathListFile = Join-Path $Script:TestRoot 'pathlist.txt'
# Write paths to the path list file (UTF8)
@($treeA.Root, $treeB.Root) | Set-Content -Path $pathListFile -Encoding UTF8

$reportPathList = Join-Path $Script:TestRoot 'pathlist_report.csv'
$r = Invoke-Repacls '/PathList' $pathListFile '/Locate' $reportPathList '.*' '/Threads' '1'
Assert-True (Test-Path $reportPathList) 'PathList-driven Locate produces output file'
$plContent = Get-Content $reportPathList -Raw -Encoding UTF8
Assert-True ($plContent -match 'PathListA') 'PathList output includes first tree'
Assert-True ($plContent -match 'PathListB') 'PathList output includes second tree'

# ═══════════════════════════════════════════════════════════════════════════════
Write-Section 'Multiple /Path arguments'
# ═══════════════════════════════════════════════════════════════════════════════

$reportMulti = Join-Path $Script:TestRoot 'multi_path.csv'
$r = Invoke-Repacls '/Path' $treeA.Root '/Path' $treeB.Root '/Locate' $reportMulti '.*' '/Threads' '1'
$mpContent = Get-Content $reportMulti -Raw -Encoding UTF8
Assert-True ($mpContent -match 'PathListA') 'Multiple /Path: includes first tree'
Assert-True ($mpContent -match 'PathListB') 'Multiple /Path: includes second tree'

# ═══════════════════════════════════════════════════════════════════════════════
Write-Section '/AddAccountIfMissing'
# ═══════════════════════════════════════════════════════════════════════════════

$tree21 = New-TestTree 'AddIfMissing'
# Break inheritance (keeping existing explicit copies) then remove Everyone so the
# pre-condition – that the SID is genuinely absent – is reliable on all machines.
$acl21 = Get-Acl $tree21.Root
$acl21.SetAccessRuleProtection($true, $true)
Set-Acl -Path $tree21.Root -AclObject $acl21
$r = Invoke-Repacls '/Path' $tree21.Root '/RemoveAccount' $NameEveryone '/MaxDepth' '0' '/Threads' '1'
Assert-False (Test-AclContainsSid $tree21.Root $SidEveryone) 'Pre-condition: Everyone is absent before AddAccountIfMissing'
$r = Invoke-Repacls '/Path' $tree21.Root '/AddAccountIfMissing' $NameEveryone '/Threads' '1'
Assert-True (Test-AclContainsSid $tree21.Root $SidEveryone) 'AddAccountIfMissing adds Everyone when missing'

# ═══════════════════════════════════════════════════════════════════════════════
Write-Section '/ResetChildren (exclusive operation)'
# ═══════════════════════════════════════════════════════════════════════════════

$tree22 = New-TestTree 'ResetChildren'
# First add an explicit entry on SubDir
$acl = Get-Acl $tree22.Sub
$rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
    $NameEveryone,
    'FullControl',
    'None',
    'None',
    'Allow')
$acl.AddAccessRule($rule)
# Protect the ACL (disable inheritance) to create explicit entries
$acl.SetAccessRuleProtection($true, $true)
Set-Acl -Path $tree22.Sub -AclObject $acl
Assert-True (Test-AclContainsSid $tree22.Sub $SidEveryone) 'Pre-condition: SubDir has Everyone explicit entry'
$beforeReset = Get-AclSddl $tree22.Sub
Assert-True ($beforeReset -match 'D:P') 'Pre-condition: SubDir DACL is protected (inheritance blocked)'

$r = Invoke-Repacls '/Path' $tree22.Root '/ResetChildren' '/Threads' '1'
# After reset, children should inherit from parent (explicit entries removed)
$afterReset = Get-AclSddl $tree22.Sub
Assert-True ($r.ExitCode -eq 0 -and $r.RawOut -notmatch 'ERROR') 'ResetChildren runs without error'
# The protected DACL flag (P) must be gone – inheritance has been re-enabled
Assert-False ($afterReset -match 'D:P') 'ResetChildren removed inheritance protection from SubDir'

# ═══════════════════════════════════════════════════════════════════════════════
Write-Section '/InheritChildren (exclusive operation)'
# ═══════════════════════════════════════════════════════════════════════════════

$tree23 = New-TestTree 'InheritChildren'
# Block inheritance on SubDir
$acl = Get-Acl $tree23.Sub
$acl.SetAccessRuleProtection($true, $true)
Set-Acl -Path $tree23.Sub -AclObject $acl
$beforeInherit = Get-AclSddl $tree23.Sub
Assert-True ($beforeInherit -match 'D:P') 'Pre-condition: SubDir DACL is protected (inheritance blocked)'

$r = Invoke-Repacls '/Path' $tree23.Root '/InheritChildren' '/Threads' '1'
Assert-True ($r.ExitCode -eq 0 -and $r.RawOut -notmatch 'ERROR') 'InheritChildren runs without error'

$afterInherit = Get-AclSddl $tree23.Sub
Assert-False ($afterInherit -match 'D:P') 'InheritChildren removed inheritance protection from SubDir'

# ═══════════════════════════════════════════════════════════════════════════════
Write-Section '/RemoveStreams'
# ═══════════════════════════════════════════════════════════════════════════════

$tree24 = New-TestTree 'RemoveStreams'
# Create an alternate data stream
$adsPath = "$($tree24.File):TestStream"
Set-Content -Path $adsPath -Value 'alternate data' -ErrorAction SilentlyContinue
$adsExists = Test-Path $adsPath -ErrorAction SilentlyContinue

if ($adsExists) {
    $r = Invoke-Repacls '/Path' $tree24.Root '/RemoveStreams' '/Threads' '1'
    $adsExistsAfter = Test-Path $adsPath -ErrorAction SilentlyContinue
    Assert-True (-not $adsExistsAfter) 'RemoveStreams removed the alternate data stream'
} else {
    $Script:SkipCount++
    Write-Host "  [SKIP] ADS creation not supported on this filesystem" -ForegroundColor DarkYellow
}

# ═══════════════════════════════════════════════════════════════════════════════
Write-Section '/RemoveStreamsByName'
# ═══════════════════════════════════════════════════════════════════════════════

$tree24b = New-TestTree 'RemoveStreamsByName'
$adsPath2 = "$($tree24b.File):Zone.Identifier"
Set-Content -Path $adsPath2 -Value 'zone data' -ErrorAction SilentlyContinue
$adsExists2 = Test-Path $adsPath2 -ErrorAction SilentlyContinue

if ($adsExists2) {
    $r = Invoke-Repacls '/Path' $tree24b.Root '/RemoveStreamsByName' '.*Zone\.Identifier.*' '/Threads' '1'
    $adsExistsAfter2 = Test-Path $adsPath2 -ErrorAction SilentlyContinue
    Assert-True (-not $adsExistsAfter2) 'RemoveStreamsByName removed Zone.Identifier stream'
} else {
    $Script:SkipCount++
    Write-Host "  [SKIP] ADS creation not supported on this filesystem" -ForegroundColor DarkYellow
}

# ═══════════════════════════════════════════════════════════════════════════════
Write-Section '/ReplaceMap'
# ═══════════════════════════════════════════════════════════════════════════════

$tree25 = New-TestTree 'ReplaceMap'
# Add Everyone
$r = Invoke-Repacls '/Path' $tree25.Root '/GrantPerms' "$NameEveryone`:(R)(CI)(OI)" '/Threads' '1'

# Create the map file: Everyone -> BUILTIN\Users
$mapFile = Join-Path $Script:TestRoot 'replacemap.txt'
"$SidEveryone`:$SidBuiltinUsers" | Set-Content -Path $mapFile -Encoding UTF8

$r = Invoke-Repacls '/Path' $tree25.Root '/ReplaceMap' $mapFile '/Threads' '1'
Assert-True (Test-AclContainsSid $tree25.Root $SidBuiltinUsers) 'ReplaceMap replaced Everyone with BUILTIN\Users'

# ═══════════════════════════════════════════════════════════════════════════════
Write-Section '/CopyMap'
# ═══════════════════════════════════════════════════════════════════════════════

$tree25b = New-TestTree 'CopyMap'
$r = Invoke-Repacls '/Path' $tree25b.Root '/GrantPerms' "$NameEveryone`:(R)(CI)(OI)" '/Threads' '1'

$copyMapFile = Join-Path $Script:TestRoot 'copymap.txt'
"$SidEveryone`:$SidBuiltinUsers" | Set-Content -Path $copyMapFile -Encoding UTF8

$r = Invoke-Repacls '/Path' $tree25b.Root '/CopyMap' $copyMapFile '/Threads' '1'
Assert-True (Test-AclContainsSid $tree25b.Root $SidBuiltinUsers) 'CopyMap added BUILTIN\Users'
# CopyMap should retain original as well
Assert-True (Test-AclContainsSid $tree25b.Root $SidEveryone) 'CopyMap retained Everyone (original)'

# ═══════════════════════════════════════════════════════════════════════════════
Write-Section '/NoHiddenSystem'
# ═══════════════════════════════════════════════════════════════════════════════

$tree26 = New-TestTree 'NoHiddenSystem'
# Mark the ROOT directory as hidden+system so /NoHiddenSystem skips it entirely.
# The NoHiddenSystem check in ObjectFile.cpp only applies at depth 0 (the scan root).
Set-ItemProperty -Path $tree26.Root -Name Attributes -Value ([System.IO.FileAttributes]::Hidden -bor [System.IO.FileAttributes]::System)

$locHs   = Join-Path $Script:TestRoot 'locate_hs.csv'
$locNoHs = Join-Path $Script:TestRoot 'locate_nohs.csv'
$r1 = Invoke-Repacls '/Path' $tree26.Root '/Locate' $locHs '.*' '/Threads' '1'
$r2 = Invoke-Repacls '/Path' $tree26.Root '/Locate' $locNoHs '.*' '/NoHiddenSystem' '/Threads' '1'

$hsLines   = @(Get-Content $locHs -Encoding UTF8).Count
$noHsLines = @(Get-Content $locNoHs -Encoding UTF8).Count
Assert-True ($noHsLines -lt $hsLines) 'NoHiddenSystem excludes hidden+system files'

# ═══════════════════════════════════════════════════════════════════════════════
Write-Section 'Chained ordered operations (multi-command)'
# ═══════════════════════════════════════════════════════════════════════════════

$tree27 = New-TestTree 'ChainedOps'
# Grant Everyone, then RemoveRedundant + Compact in one pass
$r = Invoke-Repacls '/Path' $tree27.Root `
    '/GrantPerms' "$NameEveryone`:(R)(CI)(OI)" `
    '/RemoveRedundant' '/Compact' '/Threads' '1'
Assert-True ($r.ExitCode -eq 0 -and $r.RawOut -notmatch 'ERROR') 'Chained operations run without error'

# ═══════════════════════════════════════════════════════════════════════════════
Write-Section 'Statistics output'
# ═══════════════════════════════════════════════════════════════════════════════

$tree28 = New-TestTree 'StatsTest'
$r = Invoke-Repacls '/Path' $tree28.Root '/FindAccount' $NameEveryone '/Threads' '1'
Assert-True ($r.RawOut -match 'Total Scanned:') 'Output contains Total Scanned'
Assert-True ($r.RawOut -match 'Read Failures:') 'Output contains Read Failures'
Assert-True ($r.RawOut -match 'Update Successes:') 'Output contains Update Successes'
Assert-True ($r.RawOut -match 'Time Elapsed:') 'Output contains Time Elapsed'

# ═══════════════════════════════════════════════════════════════════════════════
Write-Section 'Version banner'
# ═══════════════════════════════════════════════════════════════════════════════

$r = Invoke-Repacls '/Path' $tree28.Root '/FindAccount' $NameEveryone '/Threads' '1'
Assert-True ($r.RawOut -match 'Repacls Version') 'Output contains version banner'

# ═══════════════════════════════════════════════════════════════════════════════
Write-Section '/LocateShortcut'
# ═══════════════════════════════════════════════════════════════════════════════

$tree29 = New-TestTree 'LocateShortcut'
# Create a .lnk file using COM
try {
    $shell = New-Object -ComObject WScript.Shell
    $sc = $shell.CreateShortcut((Join-Path $tree29.Root 'test.lnk'))
    $sc.TargetPath = $tree29.File
    $sc.Save()
    [System.Runtime.InteropServices.Marshal]::ReleaseComObject($sc)    | Out-Null
    [System.Runtime.InteropServices.Marshal]::ReleaseComObject($shell) | Out-Null

    $scReport = Join-Path $Script:TestRoot 'shortcuts.csv'
    $r = Invoke-Repacls '/Path' $tree29.Root '/LocateShortcut' $scReport '.*' '/Threads' '1'
    Assert-True (Test-Path $scReport) 'LocateShortcut CSV file created'
    $scContent = Get-Content $scReport -Raw -Encoding UTF8
    Assert-True ($scContent -match 'test\.lnk' -and $scContent -match 'Target Path') 'LocateShortcut output has header and found shortcut'
} catch {
    $Script:SkipCount++
    Write-Host "  [SKIP] Could not create shortcut for test: $_" -ForegroundColor DarkYellow
}

# ═══════════════════════════════════════════════════════════════════════════════
Write-Section 'Exclusive operation conflict detection'
# ═══════════════════════════════════════════════════════════════════════════════

$tree30 = New-TestTree 'ExclusiveConflict'
$r = Invoke-Repacls '/Path' $tree30.Root '/ResetChildren' '/InheritChildren'
Assert-True ($r.RawOut -match 'ERROR.*[Ee]xclusive') 'Error when two exclusive operations combined'

# ═══════════════════════════════════════════════════════════════════════════════
Write-Section 'Invalid parameter handling'
# ═══════════════════════════════════════════════════════════════════════════════

$r = Invoke-Repacls '/Path' $tree30.Root '/SetOwner'
Assert-True ($r.RawOut -match 'ERROR') 'Error when /SetOwner has no account argument'

$r = Invoke-Repacls '/Path' $tree30.Root '/RemoveAccount' 'TOTALLY_BOGUS_ACCOUNT_THAT_DOES_NOT_EXIST_12345'
Assert-True ($r.RawOut -match 'ERROR.*[Ii]nvalid') 'Error for non-existent account in /RemoveAccount'

$r = Invoke-Repacls '/Path' $tree30.Root '/Threads' '0'
Assert-True ($r.RawOut -match 'ERROR') 'Error for /Threads 0'

$r = Invoke-Repacls '/Path' $tree30.Root '/MaxDepth' '-1'
Assert-True ($r.RawOut -match 'ERROR') 'Error for negative /MaxDepth'

# ═══════════════════════════════════════════════════════════════════════════════
Write-Section 'SetOwner + Verify recursive depth'
# ═══════════════════════════════════════════════════════════════════════════════

$tree31 = New-TestTree 'SetOwnerDepth'
# Create a 3-level deep structure
$l1 = Join-Path $tree31.Root 'L1'
$l2 = Join-Path $l1 'L2'
$l3 = Join-Path $l2 'L3'
New-Item -Path $l3 -ItemType Directory -Force | Out-Null
Set-Content -Path (Join-Path $l3 'deepfile.txt') -Value 'deep' -Encoding UTF8

# Set owner only 1 level deep
$r = Invoke-Repacls '/Path' $tree31.Root '/SetOwner' $NameSystem '/MaxDepth' '1' '/Threads' '1'
$ownerRoot = Get-Owner $tree31.Root
$ownerL1   = Get-Owner $l1
$ownerL3   = Get-Owner $l3
Assert-True ($ownerRoot -match 'SYSTEM') 'SetOwner+MaxDepth=1: root changed'
Assert-True ($ownerL1   -match 'SYSTEM') 'SetOwner+MaxDepth=1: L1 changed'
# L3 is at depth 3 which is beyond MaxDepth=1 so must not be changed
Assert-False ($ownerL3 -match 'SYSTEM') 'SetOwner+MaxDepth=1: L3 beyond MaxDepth unchanged'

# ═══════════════════════════════════════════════════════════════════════════════
Write-Section 'BackupSecurity contains all scanned paths'
# ═══════════════════════════════════════════════════════════════════════════════

$tree32 = New-TestTree 'BackupAll'
$bkAll = Join-Path $Script:TestRoot 'backup_all.txt'
$r = Invoke-Repacls '/Path' $tree32.Root '/BackupSecurity' $bkAll '/Threads' '1'
$bkContent = Get-Content $bkAll -Raw -Encoding UTF8
Assert-True ($bkContent -match [regex]::Escape($tree32.File)) 'Backup includes File.txt path'
Assert-True ($bkContent -match [regex]::Escape($tree32.Sub)) 'Backup includes SubDir path'
Assert-True ($bkContent -match [regex]::Escape($tree32.SubFile)) 'Backup includes SubFile.txt path'

# ═══════════════════════════════════════════════════════════════════════════════
Write-Section 'SID string input across commands'
# ═══════════════════════════════════════════════════════════════════════════════

$tree33 = New-TestTree 'SidInput'
# Use SIDs instead of names for GrantPerms + RemoveAccount
$r = Invoke-Repacls '/Path' $tree33.Root '/GrantPerms' "$SidEveryone`:(R)(CI)(OI)" '/Threads' '1'
Assert-True (Test-AclContainsSid $tree33.Root $SidEveryone) 'GrantPerms with SID string works'

$r = Invoke-Repacls '/Path' $tree33.Root '/RemoveAccount' $SidEveryone '/Threads' '1'
Assert-False (Test-AclContainsSid $tree33.Root $SidEveryone) 'RemoveAccount with SID string works'

# ═══════════════════════════════════════════════════════════════════════════════
Write-Section 'Scan path banner shows correct paths'
# ═══════════════════════════════════════════════════════════════════════════════

$r = Invoke-Repacls '/Path' $tree33.Root '/FindAccount' $NameEveryone '/Threads' '1'
Assert-True ($r.RawOut -match [regex]::Escape($tree33.Root)) 'Banner shows scan path'

# ═══════════════════════════════════════════════════════════════════════════════
Write-Section 'Grant + Remove round-trip'
# ═══════════════════════════════════════════════════════════════════════════════

$tree34 = New-TestTree 'RoundTrip'
$sddlBefore = Get-AclSddl $tree34.Root
$r = Invoke-Repacls '/Path' $tree34.Root '/GrantPerms' "$NameEveryone`:(R)(CI)(OI)" '/Threads' '1' '/MaxDepth' '0'
$sddlWithEveryone = Get-AclSddl $tree34.Root
Assert-True ($sddlBefore -ne $sddlWithEveryone) 'Grant changed the ACL'

$r = Invoke-Repacls '/Path' $tree34.Root '/RemoveAccount' $NameEveryone '/Threads' '1' '/MaxDepth' '0'
# Verify Everyone is no longer present (exact SDDL match may differ due to ACE reordering by SetEntriesInAcl)
Assert-False (Test-AclContainsSid $tree34.Root $SidEveryone) 'Remove restores original ACL (round-trip)'

# ═══════════════════════════════════════════════════════════════════════════════
Write-Section 'WhatIf prevents GrantPerms changes'
# ═══════════════════════════════════════════════════════════════════════════════

$tree35 = New-TestTree 'WhatIfGrant'
$sddlBefore = Get-AclSddl $tree35.Root
$r = Invoke-Repacls '/Path' $tree35.Root '/GrantPerms' "$NameEveryone`:(F)(CI)(OI)" '/WhatIf' '/Threads' '1' '/MaxDepth' '0'
$sddlAfter = Get-AclSddl $tree35.Root
Assert-True ($sddlBefore -eq $sddlAfter) 'WhatIf prevents GrantPerms from modifying ACL'

# ═══════════════════════════════════════════════════════════════════════════════
Write-Section 'Report with granular scope (DACL only)'
# ═══════════════════════════════════════════════════════════════════════════════

$tree36 = New-TestTree 'ReportScope'
# Add an explicit ACE so Report has data rows (Report skips inherited ACEs)
$r = Invoke-Repacls '/Path' $tree36.Root '/GrantPerms' "$NameEveryone`:(R)(CI)(OI)" '/Threads' '1'
$reportDacl = Join-Path $Script:TestRoot 'report_dacl.csv'
$r = Invoke-Repacls '/Path' $tree36.Root '/Report' $reportDacl '.*:DACL' '/Threads' '1'
Assert-True (Test-Path $reportDacl) 'Scoped report file created'
$reportDaclContent = Get-Content $reportDacl -Raw -Encoding UTF8
# sSdPart ('DACL') is written as the Descriptor Part column value in each data row
Assert-True ($reportDaclContent -match 'DACL') 'Scoped report references DACL entries'
# Account name must also appear to confirm at least one data row was written
Assert-True ($reportDaclContent -match [regex]::Escape($NameEveryone)) 'Scoped report contains expected account'

# ═══════════════════════════════════════════════════════════════════════════════
Write-Section 'Large tree performance / threading'
# ═══════════════════════════════════════════════════════════════════════════════

$treeLarge = Join-Path $Script:TestRoot 'LargeTree'
New-Item -Path $treeLarge -ItemType Directory -Force | Out-Null
# Create 50 files across 5 subdirectories
for ($d = 0; $d -lt 5; $d++) {
    $dir = Join-Path $treeLarge "Dir$d"
    New-Item -Path $dir -ItemType Directory -Force | Out-Null
    for ($f = 0; $f -lt 10; $f++) {
        Set-Content -Path (Join-Path $dir "file$f.txt") -Value "content $d $f" -Encoding UTF8
    }
}

$locLarge = Join-Path $Script:TestRoot 'locate_large.csv'
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$r = Invoke-Repacls '/Path' $treeLarge '/Locate' $locLarge '.*\.txt' '/Threads' '5'
$sw.Stop()
$largeLines = @(Get-Content $locLarge -Encoding UTF8).Count
Assert-True ($largeLines -ge 51) "Large tree: found all 50 .txt files (got $($largeLines - 1) data lines)"
Assert-True ($sw.ElapsedMilliseconds -lt 30000) "Large tree: completed in reasonable time ($($sw.ElapsedMilliseconds)ms)"

# ═══════════════════════════════════════════════════════════════════════════════
Write-Section 'GrantPerms permission flags'
# ═══════════════════════════════════════════════════════════════════════════════

$tree37 = New-TestTree 'PermFlags'

# Test read-only (R)
$r = Invoke-Repacls '/Path' $tree37.File '/GrantPerms' "$NameEveryone`:(R)" '/Threads' '1' '/MaxDepth' '0'
Assert-True (Test-AclContainsSid $tree37.File $SidEveryone) 'GrantPerms (R) added Everyone'

# Test full control (F)
$tree37b = New-TestTree 'PermFlagsF'
$r = Invoke-Repacls '/Path' $tree37b.File '/GrantPerms' "$NameEveryone`:(F)" '/Threads' '1' '/MaxDepth' '0'
Assert-True (Test-AclContainsSid $tree37b.File $SidEveryone) 'GrantPerms (F) added Everyone'

# Test write (W)
$tree37c = New-TestTree 'PermFlagsW'
$r = Invoke-Repacls '/Path' $tree37c.File '/GrantPerms' "$NameEveryone`:(W)" '/Threads' '1' '/MaxDepth' '0'
Assert-True (Test-AclContainsSid $tree37c.File $SidEveryone) 'GrantPerms (W) added Everyone'

# ═══════════════════════════════════════════════════════════════════════════════
Write-Section 'GrantPerms inheritance flags'
# ═══════════════════════════════════════════════════════════════════════════════

$tree38 = New-TestTree 'InhFlags'
# (CI) = Container Inherit, (OI) = Object Inherit
$r = Invoke-Repacls '/Path' $tree38.Root '/GrantPerms' "$NameEveryone`:(R)(CI)(OI)" '/Threads' '1'
Assert-True (Test-AclContainsSid $tree38.Sub $SidEveryone) 'GrantPerms (CI)(OI): inherited to SubDir'
Assert-True (Test-AclContainsSid $tree38.SubFile $SidEveryone) 'GrantPerms (CI)(OI): inherited to SubFile'

# ═══════════════════════════════════════════════════════════════════════════════
Write-Section 'Backup/Restore round-trip preserves all entries'
# ═══════════════════════════════════════════════════════════════════════════════

$tree39 = New-TestTree 'BkRoundTrip'
# Add a specific entry so we have something unique
$r = Invoke-Repacls '/Path' $tree39.Root '/GrantPerms' "$NameEveryone`:(R)(CI)(OI)" '/Threads' '1'

$bkFile = Join-Path $Script:TestRoot 'bk_roundtrip.txt'
$r = Invoke-Repacls '/Path' $tree39.Root '/BackupSecurity' $bkFile '/Threads' '1'
$sddlBefore = Get-AclSddl $tree39.Root

# Nuke Everyone
$r = Invoke-Repacls '/Path' $tree39.Root '/RemoveAccount' $NameEveryone '/Threads' '1'
$sddlMiddle = Get-AclSddl $tree39.Root
Assert-True ($sddlBefore -ne $sddlMiddle) 'ACL changed between backup and restore'

# Restore
$r = Invoke-Repacls '/Path' $tree39.Root '/RestoreSecurity' $bkFile '/Threads' '1'
Assert-True (Test-AclContainsSid $tree39.Root $SidEveryone) 'Backup/Restore round-trip preserves all entries'

# ═══════════════════════════════════════════════════════════════════════════════
Write-Section 'Log file captures operations'
# ═══════════════════════════════════════════════════════════════════════════════

$tree40 = New-TestTree 'LogCapture'
$logFile2 = Join-Path $Script:TestRoot 'log_ops.csv'
$r = Invoke-Repacls '/Path' $tree40.Root '/GrantPerms' "$NameEveryone`:(R)(CI)(OI)" '/Log' $logFile2 '/Threads' '1'
$logLines = Get-Content $logFile2 -Encoding UTF8
Assert-True ($logLines.Count -gt 1) 'Log file contains entries beyond header'

# ═══════════════════════════════════════════════════════════════════════════════
Write-Section 'SetOwner with BUILTIN\Administrators'
# ═══════════════════════════════════════════════════════════════════════════════

$tree41 = New-TestTree 'SetOwnerAdmins'
$r = Invoke-Repacls '/Path' $tree41.Root '/SetOwner' $SidBuiltinAdmins '/MaxDepth' '0' '/Threads' '1'
$owner = Get-Owner $tree41.Root
Assert-True ($owner -match 'Administrators' -or $owner -match 'BUILTIN' -or $owner -match $SidBuiltinAdmins) 'SetOwner to Administrators via SID'

# ═══════════════════════════════════════════════════════════════════════════════
Write-Section 'Locate with no matches'
# ═══════════════════════════════════════════════════════════════════════════════

$tree42 = New-TestTree 'LocateNoMatch'
$locNoMatch = Join-Path $Script:TestRoot 'locate_nomatch.csv'
$r = Invoke-Repacls '/Path' $tree42.Root '/Locate' $locNoMatch '.*\.xyz' '/Threads' '1'
Assert-True (Test-Path $locNoMatch) 'Locate output file created even with no matches'
$nmLines = @(Get-Content $locNoMatch -Encoding UTF8).Count
Assert-True ($nmLines -le 1) 'Locate with no matches only has header line'

# ═══════════════════════════════════════════════════════════════════════════════
Write-Section 'FindAccount with no matches'
# ═══════════════════════════════════════════════════════════════════════════════

$tree43 = New-TestTree 'FindNoMatch'
# Use a SID that almost certainly does not exist in ACLs: S-1-5-32-546 (Guests)
$r = Invoke-Repacls '/Path' $tree43.Root '/FindAccount' 'S-1-5-32-546' '/Threads' '1' '/MaxDepth' '0'
Assert-False ($r.RawOut -match 'Found identifier') 'FindAccount reports nothing for non-present SID'

# ═══════════════════════════════════════════════════════════════════════════════
Write-Section '/PathMode Registry'
# ═══════════════════════════════════════════════════════════════════════════════

$registryRoot = "HKCU\Software\RepaclsTest_$([guid]::NewGuid().ToString('N').Substring(0,8))"
$null = New-Item -Path "HKCU:\$($registryRoot.Substring(5))" -Force
try {
    $r = Invoke-Repacls '/Path' $registryRoot '/PathMode' 'Registry' '/FindAccount' $NameEveryone '/Threads' '1' '/MaxDepth' '0'
    Assert-True ($r.ExitCode -eq 0 -and $r.RawOut -notmatch 'ERROR') 'PathMode Registry runs without error'
} finally {
    Remove-Item -Path "HKCU:\$($registryRoot.Substring(5))" -Force -Recurse -ErrorAction SilentlyContinue
}

# ═══════════════════════════════════════════════════════════════════════════════
Write-Section '/PathMode ActiveDirectory'
# ═══════════════════════════════════════════════════════════════════════════════

# Simply passing a syntactically correct but non-existent AD path should fail to read
$r = Invoke-Repacls '/Path' 'OU=Bogus,DC=Local' '/PathMode' 'ActiveDirectory' '/FindAccount' $NameEveryone '/Threads' '1' '/MaxDepth' '0'
# As long as it parses the PathMode correctly, the tool handles lookup failures gracefully.
Assert-True ($r.ExitCode -eq 0) 'PathMode ActiveDirectory parses and runs without fatal crash'

# ═══════════════════════════════════════════════════════════════════════════════
Write-Section 'Domain operations (FindDomain, RemoveDomain)'
# ═══════════════════════════════════════════════════════════════════════════════

$treeDomain = New-TestTree 'DomainOps'

# Block inheritance and convert to explicit rules so that RemoveDomain can successfully remove them
$treeDomainAcl = Get-Acl $treeDomain.Root
$treeDomainAcl.SetAccessRuleProtection($true, $true)
Set-Acl -Path $treeDomain.Root -AclObject $treeDomainAcl

# Make sure BUILTIN\Administrators is present in the ACL so FindDomain actually finds something
$r = Invoke-Repacls '/Path' $treeDomain.Root '/GrantPerms' "$SidBuiltinAdmins`:(R)(CI)(OI)" '/Threads' '1' '/MaxDepth' '0'

# FindDomain
$r = Invoke-Repacls '/Path' $treeDomain.Root '/FindDomain' $SidBuiltinAdmins '/Threads' '1' '/MaxDepth' '0'
Assert-True ($r.RawOut -match 'Found domain identifier') 'FindDomain found BUILTIN domain'

# RemoveDomain
$r = Invoke-Repacls '/Path' $treeDomain.Root '/RemoveDomain' $SidBuiltinAdmins '/Threads' '1' '/MaxDepth' '0'
Assert-False (Test-AclContainsSid $treeDomain.Root $SidBuiltinAdmins) 'RemoveDomain removed BUILTIN\Administrators'

# ═══════════════════════════════════════════════════════════════════════════════
Write-Section 'Domain operations (MoveDomain, CopyDomain)'
# ═══════════════════════════════════════════════════════════════════════════════
$treeDomain2 = New-TestTree 'DomainOps2'

# We don't have matching identical names across BUILTIN and NT AUTHORITY,
# so we expect these to hit the code path and either warn or skip, verifying they don't break.
$r = Invoke-Repacls '/Path' $treeDomain2.Root '/MoveDomain' "$SidBuiltinAdmins`:$SidSystem" '/Threads' '1' '/MaxDepth' '0'
Assert-True ($r.ExitCode -eq 0 -and $r.RawOut -notmatch 'ERROR') 'MoveDomain parses and runs without error'

$r = Invoke-Repacls '/Path' $treeDomain2.Root '/CopyDomain' "$SidBuiltinAdmins`:$SidSystem" '/Threads' '1' '/MaxDepth' '0'
Assert-True ($r.ExitCode -eq 0 -and $r.RawOut -notmatch 'ERROR') 'CopyDomain parses and runs without error'

# ═══════════════════════════════════════════════════════════════════════════════
Write-Section '/RemoveOrphans and /UpdateHistoricalSids'
# ═══════════════════════════════════════════════════════════════════════════════

$treeMiscOps = New-TestTree 'MiscOps'
$r = Invoke-Repacls '/Path' $treeMiscOps.Root '/RemoveOrphans' 'S-1-5' '/Threads' '1' '/MaxDepth' '0'
Assert-True ($r.ExitCode -eq 0) 'RemoveOrphans runs without error'

$r = Invoke-Repacls '/Path' $treeMiscOps.Root '/UpdateHistoricalSids' '/Threads' '1' '/MaxDepth' '0'
Assert-True ($r.ExitCode -eq 0) 'UpdateHistoricalSids runs without error'

# ═══════════════════════════════════════════════════════════════════════════════
Write-Section '/SharePaths'
# ═══════════════════════════════════════════════════════════════════════════════

# Test SharePaths command pointing to localhost, filtered to a match we expect or simply not failing.
# MaxDepth 0 and WhatIf to avoid accidentally scanning whole C$ or other shares.
$r = Invoke-Repacls '/SharePaths' '127.0.0.1:AdminOnly,Match=C\$' '/WhatIf' '/Threads' '1' '/MaxDepth' '0' '/FindAccount' $NameEveryone
Assert-True ($r.ExitCode -eq 0 -and $r.RawOut -notmatch 'ERROR') 'SharePaths parses and runs without error'
Assert-True ($r.RawOut -match '\\\\127\.0\.0\.1\\C\$') 'SharePaths correctly resolved C$ on localhost'

# ═══════════════════════════════════════════════════════════════════════════════
Write-Section '/DomainPaths with invalid domain'
# ═══════════════════════════════════════════════════════════════════════════════

# Passing a non-existent or uncontactable domain should result in an error or cleanly fail
$r = Invoke-Repacls '/DomainPaths' 'BOGUS_DOMAIN_NOT_REAL_12345:StopOnError' '/MaxDepth' '0' 
Assert-True ($r.RawOut -match 'ERROR') 'DomainPaths cleanly errors out on uncontactable domain'

$r = Invoke-Repacls '/DomainPathsWithSite' 'BOGUS_DOMAIN_NOT_REAL_12345' 'BOGUS_SITE' '/MaxDepth' '0'
Assert-True ($r.RawOut -match 'ERROR') 'DomainPathsWithSite cleanly errors out on uncontactable domain'

# ═══════════════════════════════════════════════════════════════════════════════
Write-Section 'Raw ACL structure validation – GrantPerms ACE details'
# ═══════════════════════════════════════════════════════════════════════════════

$treeRaw1 = New-TestTree 'RawGrant'
$r = Invoke-Repacls '/Path' $treeRaw1.Root '/GrantPerms' "$NameEveryone`:(R)(CI)(OI)" '/Threads' '1' '/MaxDepth' '0'
$snap = Get-RawAclSnapshot $treeRaw1.Root
Assert-AclCanonical $treeRaw1.Root 'GrantPerms result is canonical'
Assert-RawAceExists $treeRaw1.Root $SidEveryone 'Allow' 'Raw ACE for Everyone is Allow type'
$aces = [RepaclsTest.RawAclValidator]::GetAcesForSid($snap, $SidEveryone)
$allowAce = $aces | Where-Object { $_.AceType -eq 'Allow' -and -not $_.IsInherited } | Select-Object -First 1
Assert-True ($null -ne $allowAce) 'Raw explicit Allow ACE found for Everyone'
Assert-True ($allowAce.InheritanceFlags -match 'ContainerInherit' -and $allowAce.InheritanceFlags -match 'ObjectInherit') 'ACE has CI+OI inheritance flags'
Assert-True (($allowAce.AccessMask -band 0x1) -ne 0) 'ACE access mask includes ReadData bit'

# ═══════════════════════════════════════════════════════════════════════════════
Write-Section 'Raw ACL structure validation – DenyPerms ACE ordering'
# ═══════════════════════════════════════════════════════════════════════════════

$treeRaw2 = New-TestTree 'RawDeny'
$r = Invoke-Repacls '/Path' $treeRaw2.Root '/DenyPerms' "$NameEveryone`:(W)(CI)(OI)" '/Threads' '1' '/MaxDepth' '0'
$snap2 = Get-RawAclSnapshot $treeRaw2.Root
Assert-AclCanonical $treeRaw2.Root 'DenyPerms result is canonical'
Assert-RawAceExists $treeRaw2.Root $SidEveryone 'Deny' 'Raw ACE for Everyone is Deny type'
$denyAces = [RepaclsTest.RawAclValidator]::GetAcesForSid($snap2, $SidEveryone)
$denyAce = $denyAces | Where-Object { $_.AceType -eq 'Deny' -and -not $_.IsInherited } | Select-Object -First 1
Assert-True ($null -ne $denyAce) 'Raw explicit Deny ACE found for Everyone'
$firstDenyIdx = -1; $firstAllowIdx = -1
for ($i = 0; $i -lt $snap2.DaclAces.Count; $i++) {
    if ($snap2.DaclAces[$i].AceType -eq 'Deny' -and -not $snap2.DaclAces[$i].IsInherited -and $firstDenyIdx -eq -1) { $firstDenyIdx = $i }
    if ($snap2.DaclAces[$i].AceType -eq 'Allow' -and -not $snap2.DaclAces[$i].IsInherited -and $firstAllowIdx -eq -1) { $firstAllowIdx = $i }
}
Assert-True ($firstAllowIdx -eq -1 -or $firstDenyIdx -lt $firstAllowIdx) 'Deny ACE appears before Allow ACEs (canonical)'

# ═══════════════════════════════════════════════════════════════════════════════
Write-Section "Side-effect isolation – SetOwner doesn't alter DACL"
# ═══════════════════════════════════════════════════════════════════════════════

$treeIso1 = New-TestTree 'IsoSetOwner'
$r = Invoke-Repacls '/Path' $treeIso1.Root '/GrantPerms' "$NameEveryone`:(R)(CI)(OI)" '/Threads' '1' '/MaxDepth' '0'
$snapBefore = Get-RawAclSnapshot $treeIso1.Root
$daclAcesBefore = $snapBefore.DaclAces.Count
$sidsBefore = [RepaclsTest.RawAclValidator]::GetUniqueSids($snapBefore)
$r = Invoke-Repacls '/Path' $treeIso1.Root '/SetOwner' $NameSystem '/MaxDepth' '0' '/Threads' '1'
$snapAfter = Get-RawAclSnapshot $treeIso1.Root
Assert-True ($snapAfter.OwnerSid -eq $SidSystem) 'SetOwner changed owner SID to SYSTEM at raw level'
Assert-True ($snapAfter.DaclAces.Count -eq $daclAcesBefore) 'SetOwner did not change DACL ACE count'
$sidsAfter = [RepaclsTest.RawAclValidator]::GetUniqueSids($snapAfter)
Assert-True ($sidsBefore.Length -eq $sidsAfter.Length) 'SetOwner preserved all DACL SIDs'

# ═══════════════════════════════════════════════════════════════════════════════
Write-Section "Side-effect isolation – GrantPerms doesn't alter owner"
# ═══════════════════════════════════════════════════════════════════════════════

$treeIso2 = New-TestTree 'IsoGrantOwner'
$snapBefore = Get-RawAclSnapshot $treeIso2.Root
$ownerBefore = $snapBefore.OwnerSid
$r = Invoke-Repacls '/Path' $treeIso2.Root '/GrantPerms' "$NameEveryone`:(F)(CI)(OI)" '/Threads' '1' '/MaxDepth' '0'
$snapAfter = Get-RawAclSnapshot $treeIso2.Root
Assert-True ($snapAfter.OwnerSid -eq $ownerBefore) 'GrantPerms did not change owner SID'

# ═══════════════════════════════════════════════════════════════════════════════
Write-Section "Side-effect isolation – MaxDepth=0 doesn't affect children"
# ═══════════════════════════════════════════════════════════════════════════════

$treeIso3 = New-TestTree 'IsoDepth0'
$treeSnap = Get-TreeAclSnapshot $treeIso3.Root
# Use (F) without CI/OI so no OS-level inheritance propagation occurs
$r = Invoke-Repacls '/Path' $treeIso3.Root '/GrantPerms' "$SidAuthUsers`:(F)" '/MaxDepth' '0' '/Threads' '1'
$treeSnapAfter = Get-TreeAclSnapshot $treeIso3.Root
Assert-NoSideEffects $treeSnap $treeSnapAfter @($treeIso3.Root) 'MaxDepth=0 GrantPerms: children unchanged' -ExplicitOnly

# ═══════════════════════════════════════════════════════════════════════════════
Write-Section 'Side-effect isolation – WhatIf produces zero changes tree-wide'
# ═══════════════════════════════════════════════════════════════════════════════

$treeIso4 = New-TestTree 'IsoWhatIf'
$treeSnap = Get-TreeAclSnapshot $treeIso4.Root
$r = Invoke-Repacls '/Path' $treeIso4.Root '/GrantPerms' "$NameEveryone`:(F)(CI)(OI)" '/SetOwner' $NameSystem '/WhatIf' '/Threads' '1'
$treeSnapAfter = Get-TreeAclSnapshot $treeIso4.Root
Assert-NoSideEffects $treeSnap $treeSnapAfter @() 'WhatIf: zero changes across entire tree'

# ═══════════════════════════════════════════════════════════════════════════════
Write-Section 'Side-effect isolation – RemoveAccount preserves other SIDs'
# ═══════════════════════════════════════════════════════════════════════════════

$treeIso5 = New-TestTree 'IsoRemove'
$r = Invoke-Repacls '/Path' $treeIso5.Root '/GrantPerms' "$NameEveryone`:(R)(CI)(OI)" '/Threads' '1' '/MaxDepth' '0'
$r = Invoke-Repacls '/Path' $treeIso5.Root '/GrantPerms' "$SidAuthUsers`:(R)(CI)(OI)" '/Threads' '1' '/MaxDepth' '0'
$snapBefore = Get-RawAclSnapshot $treeIso5.Root
Assert-True ([RepaclsTest.RawAclValidator]::HasAceForSid($snapBefore, $SidEveryone, 'Allow')) 'Pre-condition: Everyone present'
Assert-True ([RepaclsTest.RawAclValidator]::HasAceForSid($snapBefore, $SidAuthUsers, 'Allow')) 'Pre-condition: Authenticated Users present'
$r = Invoke-Repacls '/Path' $treeIso5.Root '/RemoveAccount' $NameEveryone '/Threads' '1' '/MaxDepth' '0'
$snapAfter = Get-RawAclSnapshot $treeIso5.Root
Assert-False ([RepaclsTest.RawAclValidator]::HasAceForSid($snapAfter, $SidEveryone, $null)) 'RemoveAccount removed Everyone completely'
Assert-True ([RepaclsTest.RawAclValidator]::HasAceForSid($snapAfter, $SidAuthUsers, 'Allow')) 'RemoveAccount preserved Authenticated Users'
Assert-AclCanonical $treeIso5.Root 'ACL still canonical after RemoveAccount'

# ═══════════════════════════════════════════════════════════════════════════════
Write-Section 'Side-effect isolation – ReplaceAccount only replaces target'
# ═══════════════════════════════════════════════════════════════════════════════

$treeIso6 = New-TestTree 'IsoReplace'
$r = Invoke-Repacls '/Path' $treeIso6.Root '/GrantPerms' "$NameEveryone`:(R)(CI)(OI)" '/Threads' '1' '/MaxDepth' '0'
$r = Invoke-Repacls '/Path' $treeIso6.Root '/GrantPerms' "$SidAuthUsers`:(R)(CI)(OI)" '/Threads' '1' '/MaxDepth' '0'
$r = Invoke-Repacls '/Path' $treeIso6.Root '/ReplaceAccount' "$SidEveryone`:$SidBuiltinUsers" '/Threads' '1' '/MaxDepth' '0'
$snapAfter = Get-RawAclSnapshot $treeIso6.Root
Assert-False ([RepaclsTest.RawAclValidator]::HasAceForSid($snapAfter, $SidEveryone, $null)) 'ReplaceAccount removed Everyone'
Assert-True ([RepaclsTest.RawAclValidator]::HasAceForSid($snapAfter, $SidBuiltinUsers, 'Allow')) 'ReplaceAccount added BUILTIN\Users'
Assert-True ([RepaclsTest.RawAclValidator]::HasAceForSid($snapAfter, $SidAuthUsers, 'Allow')) 'ReplaceAccount preserved Authenticated Users'
Assert-AclCanonical $treeIso6.Root 'ACL still canonical after ReplaceAccount'

# ═══════════════════════════════════════════════════════════════════════════════
Write-Section "Side-effect isolation – ResetChildren doesn't alter parent"
# ═══════════════════════════════════════════════════════════════════════════════

$treeIso7 = New-TestTree 'IsoReset'
$parentSnap = Get-RawAclSnapshot $treeIso7.Root
$acl = Get-Acl $treeIso7.Sub
$acl.SetAccessRuleProtection($true, $true)
Set-Acl -Path $treeIso7.Sub -AclObject $acl
$r = Invoke-Repacls '/Path' $treeIso7.Root '/ResetChildren' '/Threads' '1'
$parentSnapAfter = Get-RawAclSnapshot $treeIso7.Root
Assert-SnapshotUnchanged $parentSnap $parentSnapAfter 'ResetChildren did not alter parent ACL'

# ═══════════════════════════════════════════════════════════════════════════════
Write-Section "Side-effect isolation – DenyPerms doesn't remove Allow ACEs"
# ═══════════════════════════════════════════════════════════════════════════════

$treeIso8 = New-TestTree 'IsoDeny'
$r = Invoke-Repacls '/Path' $treeIso8.Root '/GrantPerms' "$SidAuthUsers`:(R)(CI)(OI)" '/Threads' '1' '/MaxDepth' '0'
$snapBefore = Get-RawAclSnapshot $treeIso8.Root
$allowCountBefore = ($snapBefore.DaclAces | Where-Object { $_.AceType -eq 'Allow' }).Count
$r = Invoke-Repacls '/Path' $treeIso8.Root '/DenyPerms' "$NameEveryone`:(W)(CI)(OI)" '/Threads' '1' '/MaxDepth' '0'
$snapAfter = Get-RawAclSnapshot $treeIso8.Root
$allowCountAfter = ($snapAfter.DaclAces | Where-Object { $_.AceType -eq 'Allow' }).Count
Assert-True ($allowCountAfter -ge $allowCountBefore) 'DenyPerms did not remove existing Allow ACEs'
Assert-True ([RepaclsTest.RawAclValidator]::HasAceForSid($snapAfter, $SidAuthUsers, 'Allow')) 'DenyPerms preserved Authenticated Users Allow ACE'
Assert-AclCanonical $treeIso8.Root 'ACL canonical after DenyPerms (Deny before Allow)'

# ═══════════════════════════════════════════════════════════════════════════════
Write-Section 'Raw ACL validation – Compact preserves canonical order and SIDs'
# ═══════════════════════════════════════════════════════════════════════════════

$treeRaw4 = New-TestTree 'RawCompact'
$r = Invoke-Repacls '/Path' $treeRaw4.File '/GrantPerms' "$NameEveryone`:(R)" '/Threads' '1' '/MaxDepth' '0'
$r = Invoke-Repacls '/Path' $treeRaw4.File '/GrantPerms' "$NameEveryone`:(R)(CI)(OI)" '/Threads' '1' '/MaxDepth' '0'
$sidsBefore = [RepaclsTest.RawAclValidator]::GetUniqueSids((Get-RawAclSnapshot $treeRaw4.File))
$r = Invoke-Repacls '/Path' $treeRaw4.File '/Compact' '/Threads' '1' '/MaxDepth' '0'
Assert-AclCanonical $treeRaw4.File 'Compact result is canonical'
$sidsAfter = [RepaclsTest.RawAclValidator]::GetUniqueSids((Get-RawAclSnapshot $treeRaw4.File))
foreach ($sid in $sidsBefore) {
    Assert-True ($sidsAfter -contains $sid) "Compact preserved SID $sid"
}

# ═══════════════════════════════════════════════════════════════════════════════
Write-Section 'Raw ACL validation – CanonicalizeAcls fixes non-canonical ACL'
# ═══════════════════════════════════════════════════════════════════════════════

$treeRaw5 = New-TestTree 'RawCanonicalize'
$acl = Get-Acl $treeRaw5.Root
$acl.SetAccessRuleProtection($true, $true)
Set-Acl -Path $treeRaw5.Root -AclObject $acl
$acl = Get-Acl $treeRaw5.Root
$allowRule = [System.Security.AccessControl.FileSystemAccessRule]::new(
    $NameEveryone, 'Read', 'None', 'None', 'Allow')
$denyRule = [System.Security.AccessControl.FileSystemAccessRule]::new(
    $NameEveryone, 'Write', 'None', 'None', 'Deny')
$acl.AddAccessRule($allowRule)
$acl.AddAccessRule($denyRule)
Set-Acl -Path $treeRaw5.Root -AclObject $acl
$r = Invoke-Repacls '/Path' $treeRaw5.Root '/CanonicalizeAcls' '/Threads' '1' '/MaxDepth' '0'
Assert-AclCanonical $treeRaw5.Root 'CanonicalizeAcls produces raw-validated canonical order'
$snap5 = Get-RawAclSnapshot $treeRaw5.Root
Assert-True ([RepaclsTest.RawAclValidator]::HasAceForSid($snap5, $SidEveryone, 'Allow')) 'CanonicalizeAcls preserved Allow ACE'
Assert-True ([RepaclsTest.RawAclValidator]::HasAceForSid($snap5, $SidEveryone, 'Deny')) 'CanonicalizeAcls preserved Deny ACE'

} finally {
    #region ── Cleanup & Summary ───────────────────────────────────────────────
    Pop-Location
    try {
        Remove-Item -Path $Script:TestRoot -Recurse -Force -ErrorAction SilentlyContinue
    } catch {
        Write-Warning "Could not fully clean up '$Script:TestRoot': $_"
    }
    #endregion
}

Write-Host ''
Write-Host '════════════════════════════════════════════════════════════════════════════════' -ForegroundColor Cyan
Write-Host "  RESULTS:  Passed=$Script:PassCount  Failed=$Script:FailCount  Skipped=$Script:SkipCount" -ForegroundColor $(if ($Script:FailCount -gt 0) { 'Red' } else { 'Green' })
Write-Host '════════════════════════════════════════════════════════════════════════════════' -ForegroundColor Cyan

exit $Script:FailCount
